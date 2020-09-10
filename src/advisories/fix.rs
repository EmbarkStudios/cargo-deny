pub struct Patch<'a> {
    /// The vulnerabilities the patch is attempting to address
    pub vulns: Vec<&'a Vulnerability>,
    /// The crate manifest we want to patch to update versions
    pub manifest_to_patch: &'a Krate,
    /// The crate and version we want to update to to get the fix(es)
    pub crate_to_patch: (&'a str, Version),
}

#[derive(Clone, Copy)]
pub enum Semver {
    Compatible,
    Latest,
}

pub struct PatchSet<'a> {
    diagnostics: Vec<Pack>,
    patches: Vec<Patch<'a>>,
}

impl super::Report {
    pub fn gather_patches(&self, krates: &Krates, semv: Semver) -> Result<PatchSet<'_>, Error> {
        use krates::petgraph as pg;
        use pg::{visit::EdgeRef, Direction};

        let graph = krates.graph();
        let index = Index::load(krates)?;

        let mut candidates = Vec::new();
        let mut diags = Vec::new();

        struct PatchCandidate<'a> {
            vuln: &'a Vulnerability,
            required: Vec<Version>,
        }

        for vuln in &self.vulnerabilities {
            // 1. Get the package with the vulnerability
            // 2. Recursively walk up the dependency chain until we've reach all roots
            // (workspace crates) that depend on the vulnerable crate version
            // 3. For each crate in the chain, check to see if has a version
            // available that ultimately includes a patched version of the vulnerable crate
            let (ind, vuln_krate) = krate_for_pkg(krates, &vuln.package).unwrap();

            // We could also see if there are unaffected versions, but easier to just say we only support
            // fixing by using newer versions than older versions
            if vuln.versions.patched.is_empty() {
                // let mut pack = Pack::with_kid(Check::Advisories, vuln_krate.id.clone());
                // pack.push(
                //     Diagnostic::error()
                //         .with_message()
                //         .with_labels(vec![ctx.label_for_span(i.index(), message)])
                //         .with_code(id.as_str().to_owned())
                //         .with_notes(notes),
                // );
                continue;
            }

            // Gather the versions that fix the issue. Note that there could be cases where the fix is in disjoint
            // versions.
            let required: Vec<_> = {
                let index_krate = match index.read_krate(vuln_krate) {
                    Some(ik) => ik,
                    None => {
                        continue;
                    }
                };

                let patched = &vuln.versions.patched;

                index_krate
                    .versions()
                    .iter()
                    .filter_map(|vs| {
                        vs.version()
                            .parse()
                            .ok()
                            .and_then(|version: rustsec::Version| {
                                if patched.iter().any(|v| v.matches(&version)) {
                                    // rustsec uses an older version of semver
                                    vs.version().parse::<Version>().ok()
                                } else {
                                    None
                                }
                            })
                    })
                    .collect()
            };

            if required.is_empty() {
                // let mut pack = Pack::with_kid(Check::Advisories, vuln_krate.id.clone());
                // pack.push(
                //     Diagnostic::error()
                //         .with_message()
                //         .with_labels(vec![ctx.label_for_span(i.index(), message)])
                //         .with_code(id.as_str().to_owned())
                //         .with_notes(notes),
                // );
                continue;
            }

            let mut krate_stack = vec![(ind, vuln_krate, required)];
            let mut visited = std::collections::HashSet::new();

            while let Some((nid, krate, required)) = krate_stack.pop() {
                for edge in graph.edges_directed(nid, Direction::Incoming) {
                    // We only need to visit each unique edge once
                    let edge_id = edge.id();
                    if !visited.insert(edge_id) {
                        continue;
                    }

                    let parent_id = edge.source();
                    let parent = &graph[parent_id];

                    if let Some(src) = &parent.krate.source {
                        if src.is_registry() {
                            match Self::find_possible_versions(&index, parent, krate, required) {
                                Ok(parent_versions) => {
                                    krate_stack.push((parent_id, parent, parent_versions));
                                    continue;
                                }
                                Err(e) => {
                                    continue;
                                }
                            }
                        } else if !src.is_path() {
                            // TODO: Emit warning that we can't update
                            continue;
                        }
                    }

                    match candidates.iter_mut().find(|c| c.0 == edge_id) {
                        Some(mut cand) => {
                            cand.1.push(PatchCandidate { vuln, required });
                        }
                        None => {
                            candidates.push((edge_id, vec![PatchCandidate { vuln, required }]));
                        }
                    }
                }
            }
        }

        // Now that we've gathered all of the patches that we can apply, try to find
        // a semver compatible version to patch to, or if the user has allowed non-semver
        // patching, just pick the highest version
        let mut patches = Vec::new();
        for (edge, candidates) in candidates {
            let (local_krate, to_patch) = graph
                .edge_endpoints(edge)
                .map(|(src, tar)| (&krates[src], &krates[tar]))
                .unwrap();

            let version =
                match semv {
                    Semver::Compatible => {
                        match local_krate.dependencies.iter().find(|dep| {
                            dep.kind != DependencyKind::Dev && dep.name == to_patch.name
                        }) {
                            Some(dep) => {
                                let req = &dep.req;

                                for pc in &candidates {
                                    if !pc.required.iter().any(|vs| req.matches(vs)) {
                                        // TODO: Emit warning that there are no semver compatible
                                        // versions we can update to
                                        continue;
                                    }
                                }
                            }
                            None => {
                                continue;
                            }
                        }
                    }
                    Semver::Latest => candidates.iter().flat_map(|pc| pc.required.iter()).max(),
                };

            patches.push(Patch {
                vulns: candidates.into_iter().map(|pc| pc.vuln).collect(),
                manifest_to_patch: local_krate,
                crate_to_patch: (to_patch.name.as_ref(), version),
            });
        }

        Ok(PatchSet {
            patches,
            diagnostics: diags,
        })
    }

    fn find_possible_versions(
        index: &Index,
        parent: &Krate,
        child: &Krate,
        required: &[Version],
    ) -> Result<Vec<Version>, Error> {
        // Lookup the available versions in the registry's index to see if there is a
        // compatible version we can update to
        let parent_krate = index.read_krate(&parent).with_context(|| {
            format!(
                "Unable to find registry index entry for crate '{}'",
                parent.name
            )
        })?;

        // Grab all of the versions of the parent crate that have a version requirement that accepts
        // any of the specified required versions
        let available: Vec<_> = parent_krate.versions().iter().filter_map(|kv| {
            let version: Version = match kv.version().parse() {
                Ok(vs) => {
                    if vs < parent.version {
                        return None;
                    }

                    vs
                },
                Err(err) => {
                    log::warn!("Unable to parse version '{}' for index crate '{}': {}", kv.version(), parent.name, err);
                    return None;
                }
            };


            if let Some(dep) = kv.dependencies().iter().find(|dep| dep.kind() != crates_index::DependencyKind::Dev && dep.name() == child.name) {
                let req: VersionReq = match dep.requirement().parse() {
                    Ok(req) => req,
                    Err(err) => {
                        log::warn!("Unable to parse version requirement '{}' for index crate '{}', dependency '{}': {}", dep.requirement(), parent.name, child.name, err);
                        return None;
                    }
                };

                if !required.iter().any(|vs| req.matches(&vs)) {
                    return None;
                }
            }

            // If the dependency has been removed from a future version, it is
            // also a candidate
            Some(version)
        }).collect();

        if available.is_empty() {
            anyhow::bail!("No versions were available that used a required version of the crate");
        } else {
            Ok(available)
        }
    }
}
