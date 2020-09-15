use crate::{diag::Pack, index::Index, Krate, Krates};
use anyhow::{Context, Error};
use rustsec::advisory::Metadata;
use semver::{Version, VersionReq};

#[derive(Debug)]
pub struct Patch<'a> {
    /// The advisories the patch is attempting to address
    pub advisories: Vec<&'a Metadata>,
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

#[derive(Debug)]
pub struct PatchSet<'a> {
    //diagnostics: Vec<Pack>,
    patches: Vec<Patch<'a>>,
}

struct Patchable<'a> {
    advisory: &'a Metadata,
    patched: &'a [rustsec::VersionReq],
    krate: &'a rustsec::package::Package,
}

impl super::Report {
    fn iter_patchable(&self) -> impl Iterator<Item = Patchable<'_>> {
        self.vulnerabilities
            .iter()
            .map(|vuln| Patchable {
                advisory: &vuln.advisory,
                patched: &vuln.versions.patched,
                krate: &vuln.package,
            })
            .chain(self.iter_warnings().filter_map(|(kind, warning)| {
                // Unmaintained crates are by definition unpatchable, so skip them entirely
                if kind == rustsec::warning::Kind::Unmaintained {
                    return None;
                }

                warning.versions.as_ref().and_then(|vs| {
                    warning.advisory.as_ref().map(|adv| Patchable {
                        advisory: &adv,
                        patched: &vs.patched,
                        krate: &warning.package,
                    })
                })
            }))
    }

    pub fn gather_patches<'a>(
        &'a self,
        krates: &'a Krates,
        semv: Semver,
    ) -> Result<PatchSet<'a>, Error> {
        use krates::petgraph as pg;
        use pg::{visit::EdgeRef, Direction};

        let graph = krates.graph();
        let mut index = Index::load(krates)?;

        let mut candidates: Vec<(pg::graph::EdgeIndex<u32>, Vec<PatchCandidate<'_>>)> = Vec::new();
        //let mut diags = Vec::new();

        #[derive(Debug)]
        struct PatchCandidate<'a> {
            advisory: &'a Metadata,
            required: Vec<Version>,
        }

        for patchable in self.iter_patchable() {
            // 1. Get the package with the vulnerability
            // 2. Recursively walk up the dependency chain until we've reach all roots
            // (workspace/local crates) that depend on the vulnerable crate version
            // 3. For each crate in the chain, check to see if has a version
            // available that ultimately includes a patched version of the vulnerable crate
            let (ind, vuln_krate) = super::krate_for_pkg(krates, &patchable.krate).unwrap();

            // We could also see if there are unaffected versions, but easier to just say we only support
            // fixing by using newer versions than older versions
            if patchable.patched.is_empty() {
                log::error!(
                    "advisory {:#?} has no available patches",
                    patchable.advisory
                );
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

            // Gather the versions that fix the issue. Note that there could be
            // cases where the fix is in disjoint versions.
            let required: Vec<_> = {
                let mut req = None;

                index.read_krate(vuln_krate, |ik| {
                    if let Some(index_krate) = ik {
                        let patched = &patchable.patched;

                        req = Some(
                            index_krate
                                .versions()
                                .iter()
                                .filter_map(|vs| {
                                    vs.version().parse().ok().and_then(
                                        |version: rustsec::Version| {
                                            if patched.iter().any(|v| v.matches(&version)) {
                                                // rustsec uses an older version of semver
                                                vs.version().parse::<Version>().ok()
                                            } else {
                                                None
                                            }
                                        },
                                    )
                                })
                                .collect(),
                        );
                    }
                });

                match req {
                    Some(r) => r,
                    None => continue,
                }
            };

            if required.is_empty() {
                log::error!(
                    "Advisory {:#?} has no available versions that meet the patch requirements",
                    patchable.advisory
                );
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

            log::warn!("ADVISORY {:#?}", patchable.advisory);

            while let Some((nid, dep, required)) = krate_stack.pop() {
                for edge in graph.edges_directed(nid, Direction::Incoming) {
                    // We only need to visit each unique edge once
                    let edge_id = edge.id();
                    if !visited.insert(edge_id) {
                        log::warn!("Already visited {} => {}", &graph[edge.source()], dep);
                        continue;
                    }

                    let parent_id = edge.source();
                    let parent = &graph[parent_id];

                    log::warn!("Visiting {} => {}", parent.krate, dep);

                    if let Some(src) = &parent.krate.source {
                        if src.is_registry() {
                            match Self::find_possible_versions(
                                &mut index,
                                &parent.krate,
                                dep,
                                &required,
                            ) {
                                Ok(parent_versions) => {
                                    krate_stack.push((parent_id, &parent.krate, parent_versions));
                                    continue;
                                }
                                Err(e) => {
                                    log::error!(
                                        "Unable to patch {} => {}: {}",
                                        parent.krate,
                                        dep,
                                        e
                                    );
                                    continue;
                                }
                            }
                        } else if !src.is_path() {
                            // TODO: Emit warning that we can't update
                            log::error!(
                                "Unable to patch {:#?}, not a registry or local source {:#?}",
                                parent.krate,
                                src
                            );
                            continue;
                        }
                    }

                    match candidates.iter_mut().find(|c| c.0 == edge_id) {
                        Some(mut cand) => {
                            cand.1.push(PatchCandidate {
                                advisory: patchable.advisory,
                                required: required.clone(),
                            });
                        }
                        None => {
                            candidates.push((
                                edge_id,
                                vec![PatchCandidate {
                                    advisory: patchable.advisory,
                                    required: required.clone(),
                                }],
                            ));
                        }
                    }
                }
            }
        }

        // Now that we've gathered all of the patches that we can apply, try to
        // find a semver compatible version to patch to, or if the user has
        // allowed non-semver patching, just pick the highest version
        let mut patches = Vec::new();
        for (edge, candidates) in candidates {
            let (local_krate, to_patch) = graph
                .edge_endpoints(edge)
                .map(|(src, tar)| (&krates[src], &krates[tar]))
                .unwrap();

            // Get the maximum version, either of the possible versions that we
            // require or of the maximum from the set of semver compatible
            // versions. I honestly expect the semver compatible one to never
            // actually work, but provide it just because
            let version = match semv {
                Semver::Compatible => {
                    match local_krate.deps.iter().find(|dep| {
                        dep.kind != krates::cm::DependencyKind::Development
                            && dep.name == to_patch.name
                    }) {
                        Some(dep) => {
                            let req = &dep.req;

                            let mut new_version = None;
                            let mut all_compatible = true;

                            for pc in &candidates {
                                match pc.required.iter().filter(|vs| req.matches(vs)).max() {
                                    Some(max) => match &mut new_version {
                                        Some(cur) => {
                                            *cur = std::cmp::max(&*cur, &max);
                                        }
                                        None => {
                                            new_version = Some(max);
                                        }
                                    },
                                    None => {
                                        log::warn!("Local crate {:#?} has a requirement of {} on {}, which does not meet any of the required versions {:#?}", local_krate, req, to_patch.name, pc.required);
                                        // TODO: Emit warning that there are no semver compatible
                                        // versions we can update to
                                        all_compatible = false;
                                    }
                                }
                            }

                            if !all_compatible {
                                continue;
                            }

                            new_version
                        }
                        None => {
                            continue;
                        }
                    }
                }
                Semver::Latest => candidates.iter().flat_map(|pc| pc.required.iter()).max(),
            };

            let version = match version {
                Some(v) => v.clone(),
                None => {
                    log::warn!("Local crate {:#?} dependency for {}, does not meet any of the required versions {:#?}", local_krate, to_patch.name, candidates);
                    // TODO: Emit warning about no version to update to
                    continue;
                }
            };

            patches.push(Patch {
                advisories: candidates.into_iter().map(|pc| pc.advisory).collect(),
                manifest_to_patch: local_krate,
                crate_to_patch: (to_patch.name.as_ref(), version),
            });
        }

        Ok(PatchSet {
            patches,
            //diagnostics: diags,
        })
    }

    fn find_possible_versions(
        index: &mut Index,
        parent: &Krate,
        child: &Krate,
        required: &[Version],
    ) -> Result<Vec<Version>, Error> {
        let mut res = None;

        index.read_krate(&parent, |ik| {
            match ik {
                Some(parent_krate) => {
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
                        res = Some(Err(anyhow::anyhow!("No versions were available that used a required version of the crate")));
                    } else {
                        res = Some(Ok(available));
                    }
                }
                None => {
                    res = Some(Err(anyhow::anyhow!("Unable to find registry index entry for crate '{}'", parent.name)));
                }
            }
        });

        res.unwrap()
    }
}
