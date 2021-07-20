use super::diags;
use crate::{
    diag::{self, Check, Pack},
    index::Index,
    Krate, Krates,
};
use anyhow::Error;
use rustsec::advisory::Metadata;
use semver::Version;

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

#[derive(Clone, Copy)]
pub enum NoVersionReason {
    /// No versions were available that used a required version of the crate
    NoMatchingVersions,
    /// Unable to find registry index entry for crate
    NoIndexEntry,
}

use std::fmt;

impl fmt::Display for NoVersionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatchingVersions => {
                f.write_str("No versions were available that used a required version of the crate")
            }
            Self::NoIndexEntry => f.write_str("Unable to find registry index entry for crate"),
        }
    }
}

pub struct PatchSet<'a> {
    pub diagnostics: Vec<Pack>,
    pub patches: Vec<Patch<'a>>,
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
                patched: vuln.versions.patched(),
                krate: &vuln.package,
            })
            .chain(self.iter_warnings().filter_map(|(kind, warning)| {
                // Unmaintained crates are by definition unpatchable, so skip them entirely
                if kind == rustsec::warning::Kind::Unmaintained {
                    return None;
                }

                warning.versions.as_ref().and_then(|vs| {
                    warning.advisory.as_ref().map(|adv| Patchable {
                        advisory: adv,
                        patched: vs.patched(),
                        krate: &warning.package,
                    })
                })
            }))
    }

    pub fn gather_patches<'a>(
        &'a self,
        krates: &'a Krates,
        semv: Semver,
        krate_spans: &'a diag::KrateSpans,
    ) -> Result<PatchSet<'a>, Error> {
        use krates::petgraph as pg;
        use pg::{visit::EdgeRef, Direction};

        let graph = krates.graph();
        let mut index = Index::load(krates)?;

        let mut candidates: Vec<(pg::graph::EdgeIndex<u32>, Vec<PatchCandidate<'_>>)> = Vec::new();
        let mut diags = Vec::new();

        #[derive(Debug)]
        struct PatchCandidate<'a> {
            advisory: &'a Metadata,
            required: Vec<Version>,
        }

        let mut visited = std::collections::HashSet::new();

        for patchable in self.iter_patchable() {
            // 1. Get the package with the vulnerability
            // 2. Recursively walk up the dependency chain until we've reach all roots
            // (workspace/local crates) that depend on the vulnerable crate version
            // 3. For each crate in the chain, check to see if has a version
            // available that ultimately includes a patched version of the vulnerable crate
            let (ind, vuln_krate) = super::krate_for_pkg(krates, patchable.krate).unwrap();

            let mut pack = Pack::with_kid(Check::Advisories, vuln_krate.id.clone());

            // We could also see if there are unaffected versions, but easier to just say we only support
            // fixing by using newer versions than older versions
            if patchable.patched.is_empty() {
                pack.push(diags::NoAvailablePatches {
                    affected_krate_coord: krate_spans.get_coord(ind.index()),
                    advisory: patchable.advisory,
                });
                diags.push(pack);
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
                                .versions
                                .iter()
                                // Disregard any versions older than the current one
                                .skip_while(|vs| vs.vers < vuln_krate.version)
                                .filter_map(|vs| {
                                    if patched.iter().any(|v| v.matches(&vs.vers)) {
                                        Some(vs.vers.clone())
                                    } else {
                                        None
                                    }
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
                pack.push(diags::NoAvailablePatchedVersions {
                    affected_krate_coord: krate_spans.get_coord(ind.index()),
                    advisory: patchable.advisory,
                });
                diags.push(pack);
                continue;
            }

            let mut krate_stack = vec![(ind, vuln_krate, required)];

            while let Some((nid, dep, required)) = krate_stack.pop() {
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
                                    pack.push(diags::UnableToFindMatchingVersion {
                                        parent_krate: &parent.krate,
                                        reason: e,
                                        dep,
                                    });
                                    continue;
                                }
                            }
                        } else if !src.is_path() {
                            pack.push(diags::UnpatchableSource {
                                parent_krate: &parent.krate,
                            });
                            continue;
                        }
                    }

                    match candidates.iter_mut().find(|c| c.0 == edge_id) {
                        Some(cand) => {
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

            if !pack.is_empty() {
                diags.push(pack);
            }
        }

        // Now that we've gathered all of the patches that we can apply, try to
        // find a semver compatible version to patch to, or if the user has
        // allowed non-semver patching, just pick the highest version
        let mut patches = Vec::new();

        let mut patch_pack = Pack::new(Check::Advisories);

        for (edge, candidates) in candidates {
            let (local_krate, to_patch) = graph
                .edge_endpoints(edge)
                .map(|(src, tar)| (&krates[src], &krates[tar]))
                .unwrap();

            // Get the maximum version, either of the possible versions that we
            // require or of the maximum from the set of semver compatible
            // versions. I honestly expect the semver compatible one to never
            // actually work, but provide it just because ¯\_(ツ)_/¯
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
                                        patch_pack.push(diags::IncompatibleLocalKrate {
                                            local_krate,
                                            dep_req: req,
                                            dep: to_patch,
                                            required_versions: &pc.required,
                                        });
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
                Some(v) => {
                    if v == &to_patch.version {
                        patch_pack.push(diags::NoNewerVersionAvailable {
                            local_krate,
                            dep: to_patch,
                        });
                        continue;
                    }

                    v.clone()
                }
                None => {
                    //log::warn!("Local crate {:#?} dependency for {}, does not meet any of the required versions {:#?}", local_krate, to_patch.name, candidates);
                    continue;
                }
            };

            patches.push(Patch {
                advisories: candidates.into_iter().map(|pc| pc.advisory).collect(),
                manifest_to_patch: local_krate,
                crate_to_patch: (to_patch.name.as_ref(), version),
            });
        }

        if !patch_pack.is_empty() {
            diags.push(patch_pack);
        }

        Ok(PatchSet {
            patches,
            diagnostics: diags,
        })
    }

    fn find_possible_versions(
        index: &mut Index,
        parent: &Krate,
        child: &Krate,
        required: &[Version],
    ) -> Result<Vec<Version>, NoVersionReason> {
        let mut res = None;

        index.read_krate(parent, |ik| {
            match ik {
                Some(parent_krate) => {
                    // Grab all of the versions of the parent crate that have a version requirement that accepts
                    // any of the specified required versions
                    let available: Vec<_> = parent_krate
                        .versions
                        .iter()
                        // Disregard any versions older than the current one
                        .skip_while(|vs| vs.vers < parent.version)
                        .filter_map(|kv| {
                            let version = &kv.vers;

                            if let Some(dep) = kv.deps.iter().find(|dep| {
                                dep.kind != Some(krates::cm::DependencyKind::Development)
                                    && dep.name == child.name
                            }) {
                                if !required.iter().any(|vs| dep.req.matches(vs)) {
                                    return None;
                                }
                            }

                            // If the dependency has been removed from a future version, it is
                            // also a candidate
                            Some(version.clone())
                        })
                        .collect();

                    if available.is_empty() {
                        res = Some(Err(NoVersionReason::NoMatchingVersions));
                    } else {
                        res = Some(Ok(available));
                    }
                }
                None => {
                    res = Some(Err(NoVersionReason::NoIndexEntry));
                }
            }
        });

        res.unwrap()
    }
}
