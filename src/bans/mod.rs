pub mod cfg;
mod diags;
mod graph;

use self::cfg::{TreeSkip, ValidConfig};
use crate::{
    diag::{self, CfgCoord, FileId, KrateCoord},
    Kid, Krate, Krates, LintLevel,
};
use anyhow::Error;
use semver::{Version, VersionReq};
use std::{cmp::Ordering, fmt};

#[derive(Eq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct KrateId {
    pub(crate) name: String,
    pub(crate) version: VersionReq,
}

impl fmt::Display for KrateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.version)
    }
}

impl Ord for KrateId {
    fn cmp(&self, o: &Self) -> Ordering {
        match self.name.cmp(&o.name) {
            Ordering::Equal => self.version.cmp(&o.version),
            o => o,
        }
    }
}

impl PartialOrd for KrateId {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl PartialEq for KrateId {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}

fn binary_search<'a>(
    arr: &'a [cfg::Skrate],
    details: &Krate,
) -> Result<(usize, &'a cfg::Skrate), usize> {
    let lowest = VersionReq::exact(&Version::new(0, 0, 0));

    match arr.binary_search_by(|i| match i.value.name.cmp(&details.name) {
        Ordering::Equal => i.value.version.cmp(&lowest),
        o => o,
    }) {
        Ok(i) => Ok((i, &arr[i])),
        Err(i) => {
            // Backtrack 1 if the crate name matches, as, for instance, wildcards will be sorted
            // before the 0.0.0 version
            let begin = if i > 0 && arr[i - 1].value.name == details.name {
                i - 1
            } else {
                i
            };

            for (j, krate) in arr[begin..].iter().enumerate() {
                if krate.value.name != details.name {
                    break;
                }

                if krate.value.version.matches(&details.version) {
                    return Ok((begin + j, krate));
                }
            }

            Err(i)
        }
    }
}

struct SkipRoot {
    span: std::ops::Range<usize>,
    skip_crates: Vec<Kid>,
    skip_hits: bitvec::vec::BitVec,
}

use bitvec::prelude::*;

// If trees are being skipped, walk each one down to the specified depth and add
// each dependency as a skipped crate at the specific version
struct TreeSkipper {
    roots: Vec<SkipRoot>,
    cfg_file_id: FileId,
}

impl TreeSkipper {
    fn build(
        skip_roots: Vec<crate::Spanned<TreeSkip>>,
        krates: &Krates,
        cfg_file_id: FileId,
    ) -> (Self, Pack) {
        let mut roots = Vec::with_capacity(skip_roots.len());

        let mut pack = Pack::new(Check::Bans);

        for ts in skip_roots {
            let num_roots = roots.len();

            for krate in krates.search_matches(&ts.value.id.name, &ts.value.id.version) {
                roots.push(Self::build_skip_root(ts.clone(), krate.0, krates));
            }

            // If no roots were added, add a diagnostic that the user's configuration
            // is outdated so they can fix or clean it up
            if roots.len() == num_roots {
                pack.push(diags::UnmatchedSkipRoot {
                    skip_root_cfg: CfgCoord {
                        file: cfg_file_id,
                        span: ts.span,
                    },
                });
            }
        }

        (Self { roots, cfg_file_id }, pack)
    }

    fn build_skip_root(
        ts: crate::Spanned<TreeSkip>,
        krate_id: krates::NodeId,
        krates: &Krates,
    ) -> SkipRoot {
        let span = ts.span;
        let ts = ts.value;

        let max_depth = ts.depth.unwrap_or(std::usize::MAX);
        let mut skip_crates = Vec::with_capacity(10);

        let graph = krates.graph();

        let mut pending = vec![(krate_id, 1)];
        while let Some((node_id, depth)) = pending.pop() {
            if depth < max_depth {
                for dep in graph.edges_directed(node_id, Direction::Outgoing) {
                    pending.push((dep.target(), depth + 1));
                }
            }

            let pkg_id = &krates[node_id].id;
            if let Err(i) = skip_crates.binary_search(pkg_id) {
                skip_crates.insert(i, pkg_id.clone());
            }
        }

        let skip_hits = bitvec![0; skip_crates.len()];

        SkipRoot {
            span,
            skip_crates,
            skip_hits,
        }
    }

    fn matches(&mut self, krate: &Krate, pack: &mut Pack) -> bool {
        let mut skip = false;

        for root in &mut self.roots {
            if let Ok(i) = root.skip_crates.binary_search(&krate.id) {
                pack.push(diags::SkippedByRoot {
                    krate,
                    skip_root_cfg: CfgCoord {
                        file: self.cfg_file_id,
                        span: root.span.clone(),
                    },
                });

                root.skip_hits.as_mut_bitslice().set(i, true);
                skip = true;
            }
        }

        skip
    }
}

fn get_enabled_features<'a>(
    edge: krates::petgraph::graph::EdgeReference<'a, krates::Edge>,
    krates: &'a Krates,
) -> Option<Vec<&'a str>> {
    let mut enabled = Vec::new();
    let mut add_default_features = false;

    // Walk up the dependency graph to figure out which features are actually, really
    // enabled for the actual crate we've been asked to gather features for
    let mut node_stack =
        smallvec::SmallVec::<[krates::petgraph::graph::EdgeReference<'_, krates::Edge>; 10]>::new();
    node_stack.push(edge);

    let krate_name = &krates[edge.target()].name;

    while let Some(edge) = node_stack.pop() {
        let dep = &krates[edge.target()];
        let parent = &krates[edge.source()];

        let kind = edge.weight().kind;
        // This should never happen, but better than panicing!
        let dep_node = match parent
            .deps
            .iter()
            .find(|d| krates::DepKind::from(d.kind) == kind && d.name == dep.name)
        {
            Some(d) => d,
            None => return None,
        };

        dep_node.features.iter().map(|s| s.as_ref()).collect();
    }

    let dep = &krates[edge.target()];

    if add_default_features && dep.features.contains_key("default") {
        let mut feature_stack = vec!["default"];

        while let Some(feat) = feature_stack.pop() {
            enabled.push(feat);
            if let Some(feats) = dep.features.get(feat) {
                for sub_feat in feats {
                    feature_stack.push(sub_feat);
                }
            }
        }
    }

    enabled.sort();
    enabled.dedup();
    Some(enabled)
}

pub struct DupGraph {
    pub duplicate: String,
    pub graph: String,
}

pub type OutputGraph = dyn Fn(DupGraph) -> Result<(), Error> + Send + Sync;

use crate::diag::{Check, Diag, Pack, Severity};
use krates::petgraph::{visit::EdgeRef, Direction};

pub fn check(
    ctx: crate::CheckCtx<'_, ValidConfig>,
    output_graph: Option<Box<OutputGraph>>,
    cargo_spans: diag::CargoSpans,
    mut sink: diag::ErrorSink,
) {
    let wildcard = VersionReq::parse("*").expect("Parsing wildcard mustnt fail");

    let ValidConfig {
        file_id,
        denied,
        allowed,
        skipped,
        multiple_versions,
        highlight,
        tree_skipped,
        wildcards,
        ..
    } = ctx.cfg;

    let krates = &ctx.krates;
    let krate_spans = &ctx.krate_spans;
    let (mut tree_skipper, build_diags) = TreeSkipper::build(tree_skipped, krates, file_id);

    if !build_diags.is_empty() {
        sink.push(build_diags);
    }

    let denied_ids: Vec<_> = denied.iter().map(|kb| kb.id.clone()).collect();
    let denied_info = denied;

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit = bitvec![0; skipped.len()];

    struct MultiDetector<'a> {
        name: &'a str,
        dupes: smallvec::SmallVec<[usize; 2]>,
    }

    let mut multi_detector = MultiDetector {
        name: &krates.krates().next().unwrap().krate.name,
        dupes: smallvec::SmallVec::new(),
    };

    let colorize = ctx.colorize;

    for (i, krate) in krates.krates().map(|kn| &kn.krate).enumerate() {
        let mut pack = Pack::with_kid(Check::Bans, krate.id.clone());

        //let krate_coord = krate_spans.get_coord(i);

        if let Ok((bind, _ban)) = binary_search(&denied_ids, krate) {
            let ban_cfg = CfgCoord {
                file: file_id,
                span: denied_ids[bind].span.clone(),
            };

            // The crate is banned, but it might have be allowed if it's wrapped
            // by one or more particular crates
            let allowed_wrappers = &denied_info[bind].wrappers;
            let is_allowed = if !allowed_wrappers.is_empty() {
                let nid = krates.nid_for_kid(&krate.id).unwrap();
                let graph = krates.graph();

                // Ensure that every single crate that has a direct dependency
                // on the banned crate is an allowed wrapper
                graph
                    .edges_directed(nid, Direction::Incoming)
                    .map(|edge| edge.source())
                    .all(|nid| {
                        let node = &graph[nid];

                        let (diag, is_allowed): (Diag, _) = match allowed_wrappers
                            .iter()
                            .find(|aw| aw.value == node.krate.name)
                        {
                            Some(aw) => (
                                diags::BannedAllowedByWrapper {
                                    ban_cfg: ban_cfg.clone(),
                                    ban_exception_cfg: CfgCoord {
                                        file: file_id,
                                        span: aw.span.clone(),
                                    },
                                    banned_krate: krate,
                                    wrapper_krate: &node.krate,
                                }
                                .into(),
                                true,
                            ),
                            None => (
                                diags::BannedUnmatchedWrapper {
                                    ban_cfg: ban_cfg.clone(),
                                    banned_krate: krate,
                                    parent_krate: &node.krate,
                                }
                                .into(),
                                false,
                            ),
                        };

                        pack.push(diag);
                        is_allowed
                    })
            } else {
                let exact = &denied_info[bind].exact_features.value;
                let af = &denied_info[bind].allow_features.value;
                let df = &denied_info[bind].deny_features.value;

                *exact || !af.is_empty() || !df.is_empty()
            };

            // Ensure that the feature set of this krate, wherever it's used
            // as a dependency, matches the ban entry.
            let nid = krates.nid_for_kid(&krate.id).unwrap();
            let graph = krates.graph();

            let feature_set_allowed = graph
                .edges_directed(nid, Direction::Incoming)
                .map(|edge| edge.source())
                .all(|pid| {
                    let parent = &graph[pid];

                    let exact = &denied_info[bind].exact_features;
                    let allowed_features = &denied_info[bind].allow_features;
                    let denied_features = &denied_info[bind].deny_features;
                    let dep = parent
                        .krate
                        .deps
                        .iter()
                        .find(|dep| dep.name == krate.name)
                        .unwrap();

                    // We need to retrieve the features used by the dependency, and if default
                    // features are enabled, crawl all of them from the package itself
                    // to retrieve the true enabled set
                    let enabled_features = match get_enabled_features(&dep, krates) {
                        Some(ef) => ef,
                        None => {
                            pack.push(diags::UnableToGetDefaultFeatures {
                                parent_krate: &parent.krate,
                                dep,
                            });
                            return false;
                        }
                    };

                    // Gather features that were present, but not explicitly allowed
                    let not_allowed: Vec<_> = enabled_features
                        .iter()
                        .filter_map(|df| {
                            if allowed_features
                                .value
                                .iter()
                                .find(|af| &af.value == df)
                                .is_none()
                            {
                                Some(df.as_ref())
                            } else {
                                None
                            }
                        })
                        .collect();

                    if exact.value {
                        // Gather features allowed, but not present
                        let missing_allowed: Vec<_> = allowed_features
                            .value
                            .iter()
                            .filter_map(|af| {
                                if enabled_features
                                    .iter()
                                    .find(|df| **df == af.value)
                                    .is_none()
                                {
                                    Some(CfgCoord {
                                        file: file_id,
                                        span: af.span.clone(),
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect();

                        if missing_allowed.is_empty() && not_allowed.is_empty() {
                            true
                        } else {
                            pack.push(diags::ExactFeaturesMismatch {
                                missing_allowed,
                                not_allowed: &not_allowed,
                                parent: &parent.krate,
                                dep_name: &dep.name,
                                exact_coord: CfgCoord {
                                    file: file_id,
                                    span: exact.span.clone(),
                                },
                            });
                            false
                        }
                    } else {
                        // Add diagnostics if features were explicitly allowed, but weren't present
                        let mut feature_set_allowed = true;
                        if !allowed_features.value.is_empty() && !not_allowed.is_empty() {
                            pack.push(diags::FeaturesNotExplicitlyAllowed {
                                not_allowed: &not_allowed,
                                enabled_features: &enabled_features,
                                parent: &parent.krate,
                                dep_name: &dep.name,
                                allowed: allowed_features
                                    .value
                                    .iter()
                                    .map(|af| CfgCoord {
                                        file: file_id,
                                        span: af.span.clone(),
                                    })
                                    .collect(),
                                colorize,
                            });

                            feature_set_allowed = false;
                        }

                        let found_denied: Vec<_> = denied_features
                            .value
                            .iter()
                            .filter(|deny_f| enabled_features.contains(&deny_f.value.as_str()))
                            .collect();

                        // Add diagnostics for features that were explicitly denied
                        if !found_denied.is_empty() {
                            pack.push(diags::FeaturesExplicitlyDenied {
                                cfg_file_id: file_id,
                                found_denied,
                                enabled_features: &enabled_features,
                                parent: &parent.krate,
                                dep_name: &dep.name,
                                colorize,
                            });

                            feature_set_allowed = false;
                        }

                        feature_set_allowed
                    }
                });

            if !is_allowed || !feature_set_allowed {
                pack.push(diags::ExplicitlyBanned { krate, ban_cfg });
            }
        }

        if !allowed.is_empty() {
            // Since only allowing specific crates is pretty draconian,
            // also emit which allow filters actually passed each crate
            match binary_search(&allowed, krate) {
                Ok((_, allow)) => {
                    pack.push(diags::ExplicitlyAllowed {
                        krate,
                        allow_cfg: CfgCoord {
                            file: file_id,
                            span: allow.span.clone(),
                        },
                    });
                }
                Err(_) => {
                    pack.push(diags::ImplicitlyBanned { krate });
                }
            }
        }

        if let Ok((index, skip)) = binary_search(&skipped, krate) {
            pack.push(diags::Skipped {
                krate,
                skip_cfg: CfgCoord {
                    file: file_id,
                    span: skip.span.clone(),
                },
            });

            // Keep a count of the number of times each skip filter is hit
            // so that we can report unused filters to the user so that they
            // can cleanup their configs as their dependency graph changes over time
            skip_hit.as_mut_bitslice().set(index, true);
        } else if !tree_skipper.matches(krate, &mut pack) {
            if multi_detector.name == krate.name {
                multi_detector.dupes.push(i);
            } else {
                if multi_detector.dupes.len() > 1 && multiple_versions != LintLevel::Allow {
                    let severity = match multiple_versions {
                        LintLevel::Warn => Severity::Warning,
                        LintLevel::Deny => Severity::Error,
                        LintLevel::Allow => unreachable!(),
                    };

                    let mut all_start = std::usize::MAX;
                    let mut all_end = 0;

                    let mut kids = smallvec::SmallVec::<[Kid; 2]>::new();

                    #[allow(clippy::needless_range_loop)]
                    for dup in multi_detector.dupes.iter().cloned() {
                        let span = &ctx.krate_spans[dup];

                        if span.start < all_start {
                            all_start = span.start
                        }

                        if span.end > all_end {
                            all_end = span.end
                        }

                        let krate = &ctx.krates[dup];

                        kids.push(krate.id.clone());
                    }

                    {
                        let mut diag: Diag = diags::Duplicates {
                            krate_name: multi_detector.name,
                            num_dupes: kids.len(),
                            krates_coord: KrateCoord {
                                file: krate_spans.file_id,
                                span: all_start..all_end,
                            },
                            severity,
                        }
                        .into();

                        diag.kids = kids;

                        let mut pack = Pack::new(Check::Bans);
                        pack.push(diag);

                        sink.push(pack);
                    }

                    if let Some(ref og) = output_graph {
                        match graph::create_graph(
                            multi_detector.name,
                            highlight,
                            ctx.krates,
                            &multi_detector.dupes,
                        ) {
                            Ok(graph) => {
                                if let Err(e) = og(DupGraph {
                                    duplicate: multi_detector.name.to_owned(),
                                    graph,
                                }) {
                                    log::error!("{}", e);
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "unable to create graph for {}: {}",
                                    multi_detector.name,
                                    e
                                );
                            }
                        };
                    }
                }

                multi_detector.name = &krate.name;
                multi_detector.dupes.clear();
                multi_detector.dupes.push(i);
            }

            if wildcards != LintLevel::Allow {
                let severity = match wildcards {
                    LintLevel::Warn => Severity::Warning,
                    LintLevel::Deny => Severity::Error,
                    LintLevel::Allow => unreachable!(),
                };

                let wildcards: Vec<_> = krate
                    .deps
                    .iter()
                    .filter(|dep| dep.req == wildcard)
                    .collect();

                if !wildcards.is_empty() {
                    sink.push(diags::Wildcards {
                        krate,
                        severity,
                        wildcards,
                        cargo_spans: &cargo_spans,
                    });
                }
            }
        }

        if !pack.is_empty() {
            sink.push(pack);
        }
    }

    let mut pack = Pack::new(Check::Bans);

    for skip in skip_hit
        .into_iter()
        .zip(skipped.into_iter())
        .filter_map(|(hit, skip)| if !hit { Some(skip) } else { None })
    {
        pack.push(diags::UnmatchedSkip {
            skip_cfg: CfgCoord {
                file: file_id,
                span: skip.span,
            },
        });
    }

    sink.push(pack);
}

#[cfg(test)]
mod test {
    use super::{cfg::CrateId, *};

    #[test]
    fn binary_search_() {
        let versions = [
            CrateId {
                name: "unicase".to_owned(),
                version: VersionReq::parse("=1.4.2").unwrap(),
            },
            CrateId {
                name: "crossbeam-deque".to_owned(),
                version: VersionReq::parse("=0.6.3").unwrap(),
            },
            CrateId {
                name: "parking_lot".to_owned(),
                version: VersionReq::parse("=0.7.1").unwrap(),
            },
            CrateId {
                name: "parking_lot_core".to_owned(),
                version: VersionReq::parse("=0.4.0").unwrap(),
            },
            CrateId {
                name: "lock_api".to_owned(),
                version: VersionReq::parse("=0.1.5").unwrap(),
            },
            CrateId {
                name: "rand".to_owned(),
                version: VersionReq::parse("=0.6.5").unwrap(),
            },
            CrateId {
                name: "rand_chacha".to_owned(),
                version: VersionReq::parse("=0.1.1").unwrap(),
            },
            CrateId {
                name: "rand_core".to_owned(),
                version: VersionReq::parse("=0.4.0").unwrap(),
            },
            CrateId {
                name: "rand_core".to_owned(),
                version: VersionReq::parse("=0.3.1").unwrap(),
            },
            CrateId {
                name: "rand_hc".to_owned(),
                version: VersionReq::parse("=0.1.0").unwrap(),
            },
            CrateId {
                name: "rand_pcg".to_owned(),
                version: VersionReq::parse("=0.1.2").unwrap(),
            },
            CrateId {
                name: "winapi".to_owned(),
                version: VersionReq::parse("<0.3").unwrap(),
            },
            CrateId {
                name: "serde".to_owned(),
                version: VersionReq::any(),
            },
            CrateId {
                name: "scopeguard".to_owned(),
                version: VersionReq::parse("=0.3.3").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("=0.1.43").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("<0.1").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("<0.2").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("0.1.*").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("<0.1.42").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse(">0.1.43").unwrap(),
            },
        ];

        let mut versions: Vec<_> = versions
            .iter()
            .map(|v| {
                #[allow(clippy::reversed_empty_ranges)]
                crate::Spanned::new(
                    super::KrateId {
                        name: v.name.clone(),
                        version: v.version.clone(),
                    },
                    0..0,
                )
            })
            .collect();

        versions.sort();

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "rand_core".to_owned(),
                    version: Version::parse("0.3.1").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::parse("=0.3.1").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "serde".to_owned(),
                    version: Version::parse("1.0.94").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::any())
        );

        assert!(binary_search(
            &versions,
            &crate::Krate {
                name: "nope".to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                ..Default::default()
            }
        )
        .is_err());

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.1.43").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::parse("=0.1.43").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.1.2").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::parse("<0.1.42").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.2.0").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::parse(">0.1.43").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.0.99").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::parse("<0.1").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::Krate {
                    name: "winapi".to_owned(),
                    version: Version::parse("0.2.8").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.value.version)
            .unwrap(),
            &(VersionReq::parse("<0.3").unwrap())
        );

        assert!(binary_search(
            &versions,
            &crate::Krate {
                name: "winapi".to_owned(),
                version: Version::parse("0.3.8").unwrap(),
                ..Default::default()
            }
        )
        .is_err());
    }
}
