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

#[derive(Eq)]
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

    let krate_spans = &ctx.krate_spans;
    let (mut tree_skipper, build_diags) = TreeSkipper::build(tree_skipped, ctx.krates, file_id);

    if !build_diags.is_empty() {
        sink.push(build_diags);
    }

    struct KrateBanInfo {
        wrappers: Vec<Spanned<String>>,
        allow_features: Spanned<Vec<Spanned<String>>>,
        deny_features: Spanned<Vec<Spanned<String>>>,
        exact_features: Spanned<bool>,
    }

    let (denied_ids, denied_info): (Vec<_>, Vec<_>) = denied
        .into_iter()
        .map(|kb| {
            (
                kb.id,
                KrateBanInfo {
                    wrappers: kb.wrappers,
                    allow_features: kb.allow_features,
                    deny_features: kb.deny_features,
                    exact_features: kb.exact_features,
                },
            )
        })
        .unzip();

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit = bitvec![0; skipped.len()];

    struct MultiDetector<'a> {
        name: &'a str,
        dupes: smallvec::SmallVec<[usize; 2]>,
    }

    let mut multi_detector = MultiDetector {
        name: &ctx.krates.krates().next().unwrap().krate.name,
        dupes: smallvec::SmallVec::new(),
    };

    for (i, krate) in ctx.krates.krates().map(|kn| &kn.krate).enumerate() {
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
                let nid = ctx.krates.nid_for_kid(&krate.id).unwrap();
                let graph = ctx.krates.graph();

                // Ensure that every single crate that has a direct dependency
                // on the banned crate is an allowed wrapper
                graph
                    .edges_directed(nid, Direction::Incoming)
                    .map(|edge| edge.source())
                    .all(|nid| {
                        let node = &graph[nid];
                        //let krate_coord = krate_spans.get_coord(nid.index());

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
                false
            };

            // Ensure that the feature set of this krate, wherever it's used
            // as a dependency, matches the ban entry.
            let nid = ctx.krates.nid_for_kid(&krate.id).unwrap();
            let graph = ctx.krates.graph();
            let features_allowed = graph
                .edges_directed(nid, Direction::Incoming)
                .map(|edge| edge.source())
                .all(|nid| {
                    let node = &graph[nid];

                    let exact = &denied_info[bind].exact_features;
                    let af = &denied_info[bind].allow_features;
                    let df = &denied_info[bind].deny_features;
                    let dep = node
                        .krate
                        .deps
                        .iter()
                        .find(|dep| dep.name == krate.name)
                        .unwrap();
                    let cf = &dep.features;

                    let mut cached_span = None;
                    let feature_set_span = |features: &[String]| match cached_span {
                        Some(cached) => cached,
                        None => {
                            let manifest = format!(
                                "[dependencies]\n{} = {{ version = {}, features = [{}] }}\n",
                                dep.name,
                                dep.req,
                                features
                                    .iter()
                                    .map(|name| format!("\"{}\"", name))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            );
                        }
                    };

                    if exact.value {
                        // TODO: We need to properly report the invalid feature set.
                        // How should we report it?
                        if cf.len() == af.value.len() {
                            let mut allowed = true;
                            for f in &af.value {
                                if !cf.contains(&f.value) {
                                    pack.push(
                                        Diagnostic::error()
                                            .with_message(format!(
                                                "invalid feature set for {}",
                                                krate
                                            ))
                                            .with_labels(vec![
                                                Label::primary(
                                                    spans_id,
                                                    krate_spans[nid.index()].clone(),
                                                )
                                                .with_message(format!(
                                                    "this crate has feature `{}` enabled...",
                                                    f.value
                                                )),
                                                Label::secondary(file_id, f.span.clone())
                                                    .with_message("...which is banned here"),
                                            ]),
                                    );
                                    allowed = false;
                                }
                            }
                            allowed
                        } else {
                            pack.push(
                                Diagnostic::error()
                                    .with_message(format!("invalid feature set for {}", krate))
                                    .with_labels(vec![Label::primary(file_id, af.span.clone())
                                        .with_message(
                                            "lengths of the feature sets do not match...",
                                        )])
                                    .with_notes(vec![
                                        "but they have to, because `exact_features` is enabled"
                                            .into(),
                                    ]),
                            );
                            false
                        }
                    } else {
                        todo!()
                    }
                });

            let is_allowed = is_allowed || features_allowed;

            if !is_allowed {
                pack.push(
                    Diagnostic::error()
                        .with_message(format!("detected banned crate {}", krate,))
                        .with_labels(vec![Label::primary(file_id, ban.span.clone())
                            .with_message("matching ban entry")]),
                );
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
