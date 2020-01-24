pub mod cfg;
mod graph;

use self::cfg::{TreeSkip, ValidConfig};
use crate::{Kid, Krate, Krates, LintLevel};
use anyhow::Error;
use semver::{Version, VersionReq};
use std::cmp::Ordering;

#[derive(Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct KrateId {
    pub(crate) name: String,
    pub(crate) version: VersionReq,
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
    span: std::ops::Range<u32>,
    skip_crates: Vec<Kid>,
    skip_hits: bitvec::vec::BitVec,
}

use bitvec::prelude::*;

// If trees are being skipped, walk each one down to the specified depth and add
// each dependency as a skipped crate at the specific version
struct TreeSkipper {
    roots: Vec<SkipRoot>,
    file_id: codespan::FileId,
}

impl TreeSkipper {
    fn build(
        skip_roots: Vec<crate::Spanned<TreeSkip>>,
        krates: &Krates,
        file_id: codespan::FileId,
        sender: crossbeam::channel::Sender<Pack>,
    ) -> Self {
        let mut roots = Vec::with_capacity(skip_roots.len());

        for ts in skip_roots {
            let num_roots = roots.len();

            for krate in krates.search_matches(&ts.value.id.name, &ts.value.id.version) {
                roots.push(Self::build_skip_root(ts.clone(), krate.0, krates));
            }

            if roots.len() == num_roots {
                sender
                    .send(
                        Diagnostic::new(
                            Severity::Warning,
                            "skip tree root was not found in the dependency graph",
                            Label::new(file_id, ts.span, "no crate matched these criteria"),
                        )
                        .into(),
                    )
                    .unwrap();
            }
        }

        Self { roots, file_id }
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
                use krates::petgraph::visit::EdgeRef;
                for dep in graph.edges_directed(node_id, krates::petgraph::Direction::Outgoing) {
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
                pack.push(Diagnostic::new(
                    Severity::Help,
                    format!("skipping crate {} = {}", krate.name, krate.version),
                    Label::new(self.file_id, root.span.clone(), "matched root filter"),
                ));

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

use crate::diag::{Diag, Diagnostic, Label, Pack, Severity};

pub fn check(
    ctx: crate::CheckCtx<'_, ValidConfig>,
    output_graph: Option<Box<OutputGraph>>,
    sender: crossbeam::channel::Sender<Pack>,
) {
    let ValidConfig {
        file_id,
        denied,
        allowed,
        skipped,
        multiple_versions,
        highlight,
        tree_skipped,
        ..
    } = ctx.cfg;

    let mut tree_skipper = TreeSkipper::build(tree_skipped, ctx.krates, file_id, sender.clone());

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
        let mut pack = Pack::with_kid(krate.id.clone());

        if let Ok((_, ban)) = binary_search(&denied, krate) {
            pack.push(Diagnostic::new(
                Severity::Error,
                format!("detected banned crate {} = {}", krate.name, krate.version),
                Label::new(file_id, ban.span.clone(), "matching ban entry"),
            ));
        }

        if !allowed.is_empty() {
            // Since only allowing specific crates is pretty draconian,
            // also emit which allow filters actually passed each crate
            match binary_search(&allowed, krate) {
                Ok((_, allow)) => {
                    pack.push(Diagnostic::new(
                        Severity::Note,
                        format!("allowed {} = {}", krate.name, krate.version),
                        Label::new(file_id, allow.span.clone(), "matching allow entry"),
                    ));
                }
                Err(mut ind) => {
                    if ind >= allowed.len() {
                        ind = allowed.len() - 1;
                    }

                    pack.push(Diagnostic::new(
                        Severity::Error,
                        format!(
                            "detected crate not specifically allowed {} = {}",
                            krate.name, krate.version
                        ),
                        Label::new(file_id, allowed[ind].span.clone(), "closest match"),
                    ));
                }
            }
        }

        if let Ok((index, skip)) = binary_search(&skipped, krate) {
            pack.push(Diagnostic::new(
                Severity::Help,
                format!("skipping crate {} = {}", krate.name, krate.version),
                Label::new(file_id, skip.span.clone(), "matched filter"),
            ));

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

                    let mut all_start = std::u32::MAX;
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

                    let mut diag = Diag::new(Diagnostic::new(
                        severity,
                        format!(
                            "found {} duplicate entries for crate '{}'",
                            kids.len(),
                            multi_detector.name
                        ),
                        Label::new(ctx.spans_id, all_start..all_end, "lock entries"),
                    ));

                    diag.kids = kids;

                    let mut pack = Pack::new();
                    pack.push(diag);

                    sender.send(pack).unwrap();

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
        }

        if !pack.is_empty() {
            sender.send(pack).unwrap();
        }
    }

    for skip in skip_hit
        .into_iter()
        .zip(skipped.into_iter())
        .filter_map(|(hit, skip)| if !hit { Some(skip) } else { None })
    {
        sender
            .send(
                Diagnostic::new(
                    Severity::Warning,
                    "skipped crate was not encountered",
                    Label::new(
                        ctx.cfg.file_id,
                        skip.span,
                        "no crate matched these criteria",
                    ),
                )
                .into(),
            )
            .unwrap();
    }
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
