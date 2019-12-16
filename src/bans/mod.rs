mod cfg;
mod graph;

use crate::{LintLevel, Pid};
use semver::{Version, VersionReq};
use std::cmp::Ordering;

pub use self::cfg::{Config, ValidConfig};

#[derive(Eq)]
pub struct KrateId {
    name: String,
    version: VersionReq,
    span: std::ops::Range<u32>,
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
    arr: &'a [KrateId],
    details: &crate::KrateDetails,
) -> Result<(usize, &'a KrateId), usize> {
    let lowest = VersionReq::exact(&Version::new(0, 0, 0));

    match arr.binary_search_by(|i| match i.name.cmp(&details.name) {
        Ordering::Equal => i.version.cmp(&lowest),
        o => o,
    }) {
        Ok(i) => Ok((i, &arr[i])),
        Err(i) => {
            // Backtrack 1 if the crate name matches, as, for instance, wildcards will be sorted
            // before the 0.0.0 version
            let begin = if i > 0 && arr[i - 1].name == details.name {
                i - 1
            } else {
                i
            };

            for (j, krate) in arr[begin..].iter().enumerate() {
                if krate.name != details.name {
                    break;
                }

                if krate.version.matches(&details.version) {
                    return Ok((begin + j, krate));
                }
            }

            Err(i)
        }
    }
}

struct SkipRoot {
    span: std::ops::Range<u32>,
    skip_crates: Vec<Pid>,
    skip_hits: bitvec::vec::BitVec,
}

use bitvec::prelude::*;

fn build_skip_root(
    ts: toml::Spanned<TreeSkip>,
    krate: &crate::KrateDetails,
    krates: &crate::Krates,
) -> SkipRoot {
    let span = ts.start() as u32..ts.end() as u32;
    let ts = ts.into_inner();

    let max_depth = ts.depth.unwrap_or(std::usize::MAX);

    let mut pending = smallvec::SmallVec::<[(Pid, usize); 10]>::new();
    pending.push((krate.id.clone(), 0));

    let mut skip_crates = Vec::with_capacity(10);
    while let Some((pkg_id, depth)) = pending.pop() {
        if depth < max_depth {
            let node = &krates.resolved.nodes[krates
                .resolved
                .nodes
                .binary_search_by(|n| n.id.cmp(&pkg_id))
                .unwrap()];
            for dep in &node.dependencies {
                pending.push((dep.clone(), depth + 1));
            }
        }

        if let Err(i) = skip_crates.binary_search(&pkg_id) {
            skip_crates.insert(i, pkg_id);
        }
    }

    let skip_hits = bitvec![0; skip_crates.len()];

    SkipRoot {
        span,
        skip_crates,
        skip_hits,
    }
}

pub struct DupGraph {
    pub duplicate: String,
    pub graph: String,
}

pub type OutputGraph = dyn Fn(DupGraph) -> Result<(), Error> + Send + Sync;

use crate::diag::{self, Diagnostic, Label, Pack, Severity};

pub fn check(
    cfg: ValidConfig,
    krates: &crate::Krates,
    (krate_spans, spans_id): (&diag::KrateSpans, codespan::FileId),
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
        ..
    } = cfg;

    struct TreeSkipper {
        roots: Vec<SkipRoot>,
    }

    let file_id = cfg.file_id;

    // If trees are being skipped, walk each one down to the specified depth and add
    // each dependency as a skipped crate at the specific version
    let mut tree_skip = if !cfg.tree_skipped.is_empty() {
        let roots: Vec<_> = cfg
            .tree_skipped
            .into_iter()
            .filter_map(|ts| {
                match krates.search_match(&ts.get_ref().id.name, &ts.get_ref().id.version) {
                    Some(ind) => Some(build_skip_root(ts, &krates.krates[ind], krates)),
                    None => {
                        sender
                            .send(Pack {
                                krate_id: None,
                                diagnostics: vec![Diagnostic::new(
                                    Severity::Warning,
                                    "skip tree root was not found in the dependency graph",
                                    Label::new(
                                        file_id,
                                        ts.start() as u32..ts.end() as u32,
                                        "no crate matched these criteria",
                                    ),
                                )],
                            })
                            .unwrap();

                        None
                    }
                }
            })
            .collect();

        Some(TreeSkipper { roots })
    } else {
        None
    };

    let mut check_root_filters = |krate: &crate::KrateDetails, diags: &mut Vec<Diagnostic>| {
        if let Some(ref mut tree_skipper) = tree_skip {
            let mut skip = false;

            for root in &mut tree_skipper.roots {
                if let Ok(i) = root.skip_crates.binary_search(&krate.id) {
                    diags.push(Diagnostic::new(
                        Severity::Help,
                        format!("skipping crate {} = {}", krate.name, krate.version),
                        Label::new(file_id, root.span.clone(), "matched root filter"),
                    ));

                    root.skip_hits.as_mut_bitslice().set(i, true);
                    skip = true;
                }
            }

            skip
        } else {
            false
        }
    };

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit = bitvec![0; cfg.skipped.len()];

    struct MultiDetector<'a> {
        name: &'a str,
        dupes: smallvec::SmallVec<[usize; 2]>,
    }

    let mut multi_detector = MultiDetector {
        name: &krates.as_ref()[0].name,
        dupes: smallvec::SmallVec::new(),
    };

    for (i, krate) in krates.iter().enumerate() {
        let mut diagnostics = Vec::new();

        if let Ok((_, ban)) = binary_search(&cfg.denied, krate) {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("detected banned crate {} = {}", krate.name, krate.version),
                Label::new(cfg.file_id, ban.span.clone(), "matching ban entry"),
            ));
        }

        if !cfg.allowed.is_empty() {
            // Since only allowing specific crates is pretty draconian,
            // also emit which allow filters actually passed each crate
            match binary_search(&cfg.allowed, krate) {
                Ok((_, allow)) => {
                    diagnostics.push(Diagnostic::new(
                        Severity::Note,
                        format!("allowed {} = {}", krate.name, krate.version),
                        Label::new(cfg.file_id, allow.span.clone(), "matching allow entry"),
                    ));
                }
                Err(mut ind) => {
                    if ind >= cfg.allowed.len() {
                        ind = cfg.allowed.len() - 1;
                    }

                    diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        format!(
                            "detected crate not specifically allowed {} = {}",
                            krate.name, krate.version
                        ),
                        Label::new(cfg.file_id, cfg.allowed[ind].span.clone(), "closest match"),
                    ));
                }
            }
        }

        if let Ok((index, skip)) = binary_search(&cfg.skipped, krate) {
            diagnostics.push(Diagnostic::new(
                Severity::Help,
                format!("skipping crate {} = {}", krate.name, krate.version),
                Label::new(cfg.file_id, skip.span.clone(), "matched filter"),
            ));

            // Keep a count of the number of times each skip filter is hit
            // so that we can report unused filters to the user so that they
            // can cleanup their configs as their dependency graph changes over time
            skip_hit.as_mut_bitslice().set(index, true);
        } else if !check_root_filters(krate, &mut diagnostics) {
            if multi_detector.name == krate.name {
                multi_detector.dupes.push(i);
            } else {
                if multi_detector.dupes.len() > 1 && cfg.multiple_versions != LintLevel::Allow {
                    let severity = match cfg.multiple_versions {
                        LintLevel::Warn => Severity::Warning,
                        LintLevel::Deny => Severity::Error,
                        LintLevel::Allow => unreachable!(),
                    };

                    let mut all_start = std::u32::MAX;
                    let mut all_end = 0;

                    let mut dupes = Vec::with_capacity(multi_detector.dupes.len());

                    #[allow(clippy::needless_range_loop)]
                    for dup in multi_detector.dupes.iter().cloned() {
                        let span = &krate_spans[dup];

                        if span.start < all_start {
                            all_start = span.start
                        }

                        if span.end > all_end {
                            all_end = span.end
                        }

                        let krate = &krates.krates[dup];

                        dupes.push(Pack {
                            krate_id: Some(krate.id.clone()),
                            diagnostics: vec![Diagnostic::new(
                                severity,
                                format!(
                                    "duplicate #{} ({}) {} = {}",
                                    dupes.len() + 1,
                                    dup,
                                    krate.name,
                                    krate.version
                                ),
                                Label::new(spans_id, span.clone(), "lock entry"),
                            )],
                        });
                    }

                    sender
                        .send(Pack {
                            krate_id: None,
                            diagnostics: vec![Diagnostic::new(
                                severity,
                                format!(
                                    "found {} duplicate entries for crate '{}'",
                                    dupes.len(),
                                    multi_detector.name
                                ),
                                Label::new(spans_id, all_start..all_end, "lock entries"),
                            )],
                        })
                        .unwrap();

                    for dup in dupes {
                        sender.send(dup).unwrap();
                    }

                    if let Some(ref og) = output_graph {
                        let graph = graph::create_graph(
                            multi_detector.name,
                            cfg.highlight,
                            krates,
                            &multi_detector.dupes,
                        )?;

                        og(DupGraph {
                            duplicate: multi_detector.name.to_owned(),
                            graph,
                        })?;
                    }
                }

                multi_detector.name = &krate.name;
                multi_detector.dupes.clear();
                multi_detector.dupes.push(i);
            }
        }

        if !diagnostics.is_empty() {
            sender
                .send(crate::DiagPack {
                    krate_id: Some(krate.id.clone()),
                    diagnostics,
                })
                .unwrap();
        }
    }

    for (hit, skip) in skip_hit.into_iter().zip(cfg.skipped.into_iter()) {
        if !hit {
            sender
                .send(crate::DiagPack {
                    krate_id: None,
                    diagnostics: vec![Diagnostic::new(
                        Severity::Warning,
                        "skipped crate was not encountered",
                        Label::new(cfg.file_id, skip.span, "no crate matched these criteria"),
                    )],
                })
                .unwrap();
        }
    }

    Ok(())
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
            .map(|v| super::KrateId {
                name: v.name.clone(),
                version: v.version.clone(),
                span: 0..0,
            })
            .collect();

        versions.sort();

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "rand_core".to_owned(),
                    version: Version::parse("0.3.1").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("=0.3.1").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "serde".to_owned(),
                    version: Version::parse("1.0.94").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::any())
        );

        assert!(binary_search(
            &versions,
            &crate::KrateDetails {
                name: "nope".to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                ..Default::default()
            }
        )
        .is_err());

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.1.43").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("=0.1.43").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.1.2").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("<0.1.42").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.2.0").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse(">0.1.43").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.0.99").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("<0.1").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "winapi".to_owned(),
                    version: Version::parse("0.2.8").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("<0.3").unwrap())
        );

        assert!(binary_search(
            &versions,
            &crate::KrateDetails {
                name: "winapi".to_owned(),
                version: Version::parse("0.3.8").unwrap(),
                ..Default::default()
            }
        )
        .is_err());
    }
}
