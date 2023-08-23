pub mod cfg;
mod diags;
mod graph;

use self::cfg::{TreeSkip, ValidBuildConfig, ValidConfig};
use crate::{
    diag::{self, CfgCoord, FileId, KrateCoord},
    Kid, Krate, Krates, LintLevel,
};
use anyhow::Error;
pub use diags::Code;
use krates::cm::DependencyKind;
use semver::VersionReq;
use std::fmt;

#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct KrateId {
    pub(crate) name: String,
    pub(crate) version: Option<VersionReq>,
}

impl fmt::Display for KrateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {:?}", self.name, self.version)
    }
}

struct ReqMatch<'vr> {
    id: &'vr cfg::Skrate,
    index: usize,
}

/// Returns the version requirements that matched the version, if any
#[inline]
fn matches<'v>(arr: &'v [cfg::Skrate], details: &Krate) -> Option<Vec<ReqMatch<'v>>> {
    let matches: Vec<_> = arr
        .iter()
        .enumerate()
        .filter_map(|(index, req)| {
            if req.value.name == details.name
                && crate::match_req(&details.version, req.value.version.as_ref())
            {
                Some(ReqMatch { id: req, index })
            } else {
                None
            }
        })
        .collect();

    if matches.is_empty() {
        None
    } else {
        Some(matches)
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

            for krate in krates
                .krates_by_name(&ts.value.id.name)
                .filter(|(_index, krate)| {
                    crate::match_req(&krate.version, ts.value.id.version.as_ref())
                })
            {
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
            let pkg_id = if let krates::Node::Krate { id, .. } = &graph[node_id] {
                id
            } else {
                continue;
            };
            if let Err(i) = skip_crates.binary_search(pkg_id) {
                skip_crates.insert(i, pkg_id.clone());

                if depth < max_depth {
                    for dep in krates.direct_dependencies(node_id) {
                        pending.push((dep.node_id, depth + 1));
                    }
                }
            }
        }

        let skip_hits = BitVec::repeat(false, skip_crates.len());

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

impl fmt::Debug for DupGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.graph)
    }
}

pub type OutputGraph = dyn Fn(DupGraph) -> Result<(), Error> + Send + Sync;

use crate::diag::{Check, Diag, Pack, Severity};

pub fn check(
    ctx: crate::CheckCtx<'_, ValidConfig>,
    output_graph: Option<Box<OutputGraph>>,
    cargo_spans: diag::CargoSpans,
    sink: impl Into<diag::ErrorSink>,
) {
    let ValidConfig {
        file_id,
        denied,
        denied_multiple_versions,
        allowed,
        features,
        workspace_default_features,
        external_default_features,
        skipped,
        multiple_versions,
        highlight,
        tree_skipped,
        wildcards,
        allow_wildcard_paths,
        build,
    } = ctx.cfg;

    let mut sink = sink.into();
    let krate_spans = &ctx.krate_spans;
    let (mut tree_skipper, build_diags) = TreeSkipper::build(tree_skipped, ctx.krates, file_id);

    if !build_diags.is_empty() {
        sink.push(build_diags);
    }

    let (denied_ids, ban_wrappers): (Vec<_>, Vec<_>) =
        denied.into_iter().map(|kb| (kb.id, kb.wrappers)).unzip();

    let (feature_ids, features): (Vec<_>, Vec<_>) =
        features.into_iter().map(|cf| (cf.id, cf.features)).unzip();

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit: BitVec = BitVec::repeat(false, skipped.len());

    struct MultiDetector<'a> {
        name: &'a str,
        dupes: smallvec::SmallVec<[usize; 2]>,
    }

    let mut multi_detector = MultiDetector {
        name: &ctx.krates.krates().next().unwrap().name,
        dupes: smallvec::SmallVec::new(),
    };

    let report_duplicates = |multi_detector: &MultiDetector<'_>, sink: &mut diag::ErrorSink| {
        if multi_detector.dupes.len() <= 1 {
            return;
        }

        let lint_level = if multi_detector.dupes.iter().any(|kindex| {
            let krate = &ctx.krates[*kindex];
            matches(&denied_multiple_versions, krate).is_some()
        }) {
            LintLevel::Deny
        } else {
            multiple_versions
        };

        let severity = match lint_level {
            LintLevel::Warn => Severity::Warning,
            LintLevel::Deny => Severity::Error,
            LintLevel::Allow => return,
        };

        let mut all_start = std::usize::MAX;
        let mut all_end = 0;

        struct Dupe {
            /// Unique id, used for printing the actual diagnostic graphs
            id: Kid,
            /// Version, for deterministically ordering the duplicates
            version: semver::Version,
        }

        let mut kids = smallvec::SmallVec::<[Dupe; 2]>::new();

        for dup in multi_detector.dupes.iter().cloned() {
            let span = &ctx.krate_spans[dup];

            if span.start < all_start {
                all_start = span.start;
            }

            if span.end > all_end {
                all_end = span.end;
            }

            let krate = &ctx.krates[dup];

            if let Err(i) = kids.binary_search_by(|other| match other.version.cmp(&krate.version) {
                std::cmp::Ordering::Equal => other.id.cmp(&krate.id),
                ord => ord,
            }) {
                kids.insert(
                    i,
                    Dupe {
                        id: krate.id.clone(),
                        version: krate.version.clone(),
                    },
                );
            }
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

            diag.graph_nodes = kids
                .into_iter()
                .map(|dupe| crate::diag::GraphNode {
                    kid: dupe.id,
                    feature: None,
                })
                .collect();

            let mut pack = Pack::new(Check::Bans);
            pack.push(diag);

            sink.push(pack);
        }

        if let Some(og) = &output_graph {
            match graph::create_graph(
                multi_detector.name,
                highlight,
                ctx.krates,
                &multi_detector.dupes,
            ) {
                Ok(graph) => {
                    if let Err(err) = og(DupGraph {
                        duplicate: multi_detector.name.to_owned(),
                        graph,
                    }) {
                        log::error!("{err}");
                    }
                }
                Err(err) => {
                    log::error!("unable to create graph for {}: {err}", multi_detector.name);
                }
            };
        }
    };

    enum Sink<'k> {
        Build(crossbeam::channel::Sender<(&'k Krate, Pack)>),
        NoBuild(diag::ErrorSink),
    }

    impl<'k> Sink<'k> {
        #[inline]
        fn push(&mut self, krate: &'k Krate, pack: Pack) {
            match self {
                Self::Build(tx) => tx.send((krate, pack)).unwrap(),
                Self::NoBuild(sink) => {
                    if !pack.is_empty() {
                        sink.push(pack);
                    }
                }
            }
        }
    }

    let mut real_sink = sink.clone();

    let (mut tx, rx) = if let Some(bc) = build {
        let (tx, rx) = crossbeam::channel::unbounded();

        (Sink::Build(tx), Some((bc, rx, sink)))
    } else {
        (Sink::NoBuild(sink), None)
    };

    rayon::join(
        || {
            for (i, krate) in ctx.krates.krates().enumerate() {
                let mut pack = Pack::with_kid(Check::Bans, krate.id.clone());

                // Check if the crate has been explicitly banned
                if let Some(matches) = matches(&denied_ids, krate) {
                    for rm in matches {
                        let ban_cfg = CfgCoord {
                            file: file_id,
                            span: rm.id.span.clone(),
                        };

                        // The crate is banned, but it might have be allowed if it's wrapped
                        // by one or more particular crates
                        let is_allowed_by_wrapper = if let Some(wrappers) =
                            ban_wrappers.get(rm.index).and_then(|bw| bw.as_ref())
                        {
                            let nid = ctx.krates.nid_for_kid(&krate.id).unwrap();

                            // Ensure that every single crate that has a direct dependency
                            // on the banned crate is an allowed wrapper
                            ctx.krates.direct_dependents(nid).into_iter().all(|src| {
                                let (diag, is_allowed): (Diag, _) =
                                    match wrappers.iter().find(|aw| aw.value == src.krate.name) {
                                        Some(aw) => (
                                            diags::BannedAllowedByWrapper {
                                                ban_cfg: ban_cfg.clone(),
                                                ban_exception_cfg: CfgCoord {
                                                    file: file_id,
                                                    span: aw.span.clone(),
                                                },
                                                banned_krate: krate,
                                                wrapper_krate: src.krate,
                                            }
                                            .into(),
                                            true,
                                        ),
                                        None => (
                                            diags::BannedUnmatchedWrapper {
                                                ban_cfg: ban_cfg.clone(),
                                                banned_krate: krate,
                                                parent_krate: src.krate,
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

                        if !is_allowed_by_wrapper {
                            pack.push(diags::ExplicitlyBanned { krate, ban_cfg });
                        }
                    }
                }

                if !allowed.is_empty() {
                    // Since only allowing specific crates is pretty draconian,
                    // also emit which allow filters actually passed each crate
                    match matches(&allowed, krate) {
                        Some(matches) => {
                            for rm in matches {
                                pack.push(diags::ExplicitlyAllowed {
                                    krate,
                                    allow_cfg: CfgCoord {
                                        file: file_id,
                                        span: rm.id.span.clone(),
                                    },
                                });
                            }
                        }
                        None => {
                            pack.push(diags::NotAllowed { krate });
                        }
                    }
                }

                let enabled_features = ctx.krates.get_enabled_features(&krate.id).unwrap();

                let default_lint_level = if enabled_features.contains("default") {
                    if ctx.krates.workspace_members().any(|n| {
                        if let krates::Node::Krate { id, .. } = n {
                            id == &krate.id
                        } else {
                            false
                        }
                    }) {
                        workspace_default_features.as_ref()
                    } else {
                        external_default_features.as_ref()
                    }
                } else {
                    None
                };

                if let Some(ll) = default_lint_level {
                    if ll.value == LintLevel::Warn {
                        pack.push(diags::DefaultFeatureEnabled {
                            krate,
                            level: ll,
                            file_id,
                        });
                    }
                }

                // Check if the crate has had features denied/allowed or are required to be exact
                if let Some(matches) = matches(&feature_ids, krate) {
                    for rm in matches {
                        let feature_bans = &features[rm.index];

                        let feature_set_allowed = {
                            // Gather features that were present, but not explicitly allowed
                            let not_explicitly_allowed: Vec<_> = enabled_features
                                .iter()
                                .filter_map(|ef| {
                                    if !feature_bans.allow.value.iter().any(|af| &af.value == ef) {
                                        if ef == "default" {
                                            if let Some(ll) = default_lint_level {
                                                if ll.value != LintLevel::Deny {
                                                    return None;
                                                }
                                            }
                                        }

                                        Some(ef.as_str())
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            if feature_bans.exact.value {
                                // Gather features allowed, but not present
                                let missing_allowed: Vec<_> = feature_bans
                                    .allow
                                    .value
                                    .iter()
                                    .filter_map(|af| {
                                        if !enabled_features.contains(&af.value) {
                                            Some(CfgCoord {
                                                file: file_id,
                                                span: af.span.clone(),
                                            })
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();

                                if missing_allowed.is_empty() && not_explicitly_allowed.is_empty() {
                                    true
                                } else {
                                    pack.push(diags::ExactFeaturesMismatch {
                                        missing_allowed,
                                        not_allowed: &not_explicitly_allowed,
                                        exact_coord: CfgCoord {
                                            file: file_id,
                                            span: feature_bans.exact.span.clone(),
                                        },
                                        krate,
                                    });
                                    false
                                }
                            } else {
                                // Mark the number of current diagnostics, if we add more
                                // the check has failed
                                let diag_count = pack.len();

                                // Add diagnostics if features were explicitly allowed,
                                // but didn't contain 1 or more features that were enabled
                                if !feature_bans.allow.value.is_empty() {
                                    for feature in &not_explicitly_allowed {
                                        // Since the user has not specified `exact` we
                                        // can also look at the full tree of features to
                                        // determine if the feature is covered by an allowed
                                        // parent feature
                                        fn has_feature(
                                            map: &std::collections::BTreeMap<String, Vec<String>>,
                                            parent: &str,
                                            feature: &str,
                                        ) -> bool {
                                            if let Some(parent) = map.get(parent) {
                                                parent.iter().any(|f| {
                                                    let pf =
                                                        krates::ParsedFeature::from(f.as_str());

                                                    if let krates::Feature::Simple(feat) = pf.feat()
                                                    {
                                                        if feat == feature {
                                                            true
                                                        } else {
                                                            has_feature(map, feat, feature)
                                                        }
                                                    } else {
                                                        false
                                                    }
                                                })
                                            } else {
                                                false
                                            }
                                        }

                                        if !feature_bans.allow.value.iter().any(|allowed| {
                                            has_feature(
                                                &krate.features,
                                                allowed.value.as_str(),
                                                feature,
                                            )
                                        }) {
                                            pack.push(diags::FeatureNotExplicitlyAllowed {
                                                krate,
                                                feature,
                                                allowed: CfgCoord {
                                                    file: file_id,
                                                    span: feature_bans.allow.span.clone(),
                                                },
                                            });
                                        }
                                    }
                                }

                                // If the default feature has been denied at a global
                                // level but not at the crate level, emit an error with
                                // the global span, otherwise the crate level setting,
                                // if the default feature was banned explicitly, takes
                                // precedence
                                if let Some(ll) = default_lint_level {
                                    if ll.value == LintLevel::Deny
                                        && !feature_bans
                                            .allow
                                            .value
                                            .iter()
                                            .any(|d| d.value == "default")
                                        && !feature_bans.deny.iter().any(|d| d.value == "default")
                                    {
                                        pack.push(diags::DefaultFeatureEnabled {
                                            krate,
                                            level: ll,
                                            file_id,
                                        });
                                    }
                                }

                                for feature in feature_bans
                                    .deny
                                    .iter()
                                    .filter(|feat| enabled_features.contains(&feat.value))
                                {
                                    pack.push(diags::FeatureBanned {
                                        krate,
                                        feature,
                                        file_id,
                                    });
                                }

                                diag_count <= pack.len()
                            }
                        };

                        // If the crate isn't actually banned, but does reference
                        // features that don't exist, emit warnings about them so
                        // the user can cleanup their config. We _could_ emit these
                        // warnings if the crate is banned, but feature graphs in
                        // particular can be massive and adding warnings into the mix
                        // will just make parsing the error graphs harder
                        if feature_set_allowed {
                            for feature in feature_bans
                                .allow
                                .value
                                .iter()
                                .chain(feature_bans.deny.iter())
                            {
                                if !krate.features.contains_key(&feature.value) {
                                    pack.push(diags::UnknownFeature {
                                        krate,
                                        feature,
                                        file_id,
                                    });
                                }
                            }
                        }
                    }
                } else if let Some(ll) = default_lint_level {
                    if ll.value == LintLevel::Deny {
                        pack.push(diags::DefaultFeatureEnabled {
                            krate,
                            level: ll,
                            file_id,
                        });
                    }
                }

                if let Some(matches) = matches(&skipped, krate) {
                    for rm in matches {
                        pack.push(diags::Skipped {
                            krate,
                            skip_cfg: CfgCoord {
                                file: file_id,
                                span: rm.id.span.clone(),
                            },
                        });

                        // Mark each skip filter that is hit so that we can report unused
                        // filters to the user so that they can cleanup their configs as
                        // their dependency graph changes over time
                        skip_hit.as_mut_bitslice().set(rm.index, true);
                    }
                } else if !tree_skipper.matches(krate, &mut pack) {
                    if multi_detector.name != krate.name {
                        report_duplicates(&multi_detector, &mut real_sink);

                        multi_detector.name = &krate.name;
                        multi_detector.dupes.clear();
                    }

                    multi_detector.dupes.push(i);

                    if wildcards != LintLevel::Allow && !krate.is_git_source() {
                        let severity = match wildcards {
                            LintLevel::Warn => Severity::Warning,
                            LintLevel::Deny => Severity::Error,
                            LintLevel::Allow => unreachable!(),
                        };

                        let mut wildcards: Vec<_> = krate
                            .deps
                            .iter()
                            .filter(|dep| dep.req == VersionReq::STAR)
                            .collect();

                        if allow_wildcard_paths {
                            let is_private = krate.is_private(&[]);

                            wildcards.retain(|dep| {
                                if is_private {
                                    dep.path.is_none()
                                } else {
                                    let is_path_dev_dependency = dep.path.is_some()
                                        && dep.kind != DependencyKind::Development;
                                    is_path_dev_dependency || dep.path.is_none()
                                }
                            });
                        }

                        if !wildcards.is_empty() {
                            real_sink.push(diags::Wildcards {
                                krate,
                                severity,
                                wildcards,
                                allow_wildcard_paths,
                                cargo_spans: &cargo_spans,
                            });
                        }
                    }
                }

                tx.push(krate, pack);
            }
        },
        || {
            let Some((build_config, rx, sink)) = rx else { return; };
            rayon::scope(|s| {
                while let Ok((krate, mut pack)) = rx.recv() {
                    let mut sink = sink.clone();
                    let bc = &build_config;
                    s.spawn(move |_s| {
                        check_build(bc, krate, ctx.krates, &mut pack);

                        if !pack.is_empty() {
                            sink.push(pack);
                        }
                    });
                }
            });
        },
    );

    let mut sink = real_sink;
    report_duplicates(&multi_detector, &mut sink);

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
            skipped_krate: &skip.value,
        });
    }

    sink.push(pack);
}

pub fn check_build(config: &ValidBuildConfig, krate: &Krate, krates: &Krates, pack: &mut Pack) {
    if let Some(allow_build_scripts) = &config.allow_build_scripts {
        let has_build_script = krate
            .targets
            .iter()
            .any(|t| t.kind.iter().any(|k| *k == "custom-build"));

        if has_build_script {
            let allowed_build_script = allow_build_scripts.value.iter().any(|id| {
                krate.name == id.name && crate::match_req(&krate.version, id.version.as_ref())
            });

            if !allowed_build_script {
                pack.push(diags::BuildScriptNotAllowed { krate });
            }
        }
    }

    if config.executables == LintLevel::Allow {
        return;
    }

    fn needs_checking(krate: krates::NodeId, krates: &Krates) -> bool {
        if krates[krate].targets.iter().any(|t| {
            t.kind
                .iter()
                .any(|k| *k == "custom-build" || *k == "proc-macro")
        }) {
            return true;
        }

        for dd in krates.direct_dependents(krate) {
            if needs_checking(dd.node_id, krates) {
                return true;
            }
        }

        false
    }

    // Check if the krate is either a proc-macro, has a build-script, OR is a dependency
    // of a crate that is/does
    if !needs_checking(krates.nid_for_kid(&krate.id).unwrap(), krates) {
        return;
    }

    let krate_config = config.allow_executables.as_ref().and_then(|ae| {
        ae.iter().find_map(|ae| {
            (ae.name.value == krate.name && crate::match_req(&krate.version, ae.version.as_ref()))
                .then_some(ae)
        })
    });

    let parent = krate.manifest_path.parent().unwrap();

    for entry in walkdir::WalkDir::new(parent) {
        let Ok(entry) = entry else { continue; };

        let path = match crate::PathBuf::from_path_buf(entry.into_path()) {
            Ok(p) => p,
            Err(path) => {
                pack.push(
                    crate::diag::Diagnostic::warning()
                        .with_message(format!("path {path:?} is not utf-8, skipping")),
                );
                continue;
            }
        };

        let Ok(rel_path) = path.strip_prefix(parent) else {
            pack.push(
                crate::diag::Diagnostic::error()
                    .with_message(format!("path '{path}' is not relative to crate root '{parent}'")),
            );
            continue;
        };

        // First just check if the file has been explicitly allowed without a
        // checksum so we don't even need to bother checking it
    }
}
