use std::fmt;

use crate::{
    Krate, Spanned,
    bans::{SpecAndReason, cfg},
    diag::{
        CfgCoord, Check, Diag, Diagnostic, FileId, GraphNode, KrateCoord, Label, Pack, Severity,
    },
};

#[derive(
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Code {
    Banned,
    Allowed,
    NotAllowed,
    Duplicate,
    Skipped,
    Wildcard,
    UnmatchedSkip,
    UnnecessarySkip,
    AllowedByWrapper,
    UnmatchedWrapper,
    SkippedByRoot,
    UnmatchedSkipRoot,
    BuildScriptNotAllowed,
    ExactFeaturesMismatch,
    FeatureNotExplicitlyAllowed,
    FeatureBanned,
    UnknownFeature,
    DefaultFeatureEnabled,
    PathBypassed,
    PathBypassedByGlob,
    ChecksumMatch,
    ChecksumMismatch,
    DeniedByExtension,
    DetectedExecutable,
    DetectedExecutableScript,
    UnableToCheckPath,
    FeaturesEnabled,
    UnmatchedBypass,
    UnmatchedPathBypass,
    UnmatchedGlob,
    UnusedWrapper,
    WorkspaceDuplicate,
    UnresolvedWorkspaceDependency,
    UnusedWorkspaceDependency,
    NonUtf8Path,
    NonRootPath,
}

impl Code {
    #[inline]
    pub fn description(self) -> &'static str {
        match self {
            Self::Banned => "Detected an explicitly banned crate",
            Self::Allowed => "Detected an explicitly allowed crate",
            Self::NotAllowed => "Detected a crate not explicitly allowed",
            Self::Duplicate => "Detected two or more versions of the same crate",
            Self::Skipped => "A crate version was skipped when checking for multiple versions",
            Self::Wildcard => "A dependency was declared with a wildcard version",
            Self::UnmatchedSkip => "A skip entry didn't match any crates in the graph",
            Self::UnnecessarySkip => "A skip entry applied to a crate that only had one version",
            Self::AllowedByWrapper => "A banned crate was allowed by a wrapper crate",
            Self::UnmatchedWrapper => {
                "A wrapper was declared for a crate that was not a direct parent"
            }
            Self::SkippedByRoot => {
                "A crate version was skipped by a tree skip when checking for multiple versions"
            }
            Self::UnmatchedSkipRoot => "A tree skip didn't match any crates in the graph",
            Self::BuildScriptNotAllowed => {
                "A crate has code that executes at build time but was not allowed to"
            }
            Self::ExactFeaturesMismatch => {
                "The feature set of a crate did not exactly match the features configured for it"
            }
            Self::FeatureNotExplicitlyAllowed => "A feature for a crate was not explicitly allowed",
            Self::FeatureBanned => "An explicitly banned feature for a crate was set",
            Self::UnknownFeature => {
                "Attempted to allow or ban a feature for a crate which doesn't exist"
            }
            Self::DefaultFeatureEnabled => "Default features were enabled for a crate",
            Self::PathBypassed => {
                "A path was explicitly allowed when checking build time execution"
            }
            Self::PathBypassedByGlob => {
                "A path was explicitly allowed by a glob when checking build time execution"
            }
            Self::ChecksumMatch => "A path bypass checksum matched",
            Self::ChecksumMismatch => "A path bypass checksum did not match the file on disk",
            Self::DeniedByExtension => {
                "A file in a crate executed at build time was denied due to its extension"
            }
            Self::DetectedExecutable => {
                "An executable was detected in a crate which executes at build time"
            }
            Self::DetectedExecutableScript => {
                "An executable script was detected in a crate which executes at build time"
            }
            Self::UnableToCheckPath => "A failure occurred trying to inspect a file on disk",
            Self::FeaturesEnabled => {
                "Features which enable code during build time execution were enabled"
            }
            Self::UnmatchedBypass => {
                "A bypass was declared for a crate which does not execute at build time"
            }
            Self::UnmatchedPathBypass => "A path bypass did not match a path in a crate's source",
            Self::UnmatchedGlob => "A glob bypass did not match any paths in a crate's source",
            Self::UnusedWrapper => "A wrapper was declared for a crate not in the graph",
            Self::WorkspaceDuplicate => {
                "A workspace directly depended on more than one version of the same crate"
            }
            Self::UnresolvedWorkspaceDependency => "Failed to resolve a workspace dependency",
            Self::UnusedWorkspaceDependency => "A workspace dependency was declared but never used",
            Self::NonUtf8Path => {
                "A non-utf8 path was detected in a crate that executes at build time"
            }
            Self::NonRootPath => "A path was not rooted in the crate source",
        }
    }
}

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
}

#[inline]
fn dcode(code: Code) -> Option<crate::diag::DiagnosticCode> {
    Some(crate::diag::DiagnosticCode::Bans(code))
}

#[inline]
fn diag(diag: Diagnostic, code: Code) -> Diag {
    Diag::new(diag, dcode(code))
}

impl SpecAndReason {
    pub(crate) fn to_labels(&self, spec_msg: Option<&str>) -> Vec<Label> {
        let mut v = Vec::new();

        {
            let l = Label::primary(self.file_id, self.spec.name.span);
            if let Some(sm) = spec_msg {
                v.push(l.with_message(sm));
            } else {
                v.push(l);
            }
        }

        if let Some(reason) = &self.reason {
            v.push(Label::secondary(self.file_id, reason.0.span).with_message("reason"));
        }

        if let Some(ui) = &self.use_instead {
            v.push(Label::secondary(self.file_id, ui.span).with_message("use instead"));
        }

        v
    }
}

pub(crate) struct ExplicitlyBanned<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) ban_cfg: &'a SpecAndReason,
}

impl<'a> From<ExplicitlyBanned<'a>> for Diag {
    fn from(eb: ExplicitlyBanned<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Error)
                .with_message(format_args!("crate '{}' is explicitly banned", eb.krate))
                .with_labels(eb.ban_cfg.to_labels(Some("banned here"))),
            Code::Banned,
        )
    }
}

pub(crate) struct ExplicitlyAllowed<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) allow_cfg: &'a SpecAndReason,
}

impl<'a> From<ExplicitlyAllowed<'a>> for Diag {
    fn from(ea: ExplicitlyAllowed<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note)
                .with_message(format_args!("crate '{}' is explicitly allowed", ea.krate))
                .with_labels(ea.allow_cfg.to_labels(Some("allowed here"))),
            Code::Allowed,
        )
    }
}

pub(crate) struct NotAllowed<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<NotAllowed<'a>> for Diag {
    fn from(ib: NotAllowed<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Error).with_message(format_args!(
                "crate '{}' is not explicitly allowed",
                ib.krate
            )),
            Code::NotAllowed,
        )
    }
}

pub(crate) struct Duplicates<'a> {
    pub(crate) krate_name: &'a str,
    pub(crate) num_dupes: usize,
    pub(crate) krates_coord: KrateCoord,
    pub(crate) severity: Severity,
}

impl<'a> From<Duplicates<'a>> for Diag {
    fn from(dup: Duplicates<'a>) -> Self {
        diag(
            Diagnostic::new(dup.severity)
                .with_message(format_args!(
                    "found {} duplicate entries for crate '{}'",
                    dup.num_dupes, dup.krate_name,
                ))
                .with_labels(vec![
                    dup.krates_coord.into_label().with_message("lock entries"),
                ]),
            Code::Duplicate,
        )
    }
}

pub(crate) struct Skipped<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) skip_cfg: &'a SpecAndReason,
}

impl<'a> From<Skipped<'a>> for Diag {
    fn from(sk: Skipped<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note)
                .with_message(format_args!(
                    "crate '{}' skipped when checking for duplicates",
                    sk.krate
                ))
                .with_labels(sk.skip_cfg.to_labels(Some("skipped here"))),
            Code::Skipped,
        )
    }
}

pub(crate) struct Wildcards<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) severity: Severity,
    pub(crate) labels: Vec<Label>,
    pub(crate) allow_wildcard_paths: bool,
}

impl<'a> From<Wildcards<'a>> for Pack {
    fn from(wc: Wildcards<'a>) -> Self {
        let labels = wc.labels;
        let diag = diag(
            Diagnostic::new(wc.severity)
                .with_message(format_args!(
                    "found {} wildcard dependenc{} for crate '{}'{}",
                    labels.len(),
                    if labels.len() == 1 { "y" } else { "ies" },
                    wc.krate.name,
                    if wc.allow_wildcard_paths {
                        ". allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies."
                    } else {
                        ""
                    },
                ))
                .with_labels(labels),
                Code::Wildcard
        );

        let mut pack = Pack::with_kid(Check::Bans, wc.krate.id.clone());
        pack.push(diag);

        pack
    }
}

pub(crate) struct UnmatchedSkip<'a> {
    pub(crate) skip_cfg: &'a SpecAndReason,
}

impl<'a> From<UnmatchedSkip<'a>> for Diag {
    fn from(us: UnmatchedSkip<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message(format_args!(
                    "skipped crate '{}' was not encountered",
                    us.skip_cfg.spec,
                ))
                .with_labels(us.skip_cfg.to_labels(Some("unmatched skip configuration"))),
            Code::UnmatchedSkip,
        )
    }
}

pub(crate) struct UnnecessarySkip<'a> {
    pub(crate) skip_cfg: &'a SpecAndReason,
}

impl<'a> From<UnnecessarySkip<'a>> for Diag {
    fn from(us: UnnecessarySkip<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message(format_args!(
                    "skip '{}' applied to a crate with only one version",
                    us.skip_cfg.spec,
                ))
                .with_labels(
                    us.skip_cfg
                        .to_labels(Some("unnecessary skip configuration")),
                ),
            Code::UnnecessarySkip,
        )
    }
}

pub(crate) struct UnusedWrapper {
    pub(crate) wrapper_cfg: CfgCoord,
}

impl From<UnusedWrapper> for Diag {
    fn from(us: UnusedWrapper) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("wrapper for banned crate was not encountered")
                .with_labels(vec![
                    us.wrapper_cfg
                        .into_label()
                        .with_message("unmatched wrapper"),
                ]),
            Code::UnusedWrapper,
        )
    }
}

pub(crate) struct BannedAllowedByWrapper<'a> {
    pub(crate) ban_cfg: CfgCoord,
    pub(crate) banned_krate: &'a Krate,
    pub(crate) ban_exception_cfg: CfgCoord,
    pub(crate) wrapper_krate: &'a Krate,
}

impl<'a> From<BannedAllowedByWrapper<'a>> for Diag {
    fn from(baw: BannedAllowedByWrapper<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note)
                .with_message(format_args!(
                    "banned crate '{}' allowed by wrapper '{}'",
                    baw.banned_krate, baw.wrapper_krate
                ))
                .with_labels(vec![
                    baw.ban_cfg.into_label().with_message("banned here"),
                    baw.ban_exception_cfg
                        .into_label()
                        .with_message("allowed wrapper"),
                ]),
            Code::AllowedByWrapper,
        )
    }
}

pub(crate) struct BannedUnmatchedWrapper<'a> {
    pub(crate) ban_cfg: &'a SpecAndReason,
    pub(crate) banned_krate: &'a Krate,
    pub(crate) parent_krate: &'a Krate,
}

impl<'a> From<BannedUnmatchedWrapper<'a>> for Diag {
    fn from(buw: BannedUnmatchedWrapper<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message(format_args!(
                    "direct parent '{}' of banned crate '{}' was not marked as a wrapper",
                    buw.parent_krate, buw.banned_krate
                ))
                .with_labels(buw.ban_cfg.to_labels(Some("banned here"))),
            Code::UnmatchedWrapper,
        )
    }
}

pub(crate) struct SkippedByRoot<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) skip_root_cfg: &'a SpecAndReason,
}

impl<'a> From<SkippedByRoot<'a>> for Diag {
    fn from(sbr: SkippedByRoot<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note)
                .with_message(format_args!(
                    "skipping crate '{}' due to root skip",
                    sbr.krate
                ))
                .with_labels(sbr.skip_root_cfg.to_labels(Some("matched skip root"))),
            Code::SkippedByRoot,
        )
    }
}

pub(crate) struct UnmatchedSkipRoot {
    pub(crate) skip_root_cfg: CfgCoord,
}

impl From<UnmatchedSkipRoot> for Diag {
    fn from(usr: UnmatchedSkipRoot) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("skip tree root was not found in the dependency graph")
                .with_labels(vec![
                    usr.skip_root_cfg
                        .into_label()
                        .with_message("no crate matched these criteria"),
                ]),
            Code::UnmatchedSkipRoot,
        )
    }
}

pub(crate) struct BuildScriptNotAllowed<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<BuildScriptNotAllowed<'a>> for Diag {
    fn from(bs: BuildScriptNotAllowed<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Error).with_message(format_args!(
                "crate '{}' has a build script but is not allowed to have one",
                bs.krate
            )),
            Code::BuildScriptNotAllowed,
        )
    }
}

pub(crate) struct ExactFeaturesMismatch<'a> {
    pub(crate) missing_allowed: Vec<CfgCoord>,
    pub(crate) not_allowed: &'a [&'a str],
    pub(crate) exact_coord: CfgCoord,
    pub(crate) krate: &'a Krate,
}

impl From<ExactFeaturesMismatch<'_>> for Diag {
    fn from(efm: ExactFeaturesMismatch<'_>) -> Self {
        let mut labels = vec![
            efm.exact_coord
                .into_label()
                .with_message("exact enabled here"),
        ];

        labels.extend(
            efm.missing_allowed
                .into_iter()
                .map(|ma| ma.into_label().with_message("allowed feature not present")),
        );

        let diag = Diagnostic::new(Severity::Error)
            .with_message(format_args!(
                "feature set for crate '{}' did not match exactly",
                efm.krate
            ))
            .with_code(Code::ExactFeaturesMismatch)
            .with_labels(labels)
            .with_notes(
                efm.not_allowed
                    .iter()
                    .map(|na| format!("'{na}' feature was enabled but not explicitly allowed"))
                    .collect(),
            );

        let graph_nodes = if efm.not_allowed.is_empty() {
            vec![GraphNode {
                kid: efm.krate.id.clone(),
                feature: None,
            }]
        } else {
            efm.not_allowed
                .iter()
                .map(|feat| GraphNode {
                    kid: efm.krate.id.clone(),
                    feature: Some((*feat).to_owned()),
                })
                .collect()
        };

        Diag {
            diag,
            code: dcode(Code::ExactFeaturesMismatch),
            graph_nodes: graph_nodes.into(),
            extra: None,
            with_features: true,
        }
    }
}

pub(crate) struct FeatureNotExplicitlyAllowed<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) feature: &'a str,
    pub(crate) allowed: CfgCoord,
}

impl From<FeatureNotExplicitlyAllowed<'_>> for Diag {
    fn from(fna: FeatureNotExplicitlyAllowed<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Error)
            .with_message(format_args!(
                "feature '{}' for crate '{}' was not explicitly allowed",
                fna.feature, fna.krate,
            ))
            .with_code(Code::FeatureNotExplicitlyAllowed)
            .with_labels(vec![
                fna.allowed.into_label().with_message("allowed features"),
            ]);

        Diag {
            diag,
            code: dcode(Code::FeatureNotExplicitlyAllowed),
            graph_nodes: std::iter::once(GraphNode {
                kid: fna.krate.id.clone(),
                feature: None,
            })
            .collect(),
            extra: None,
            with_features: true,
        }
    }
}

pub(crate) struct FeatureBanned<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) feature: &'a Spanned<String>,
    pub(crate) file_id: FileId,
}

impl From<FeatureBanned<'_>> for Diag {
    fn from(fed: FeatureBanned<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Error)
            .with_message(format_args!(
                "feature '{}' for crate '{}' is explicitly denied",
                fed.feature.value, fed.krate,
            ))
            .with_code(Code::FeatureBanned)
            .with_labels(vec![
                Label::primary(fed.file_id, fed.feature.span).with_message("feature denied here"),
            ]);

        Diag {
            diag,
            code: dcode(Code::FeatureBanned),
            graph_nodes: std::iter::once(GraphNode {
                kid: fed.krate.id.clone(),
                feature: Some(fed.feature.value.clone()),
            })
            .collect(),
            extra: None,
            with_features: true,
        }
    }
}

pub(crate) struct UnknownFeature<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) feature: &'a Spanned<String>,
    pub(crate) file_id: FileId,
}

impl From<UnknownFeature<'_>> for Diag {
    fn from(uf: UnknownFeature<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Warning)
            .with_message(format_args!(
                "found unknown feature '{}' for crate '{}'",
                uf.feature.value, uf.krate,
            ))
            .with_code(Code::UnknownFeature)
            .with_labels(vec![
                Label::primary(uf.file_id, uf.feature.span).with_message("unknown feature"),
            ]);

        Diag {
            diag,
            code: dcode(Code::UnknownFeature),
            graph_nodes: std::iter::once(GraphNode {
                kid: uf.krate.id.clone(),
                feature: None,
            })
            .collect(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct DefaultFeatureEnabled<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) level: &'a Spanned<crate::LintLevel>,
    pub(crate) file_id: FileId,
}

impl From<DefaultFeatureEnabled<'_>> for Diag {
    fn from(dfe: DefaultFeatureEnabled<'_>) -> Diag {
        let diag = Diagnostic::new(dfe.level.value.into())
            .with_message(format_args!(
                "'default' feature enabled for crate '{}'",
                dfe.krate,
            ))
            .with_code(Code::DefaultFeatureEnabled)
            .with_labels(vec![
                Label::primary(dfe.file_id, dfe.level.span).with_message("lint level"),
            ]);

        Diag {
            diag,
            code: dcode(Code::DefaultFeatureEnabled),
            graph_nodes: std::iter::once(GraphNode {
                kid: dfe.krate.id.clone(),
                feature: Some("default".to_owned()),
            })
            .collect(),
            extra: None,
            with_features: true,
        }
    }
}

pub(crate) struct HomePath<'a> {
    pub(crate) path: &'a crate::Path,
    pub(crate) root: &'a crate::Path,
    pub(crate) home: Option<&'a crate::Path>,
}

impl fmt::Display for HomePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(rel_path) = self.home.and_then(|home| self.path.strip_prefix(home).ok()) {
            f.write_str("$CARGO_HOME/")?;
            f.write_str(rel_path.as_str())
        } else if let Ok(rel_path) = self.path.strip_prefix(self.root) {
            f.write_str("$crate/")?;
            f.write_str(rel_path.as_str())
        } else {
            f.write_str(self.path.as_str())
        }
    }
}

pub(crate) struct ExplicitPathAllowance<'a> {
    pub(crate) allowed: &'a cfg::BypassPath,
    pub(crate) file_id: FileId,
}

impl From<ExplicitPathAllowance<'_>> for Diag {
    fn from(pa: ExplicitPathAllowance<'_>) -> Diag {
        let mut labels =
            vec![Label::primary(pa.file_id, pa.allowed.path.span).with_message("allowed path")];

        labels.extend(
            pa.allowed
                .checksum
                .as_ref()
                .map(|chk| Label::secondary(pa.file_id, chk.span).with_message("matched checksum")),
        );
        let diag = Diagnostic::new(Severity::Help)
            .with_message("file explicitly allowed")
            .with_code(Code::PathBypassed)
            .with_labels(labels);

        Diag {
            diag,
            code: dcode(Code::PathBypassed),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

#[inline]
fn globs_to_labels(file_id: FileId, globs: Vec<&cfg::GlobPattern>) -> Vec<Label> {
    globs
        .into_iter()
        .map(|gp| match gp {
            cfg::GlobPattern::Builtin((glob, id)) => {
                Label::secondary(*id, glob.span).with_message("builtin")
            }
            cfg::GlobPattern::User(glob) => Label::secondary(file_id, glob.span),
        })
        .collect()
}

pub(crate) struct GlobAllowance<'a> {
    pub(crate) path: HomePath<'a>,
    pub(crate) globs: Vec<&'a cfg::GlobPattern>,
    pub(crate) file_id: FileId,
}

impl From<GlobAllowance<'_>> for Diag {
    fn from(pa: GlobAllowance<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Help)
            .with_message("file allowed by glob")
            .with_notes(vec![format!("path = '{}'", pa.path)])
            .with_code(Code::PathBypassedByGlob)
            .with_labels(globs_to_labels(pa.file_id, pa.globs));

        Diag {
            diag,
            code: dcode(Code::PathBypassedByGlob),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct ChecksumMatch<'a> {
    pub(crate) path: HomePath<'a>,
    pub(crate) checksum: &'a Spanned<super::cfg::Checksum>,
    pub(crate) severity: Option<Severity>,
    pub(crate) file_id: FileId,
}

impl From<ChecksumMatch<'_>> for Diag {
    fn from(cm: ChecksumMatch<'_>) -> Diag {
        let diag = Diagnostic::new(cm.severity.unwrap_or(Severity::Help))
            .with_message("file checksum matched")
            .with_notes(vec![format!("path = '{}'", cm.path)])
            .with_code(Code::ChecksumMatch)
            .with_labels(vec![
                Label::primary(cm.file_id, cm.checksum.span).with_message("checksum"),
            ]);

        Diag {
            diag,
            code: dcode(Code::ChecksumMatch),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct ChecksumMismatch<'a> {
    pub(crate) path: HomePath<'a>,
    pub(crate) checksum: &'a Spanned<super::cfg::Checksum>,
    pub(crate) severity: Option<Severity>,
    pub(crate) error: String,
    pub(crate) file_id: FileId,
}

impl From<ChecksumMismatch<'_>> for Diag {
    fn from(cm: ChecksumMismatch<'_>) -> Diag {
        let mut notes = vec![format!("path = '{}'", cm.path)];
        notes.extend(
            format!("error = {:#}", cm.error)
                .lines()
                .map(|l| l.to_owned()),
        );

        let diag = Diagnostic::new(cm.severity.unwrap_or(Severity::Error))
            .with_message("file did not match the expected checksum")
            .with_notes(notes)
            .with_code(Code::ChecksumMismatch)
            .with_labels(vec![
                Label::primary(cm.file_id, cm.checksum.span).with_message("expected checksum"),
            ]);

        Diag {
            diag,
            code: dcode(Code::ChecksumMismatch),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct DeniedByExtension<'a> {
    pub(crate) path: HomePath<'a>,
    pub(crate) globs: Vec<&'a cfg::GlobPattern>,
    pub(crate) file_id: FileId,
}

impl From<DeniedByExtension<'_>> for Diag {
    fn from(de: DeniedByExtension<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Error)
            .with_message("path disallowed by extension")
            .with_notes(vec![format!("path = '{}'", de.path)])
            .with_code(Code::DeniedByExtension)
            .with_labels(globs_to_labels(de.file_id, de.globs));

        Diag {
            diag,
            code: dcode(Code::DeniedByExtension),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct DetectedExecutable<'a> {
    pub(crate) path: HomePath<'a>,
    pub(crate) interpreted: crate::LintLevel,
    pub(crate) exe_kind: super::ExecutableKind,
}

impl From<DetectedExecutable<'_>> for Diag {
    fn from(de: DetectedExecutable<'_>) -> Diag {
        let (code, exe_note, severity) = match de.exe_kind {
            super::ExecutableKind::Native(hint) => {
                let native_kind = match hint {
                    goblin::Hint::Elf(_) => "elf",
                    goblin::Hint::PE => "pe",
                    goblin::Hint::Mach(_) | goblin::Hint::MachFat(_) => "mach",
                    goblin::Hint::Archive => "archive",
                    _ => unreachable!("unhandled format {hint:#?} for {}", de.path),
                };

                (
                    Code::DetectedExecutable,
                    format!("executable-kind = '{native_kind}'"),
                    Severity::Error,
                )
            }
            super::ExecutableKind::Interpreted(interpreter) => (
                Code::DetectedExecutableScript,
                format!("interpreter = '{interpreter}'"),
                de.interpreted.into(),
            ),
        };

        let diag = Diagnostic::new(severity)
            .with_message("detected executable")
            .with_notes(vec![format!("path = '{}'", de.path), exe_note])
            .with_code(code);

        Diag {
            diag,
            code: dcode(code),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct UnableToCheckPath<'a> {
    pub(crate) path: HomePath<'a>,
    pub(crate) error: anyhow::Error,
}

impl From<UnableToCheckPath<'_>> for Diag {
    fn from(ucp: UnableToCheckPath<'_>) -> Diag {
        let mut notes = vec![format!("path = {}", ucp.path)];

        notes.extend(
            format!("error = {:#}", ucp.error)
                .lines()
                .map(|l| l.to_owned()),
        );
        let diag = Diagnostic::new(Severity::Error)
            .with_message("unable to check if path is an executable")
            .with_notes(notes)
            .with_code(Code::UnableToCheckPath);

        Diag {
            diag,
            code: dcode(Code::UnableToCheckPath),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct FeaturesEnabled<'a> {
    pub(crate) enabled_features: Vec<&'a Spanned<String>>,
    pub(crate) file_id: FileId,
}

impl From<FeaturesEnabled<'_>> for Diag {
    fn from(fe: FeaturesEnabled<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Note)
            .with_message(format_args!(
                "{} features enabled for crate with build script, checking sources",
                fe.enabled_features.len()
            ))
            .with_code(Code::FeaturesEnabled)
            .with_labels(
                fe.enabled_features
                    .into_iter()
                    .map(|ef| Label::secondary(fe.file_id, ef.span))
                    .collect(),
            );

        Diag {
            diag,
            code: dcode(Code::FeaturesEnabled),
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct UnmatchedBypass<'a> {
    pub(crate) unmatched: &'a super::cfg::ValidBypass,
    pub(crate) file_id: FileId,
}

impl<'a> From<UnmatchedBypass<'a>> for Diag {
    fn from(ubc: UnmatchedBypass<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("crate build bypass was not encountered")
                .with_labels(vec![
                    Label::primary(ubc.file_id, ubc.unmatched.spec.name.span)
                        .with_message("unmatched bypass"),
                ]),
            Code::UnmatchedBypass,
        )
    }
}

pub(crate) struct UnmatchedPathBypass<'a> {
    pub(crate) unmatched: &'a super::cfg::BypassPath,
    pub(crate) file_id: FileId,
}

impl<'a> From<UnmatchedPathBypass<'a>> for Diag {
    fn from(ua: UnmatchedPathBypass<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("allowed path was not encountered")
                .with_labels(vec![Label::primary(ua.file_id, ua.unmatched.path.span)]),
            Code::UnmatchedPathBypass,
        )
    }
}

pub(crate) struct UnmatchedGlob<'a> {
    pub(crate) unmatched: &'a Spanned<String>,
    pub(crate) file_id: FileId,
}

impl<'a> From<UnmatchedGlob<'a>> for Diag {
    fn from(ug: UnmatchedGlob<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("glob was not encountered")
                .with_labels(vec![Label::primary(ug.file_id, ug.unmatched.span)]),
            Code::UnmatchedGlob,
        )
    }
}

pub(crate) struct WorkspaceDuplicate<'k> {
    pub(crate) duplicate: &'k Krate,
    pub(crate) labels: Vec<Label>,
    pub(crate) severity: crate::LintLevel,
    pub(crate) has_workspace_declaration: bool,
    pub(crate) total_uses: usize,
}

impl<'k> From<WorkspaceDuplicate<'k>> for Diag {
    fn from(wd: WorkspaceDuplicate<'k>) -> Self {
        diag(
            Diagnostic::new(wd.severity.into())
                .with_message(format_args!(
                    "crate {} is used {} times in the workspace, {}",
                    wd.duplicate,
                    wd.total_uses,
                    if wd.has_workspace_declaration {
                        "but not all declarations use the shared workspace dependency"
                    } else {
                        "and there is no shared workspace dependency for it"
                    }
                ))
                .with_labels(wd.labels),
            Code::WorkspaceDuplicate,
        )
    }
}

pub(crate) struct UnresolveWorkspaceDependency<'m, 'k> {
    pub(crate) manifest: &'m crate::diag::Manifest<'k>,
    pub(crate) dep: &'m crate::diag::ManifestDep<'k>,
}

#[allow(clippy::fallible_impl_from)]
impl<'m, 'k> From<UnresolveWorkspaceDependency<'m, 'k>> for Diag {
    fn from(uwd: UnresolveWorkspaceDependency<'m, 'k>) -> Self {
        diag(
            Diagnostic::bug()
                .with_message("failed to resolve a workspace dependency")
                .with_labels(vec![
                    Label::primary(
                        uwd.manifest.id,
                        uwd.dep.workspace.as_ref().map(|ws| ws.span).unwrap(),
                    )
                    .with_message("usage of workspace dependency"),
                    Label::secondary(uwd.manifest.id, uwd.dep.value_span),
                ]),
            Code::UnresolvedWorkspaceDependency,
        )
    }
}

pub(crate) struct UnusedWorkspaceDependencies<'u> {
    pub(crate) unused: &'u [crate::diag::UnusedWorkspaceDep],
    pub(crate) level: crate::LintLevel,
    pub(crate) id: FileId,
}

impl<'u> From<UnusedWorkspaceDependencies<'u>> for Pack {
    fn from(uwd: UnusedWorkspaceDependencies<'u>) -> Self {
        let mut pack = Pack::new(Check::Bans);

        for unused in uwd.unused {
            let mut labels = vec![
                Label::primary(uwd.id, unused.key).with_message(format_args!(
                    "unused {}workspace dependency",
                    if unused.patched.is_some() {
                        "and patched "
                    } else {
                        ""
                    }
                )),
            ];

            if let Some(patched) = unused.patched {
                labels.push(
                    Label::secondary(uwd.id, patched)
                        .with_message("note this is the original dependency that is patched"),
                );
            }

            if let Some(rename) = &unused.rename {
                labels.push(
                    Label::secondary(uwd.id, rename.span)
                        .with_message("note the dependency is renamed"),
                );
            }

            pack.push(diag(
                Diagnostic::new(uwd.level.into())
                    .with_message("workspace dependency is declared, but unused")
                    .with_labels(labels),
                Code::UnusedWorkspaceDependency,
            ));
        }

        pack
    }
}

pub(crate) struct NonUtf8Path<'p> {
    pub(crate) path: &'p std::path::Path,
}

impl<'p> From<NonUtf8Path<'p>> for Diag {
    fn from(value: NonUtf8Path<'p>) -> Self {
        diag(
            Diagnostic::warning()
                .with_message(format_args!("path {:?} is not utf-8, skipping", value.path)),
            Code::NonUtf8Path,
        )
    }
}

pub(crate) struct NonRootPath<'p> {
    pub(crate) path: &'p crate::Path,
    pub(crate) root: &'p crate::Path,
}

impl<'p> From<NonRootPath<'p>> for Diag {
    fn from(value: NonRootPath<'p>) -> Self {
        diag(
            Diagnostic::error().with_message(format_args!(
                "path '{}' is not relative to crate root '{}'",
                value.path, value.root
            )),
            Code::NonRootPath,
        )
    }
}
