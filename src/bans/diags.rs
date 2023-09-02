use crate::{
    bans::{cfg, KrateId},
    diag::{
        CfgCoord, Check, Diag, Diagnostic, FileId, GraphNode, KrateCoord, Label, Pack, Severity,
    },
    Krate, Spanned,
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
    PathAllowed,
    PathAllowedByGlob,
    ChecksumMatch,
    ChecksumMismatch,
    DisallowedByExtension,
    DetectedExecutable,
    DetectedExecutableScript,
    UnableToCheckPath,
    FeaturesEnabled,
    UnmatchedBuildConfig,
}

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
}

pub(crate) struct ExplicitlyBanned<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) ban_cfg: CfgCoord,
}

impl<'a> From<ExplicitlyBanned<'a>> for Diag {
    fn from(eb: ExplicitlyBanned<'a>) -> Self {
        Diagnostic::new(Severity::Error)
            .with_message(format!("crate '{}' is explicitly banned", eb.krate))
            .with_code(Code::Banned)
            .with_labels(vec![eb.ban_cfg.into_label().with_message("banned here")])
            .into()
    }
}

pub(crate) struct ExplicitlyAllowed<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) allow_cfg: CfgCoord,
}

impl<'a> From<ExplicitlyAllowed<'a>> for Diag {
    fn from(ea: ExplicitlyAllowed<'a>) -> Self {
        Diagnostic::new(Severity::Note)
            .with_message(format!("crate '{}' is explicitly allowed", ea.krate))
            .with_code(Code::Allowed)
            .with_labels(vec![ea.allow_cfg.into_label().with_message("allowed here")])
            .into()
    }
}

pub(crate) struct NotAllowed<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<NotAllowed<'a>> for Diag {
    fn from(ib: NotAllowed<'a>) -> Self {
        Diagnostic::new(Severity::Error)
            .with_message(format!("crate '{}' is not explicitly allowed", ib.krate))
            .with_code(Code::NotAllowed)
            .into()
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
        Diagnostic::new(dup.severity)
            .with_message(format!(
                "found {} duplicate entries for crate '{}'",
                dup.num_dupes, dup.krate_name,
            ))
            .with_code(Code::Duplicate)
            .with_labels(vec![dup
                .krates_coord
                .into_label()
                .with_message("lock entries")])
            .into()
    }
}

pub(crate) struct Skipped<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) skip_cfg: CfgCoord,
}

impl<'a> From<Skipped<'a>> for Diag {
    fn from(sk: Skipped<'a>) -> Self {
        Diagnostic::new(Severity::Note)
            .with_message(format!(
                "crate '{}' skipped when checking for duplicates",
                sk.krate
            ))
            .with_code(Code::Skipped)
            .with_labels(vec![sk.skip_cfg.into_label().with_message("skipped here")])
            .into()
    }
}

pub(crate) struct Wildcards<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) severity: Severity,
    pub(crate) wildcards: Vec<&'a krates::cm::Dependency>,
    pub(crate) allow_wildcard_paths: bool,
    pub(crate) cargo_spans: &'a crate::diag::CargoSpans,
}

impl<'a> From<Wildcards<'a>> for Pack {
    fn from(wc: Wildcards<'a>) -> Self {
        let (file_id, map) = &wc.cargo_spans[&wc.krate.id];

        let labels: Vec<_> = wc
            .wildcards
            .into_iter()
            .map(|dep| {
                Label::primary(*file_id, map[&dep.name].clone())
                    .with_message("wildcard crate entry")
            })
            .collect();

        let diag = Diag::new(
            Diagnostic::new(wc.severity)
                .with_message(format!(
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
                .with_code(Code::Wildcard)
                .with_labels(labels),
        );

        let mut pack = Pack::with_kid(Check::Bans, wc.krate.id.clone());
        pack.push(diag);

        pack
    }
}

pub(crate) struct UnmatchedSkip<'a> {
    pub(crate) skip_cfg: CfgCoord,
    pub(crate) skipped_krate: &'a KrateId,
}

impl<'a> From<UnmatchedSkip<'a>> for Diag {
    fn from(us: UnmatchedSkip<'a>) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message(match &us.skipped_krate.version {
                Some(version) => format!(
                    "skipped crate '{} = {}' was not encountered",
                    us.skipped_krate.name, version
                ),
                None => format!(
                    "skipped crate '{}' was not encountered",
                    us.skipped_krate.name
                ),
            })
            .with_code(Code::UnmatchedSkip)
            .with_labels(vec![us
                .skip_cfg
                .into_label()
                .with_message("unmatched skip configuration")])
            .into()
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
        Diagnostic::new(Severity::Note)
            .with_message(format!(
                "banned crate '{}' allowed by wrapper '{}'",
                baw.banned_krate, baw.wrapper_krate
            ))
            .with_code(Code::AllowedByWrapper)
            .with_labels(vec![
                baw.ban_cfg.into_label().with_message("banned here"),
                baw.ban_exception_cfg
                    .into_label()
                    .with_message("allowed wrapper"),
            ])
            .into()
    }
}

pub(crate) struct BannedUnmatchedWrapper<'a> {
    pub(crate) ban_cfg: CfgCoord,
    pub(crate) banned_krate: &'a Krate,
    pub(crate) parent_krate: &'a Krate,
}

impl<'a> From<BannedUnmatchedWrapper<'a>> for Diag {
    fn from(buw: BannedUnmatchedWrapper<'a>) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "direct parent '{}' of banned crate '{}' was not marked as a wrapper",
                buw.parent_krate, buw.banned_krate
            ))
            .with_code(Code::UnmatchedWrapper)
            .with_labels(vec![buw.ban_cfg.into_label().with_message("banned here")])
            .into()
    }
}

pub(crate) struct SkippedByRoot<'a> {
    pub(crate) skip_root_cfg: CfgCoord,
    pub(crate) krate: &'a Krate,
}

impl<'a> From<SkippedByRoot<'a>> for Diag {
    fn from(sbr: SkippedByRoot<'a>) -> Self {
        Diagnostic::new(Severity::Note)
            .with_message(format!("skipping crate '{}' due to root skip", sbr.krate))
            .with_code(Code::SkippedByRoot)
            .with_labels(vec![sbr
                .skip_root_cfg
                .into_label()
                .with_message("matched skip root")])
            .into()
    }
}

pub(crate) struct UnmatchedSkipRoot {
    pub(crate) skip_root_cfg: CfgCoord,
}

impl From<UnmatchedSkipRoot> for Diag {
    fn from(usr: UnmatchedSkipRoot) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message("skip tree root was not found in the dependency graph")
            .with_code(Code::UnmatchedSkipRoot)
            .with_labels(vec![usr
                .skip_root_cfg
                .into_label()
                .with_message("no crate matched these criteria")])
            .into()
    }
}

pub(crate) struct BuildScriptNotAllowed<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<BuildScriptNotAllowed<'a>> for Diag {
    fn from(bs: BuildScriptNotAllowed<'a>) -> Self {
        Diagnostic::new(Severity::Error)
            .with_message(format!(
                "crate '{}' has a build script but is not allowed to have one",
                bs.krate
            ))
            .with_code(Code::BuildScriptNotAllowed)
            .with_notes(vec![
                "the `bans.allow-build-scripts` field did not contain a match for the crate"
                    .to_owned(),
            ])
            .into()
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
        let mut labels = vec![efm
            .exact_coord
            .into_label()
            .with_message("exact enabled here")];

        labels.extend(
            efm.missing_allowed
                .into_iter()
                .map(|ma| ma.into_label().with_message("allowed feature not present")),
        );

        let diag = Diagnostic::new(Severity::Error)
            .with_message(format!(
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
            .with_message(format!(
                "feature '{}' for crate '{}' was not explicitly allowed",
                fna.feature, fna.krate,
            ))
            .with_code(Code::FeatureNotExplicitlyAllowed)
            .with_labels(vec![fna
                .allowed
                .into_label()
                .with_message("allowed features")]);

        Diag {
            diag,
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
            .with_message(format!(
                "feature '{}' for crate '{}' is explicitly denied",
                fed.feature.value, fed.krate,
            ))
            .with_code(Code::FeatureBanned)
            .with_labels(vec![Label::primary(fed.file_id, fed.feature.span.clone())
                .with_message("feature denied here")]);

        Diag {
            diag,
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
            .with_message(format!(
                "found unknown feature '{}' for crate '{}'",
                uf.feature.value, uf.krate,
            ))
            .with_code(Code::UnknownFeature)
            .with_labels(vec![
                Label::primary(uf.file_id, uf.feature.span.clone()).with_message("unknown feature")
            ]);

        Diag {
            diag,
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
            .with_message(format!(
                "'default' feature enabled for crate '{}'",
                dfe.krate,
            ))
            .with_code(Code::DefaultFeatureEnabled)
            .with_labels(vec![
                Label::primary(dfe.file_id, dfe.level.span.clone()).with_message("lint level")
            ]);

        Diag {
            diag,
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

pub(crate) struct ExplicitPathAllowance<'a> {
    pub(crate) allowed: &'a cfg::AllowedExecutable,
    pub(crate) file_id: FileId,
}

impl From<ExplicitPathAllowance<'_>> for Diag {
    fn from(pa: ExplicitPathAllowance<'_>) -> Diag {
        let mut labels =
            vec![Label::primary(pa.file_id, pa.allowed.path.span.clone())
                .with_message("allowed path")];

        labels.extend(pa.allowed.checksum.as_ref().map(|chk| {
            Label::secondary(pa.file_id, chk.span.clone()).with_message("matched checksum")
        }));
        let diag = Diagnostic::new(Severity::Help)
            .with_message("file explicitly allowed")
            .with_code(Code::PathAllowed)
            .with_labels(labels);

        Diag {
            diag,
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
                Label::secondary(*id, glob.span.clone()).with_message("builtin")
            }
            cfg::GlobPattern::User(glob) => Label::secondary(file_id, glob.span.clone()),
        })
        .collect()
}

pub(crate) struct GlobAllowance<'a> {
    pub(crate) path: &'a crate::Path,
    pub(crate) globs: Vec<&'a cfg::GlobPattern>,
    pub(crate) file_id: FileId,
}

impl From<GlobAllowance<'_>> for Diag {
    fn from(pa: GlobAllowance<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Help)
            .with_message("file allowed by glob")
            .with_notes(vec![format!("path = '{}'", pa.path)])
            .with_code(Code::PathAllowedByGlob)
            .with_labels(globs_to_labels(pa.file_id, pa.globs));

        Diag {
            diag,
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct ChecksumMatch<'a> {
    pub(crate) path: &'a crate::Path,
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
                Label::primary(cm.file_id, cm.checksum.span.clone()).with_message("checksum")
            ]);

        Diag {
            diag,
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct ChecksumMismatch<'a> {
    pub(crate) path: &'a crate::Path,
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
            .with_labels(vec![Label::primary(cm.file_id, cm.checksum.span.clone())
                .with_message("expected checksum")]);

        Diag {
            diag,
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct DisallowedByExtension<'a> {
    pub(crate) path: &'a crate::Path,
    pub(crate) globs: Vec<&'a cfg::GlobPattern>,
    pub(crate) file_id: FileId,
}

impl From<DisallowedByExtension<'_>> for Diag {
    fn from(de: DisallowedByExtension<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Error)
            .with_message("path disallowed by extension")
            .with_notes(vec![format!("path = '{}'", de.path)])
            .with_code(Code::DisallowedByExtension)
            .with_labels(globs_to_labels(de.file_id, de.globs));

        Diag {
            diag,
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct DetectedExecutable<'a> {
    pub(crate) path: &'a crate::Path,
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
                    goblin::Hint::Unknown(_) => unreachable!(),
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
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct UnableToCheckPath<'a> {
    pub(crate) path: &'a crate::Path,
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
            .with_message(format!(
                "{} features enabled for crate with build script, checking sources",
                fe.enabled_features.len()
            ))
            .with_code(Code::FeaturesEnabled)
            .with_labels(
                fe.enabled_features
                    .into_iter()
                    .map(|ef| Label::secondary(fe.file_id, ef.span.clone()))
                    .collect(),
            );

        Diag {
            diag,
            // Not really helpful to show graphs for these
            graph_nodes: Default::default(),
            extra: None,
            with_features: false,
        }
    }
}

pub(crate) struct UnmatchedBuildConfig<'a> {
    pub(crate) unmatched: &'a super::cfg::ValidExecutables,
    pub(crate) file_id: FileId,
}

impl<'a> From<UnmatchedBuildConfig<'a>> for Diag {
    fn from(ubc: UnmatchedBuildConfig<'a>) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message("crate build configuration was not encountered")
            .with_code(Code::UnmatchedBuildConfig)
            .with_labels(vec![Label::primary(
                ubc.file_id,
                ubc.unmatched.name.span.clone(),
            )
            .with_message("unmatched crate configuration")])
            .into()
    }
}
