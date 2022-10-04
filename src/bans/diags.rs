use crate::{
    bans::KrateId,
    diag::{
        CfgCoord, Check, Diag, Diagnostic, FileId, GraphNode, KrateCoord, Label, Pack, Severity,
    },
    Krate, Spanned,
};

pub(crate) struct ExplicitlyBanned<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) ban_cfg: CfgCoord,
}

impl<'a> From<ExplicitlyBanned<'a>> for Diag {
    fn from(eb: ExplicitlyBanned<'a>) -> Self {
        Diagnostic::new(Severity::Error)
            .with_message(format!("crate '{}' is explicitly banned", eb.krate))
            .with_code("B001")
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
            .with_code("B002")
            .with_labels(vec![ea.allow_cfg.into_label().with_message("allowed here")])
            .into()
    }
}

pub(crate) struct ImplicitlyBanned<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<ImplicitlyBanned<'a>> for Diag {
    fn from(ib: ImplicitlyBanned<'a>) -> Self {
        Diagnostic::new(Severity::Error)
            .with_message(format!("crate '{}' is implicitly banned", ib.krate))
            .with_code("B003")
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
            .with_code("B004")
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
        Diagnostic::new(Severity::Help)
            .with_message(format!(
                "crate '{}' skipped when checking for duplicates",
                sk.krate
            ))
            .with_code("B005")
            .with_labels(vec![sk.skip_cfg.into_label().with_message("skipped here")])
            .into()
    }
}

pub(crate) struct Wildcards<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) severity: Severity,
    pub(crate) wildcards: Vec<&'a krates::cm::Dependency>,
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
                    "found {} wildcard dependenc{} for crate '{}'",
                    labels.len(),
                    if labels.len() == 1 { "y" } else { "ies" },
                    wc.krate.name
                ))
                .with_code("B006")
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
            .with_code("B007")
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
        Diagnostic::new(Severity::Help)
            .with_message(format!(
                "banned crate '{}' allowed by wrapper '{}'",
                baw.banned_krate, baw.wrapper_krate
            ))
            .with_code("B008")
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
            .with_code("B009")
            .with_labels(vec![buw.ban_cfg.into_label().with_message("banned here")])
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
            .with_code("B010")
            .with_labels(vec![usr
                .skip_root_cfg
                .into_label()
                .with_message("no crate matched these criteria")])
            .into()
    }
}

pub(crate) struct SkippedByRoot<'a> {
    pub(crate) skip_root_cfg: CfgCoord,
    pub(crate) krate: &'a Krate,
}

impl<'a> From<SkippedByRoot<'a>> for Diag {
    fn from(sbr: SkippedByRoot<'a>) -> Self {
        Diagnostic::new(Severity::Help)
            .with_message(format!("skipping crate '{}' due to root skip", sbr.krate))
            .with_code("B011")
            .with_labels(vec![sbr
                .skip_root_cfg
                .into_label()
                .with_message("matched skip root")])
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
            .with_code("B012")
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
            .with_code("B013")
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
            .with_code("B014")
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

pub(crate) struct FeatureExplicitlyDenied<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) feature: &'a Spanned<String>,
    pub(crate) file_id: FileId,
}

impl From<FeatureExplicitlyDenied<'_>> for Diag {
    fn from(fed: FeatureExplicitlyDenied<'_>) -> Diag {
        let diag = Diagnostic::new(Severity::Error)
            .with_message(format!(
                "feature '{}' for crate '{}' is explicitly denied",
                fed.feature.value, fed.krate,
            ))
            .with_code("B015")
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
            .with_code("B016")
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
