use crate::{
    diag::{CfgCoord, Check, Diag, Diagnostic, FileId, KrateCoord, Label, Pack, Severity},
    Krate,
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
    pub(crate) parent: &'a Krate,
    pub(crate) dep_name: &'a str,
    pub(crate) exact_coord: CfgCoord,
}

impl From<ExactFeaturesMismatch<'_>> for Diag {
    fn from(efm: ExactFeaturesMismatch<'_>) -> Self {
        let mut labels: Vec<_> = efm
            .missing_allowed
            .into_iter()
            .map(|ma| ma.into_label().with_message("allowed feature not present"))
            .collect();

        labels.push(
            efm.exact_coord
                .into_label()
                .with_message("exact-features declared here"),
        );

        Diagnostic::new(Severity::Error)
            .with_message(format!(
                "feature set declared by '{}' for '{}' did not match exactly",
                efm.parent, efm.dep_name
            ))
            .with_code("B013")
            .with_labels(labels)
            .with_notes(
                efm.not_allowed
                    .iter()
                    .map(|na| format!("'{}' feature was enabled but not explicitly allowed", na))
                    .collect(),
            )
            .into()
    }
}

pub(crate) struct FeaturesNotExplicitlyAllowed<'a> {
    pub(crate) not_allowed: &'a [&'a str],
    pub(crate) allowed: Vec<CfgCoord>,
    pub(crate) enabled_features: &'a [&'a str],
    pub(crate) parent: &'a Krate,
    pub(crate) dep_name: &'a str,
    pub(crate) colorize: bool,
}

impl From<FeaturesNotExplicitlyAllowed<'_>> for Diag {
    fn from(fna: FeaturesNotExplicitlyAllowed<'_>) -> Diag {
        let mut note = String::with_capacity(100);
        note.push_str("Enabled features: ");

        note.push('[');
        if fna.colorize {
            for enabled in fna.enabled_features {
                if fna.not_allowed.iter().any(|na| na == enabled) {
                    note.push_str(&ansi_term::Color::Red.paint(*enabled));
                } else {
                    note.push_str(&ansi_term::Color::Green.paint(*enabled));
                }
                note.push_str(", ");
            }
        } else {
            for f in fna.enabled_features {
                note.push_str(f);
                note.push_str(", ");
            }
        }
        note.truncate(note.len() - 2);
        note.push(']');

        Diagnostic::new(Severity::Error)
            .with_message(format!(
                "features declared by '{}' for '{}' were not explicitly allowed",
                fna.parent, fna.dep_name
            ))
            .with_code("B014")
            .with_labels(
                fna.allowed
                    .into_iter()
                    .map(|cc| cc.into_label().with_message("feature allowed here"))
                    .collect(),
            )
            .with_notes(vec![note])
            .into()
    }
}

pub(crate) struct FeaturesExplicitlyDenied<'a> {
    pub(crate) cfg_file_id: FileId,
    pub(crate) found_denied: Vec<&'a crate::cfg::Spanned<String>>,
    pub(crate) enabled_features: &'a [&'a str],
    pub(crate) parent: &'a Krate,
    pub(crate) dep_name: &'a str,
    pub(crate) colorize: bool,
}

impl From<FeaturesExplicitlyDenied<'_>> for Diag {
    fn from(fed: FeaturesExplicitlyDenied<'_>) -> Diag {
        let mut note = String::with_capacity(100);
        note.push_str("Enabled features: ");

        note.push('[');
        if fed.colorize {
            for enabled in fed.enabled_features {
                if fed.found_denied.iter().any(|fd| fd.value == *enabled) {
                    note.push_str(&ansi_term::Color::Red.paint(*enabled));
                } else {
                    note.push_str(enabled);
                }
                note.push_str(", ");
            }
        } else {
            for f in fed.enabled_features {
                note.push_str(f);
                note.push_str(", ");
            }
        }
        note.truncate(note.len() - 2);
        note.push(']');

        Diagnostic::new(Severity::Error)
            .with_message(format!(
                "features declared by '{}' for '{}' were explicitly denied",
                fed.parent, fed.dep_name
            ))
            .with_code("B015")
            .with_labels(
                fed.found_denied
                    .into_iter()
                    .map(|fd| {
                        Label::primary(fed.cfg_file_id, fd.span.clone())
                            .with_message("feature denied here")
                    })
                    .collect(),
            )
            .with_notes(vec![note])
            .into()
    }
}

pub(crate) struct UnableToGetDefaultFeatures<'a> {
    pub(crate) parent_krate: &'a Krate,
    pub(crate) dep: &'a krates::cm::Dependency,
}

impl From<UnableToGetDefaultFeatures<'_>> for Diag {
    fn from(udf: UnableToGetDefaultFeatures<'_>) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "unable to get default features for '{}' used by '{}'",
                udf.dep.name, udf.parent_krate,
            ))
            .with_code("B016")
            .into()
    }
}
