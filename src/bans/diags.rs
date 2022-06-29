use crate::{
    diag::{CfgCoord, Check, Diag, Diagnostic, KrateCoord, Label, Pack, Severity},
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

pub(crate) struct UnmatchedSkip {
    pub(crate) skip_cfg: CfgCoord,
}

impl From<UnmatchedSkip> for Diag {
    fn from(us: UnmatchedSkip) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message("skipped crate was not encountered")
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
