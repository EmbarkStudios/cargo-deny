use crate::{
    diag::{CfgCoord, Check, Diag, Diagnostic, KrateCoord, Label, Pack, Severity},
    Krate,
};

pub(crate) struct ExplicitlyBanned<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) ban_cfg: CfgCoord,
}

impl<'a> Into<Diag> for ExplicitlyBanned<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Error)
            .with_message(format!("crate '{}' is explicitly banned", self.krate))
            .with_code("B001")
            .with_labels(vec![self.ban_cfg.into_label().with_message("banned here")])
            .into()
    }
}

pub(crate) struct ExplicitlyAllowed<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) allow_cfg: CfgCoord,
}

impl<'a> Into<Diag> for ExplicitlyAllowed<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Note)
            .with_message(format!("crate '{}' is explicitly allowed", self.krate))
            .with_code("B002")
            .with_labels(vec![self
                .allow_cfg
                .into_label()
                .with_message("allowed here")])
            .into()
    }
}

pub(crate) struct ImplicitlyBanned<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> Into<Diag> for ImplicitlyBanned<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Error)
            .with_message(format!("crate '{}' is implicitly banned", self.krate))
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

impl<'a> Into<Diag> for Duplicates<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(self.severity)
            .with_message(format!(
                "found {} duplicate entries for crate '{}'",
                self.num_dupes, self.krate_name,
            ))
            .with_code("B004")
            .with_labels(vec![self
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

impl<'a> Into<Diag> for Skipped<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Help)
            .with_message(format!(
                "crate '{}' skipped when checking for duplicates",
                self.krate
            ))
            .with_code("B005")
            .with_labels(vec![self
                .skip_cfg
                .into_label()
                .with_message("skipped here")])
            .into()
    }
}

pub(crate) struct Wildcards<'a> {
    pub(crate) krate: &'a Krate,
    pub(crate) severity: Severity,
    pub(crate) wildcards: Vec<&'a krates::cm::Dependency>,
    pub(crate) cargo_spans: &'a crate::diag::CargoSpans,
}

impl<'a> Into<Pack> for Wildcards<'a> {
    fn into(self) -> Pack {
        let (file_id, map) = &self.cargo_spans[&self.krate.id];

        let labels: Vec<_> = self
            .wildcards
            .into_iter()
            .map(|dep| {
                Label::primary(*file_id, map[&dep.name].clone())
                    .with_message("wildcard crate entry")
            })
            .collect();

        let diag = Diag::new(
            Diagnostic::new(self.severity)
                .with_message(format!(
                    "found {} wildcard dependenc{} for crate '{}'",
                    labels.len(),
                    if labels.len() == 1 { "y" } else { "ies" },
                    self.krate.name
                ))
                .with_code("B006")
                .with_labels(labels),
        );

        let mut pack = Pack::with_kid(Check::Bans, self.krate.id.clone());
        pack.push(diag);

        pack
    }
}

pub(crate) struct UnmatchedSkip {
    pub(crate) skip_cfg: CfgCoord,
}

impl Into<Diag> for UnmatchedSkip {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message("skipped crate was not encountered")
            .with_code("B007")
            .with_labels(vec![self
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

impl<'a> Into<Diag> for BannedAllowedByWrapper<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Help)
            .with_message(format!(
                "banned crate '{}' allowed by wrapper '{}'",
                self.banned_krate, self.wrapper_krate
            ))
            .with_code("B008")
            .with_labels(vec![
                self.ban_cfg.into_label().with_message("banned here"),
                self.ban_exception_cfg
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

impl<'a> Into<Diag> for BannedUnmatchedWrapper<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "direct parent '{}' of banned crate '{}' was not marked as a wrapper",
                self.parent_krate, self.banned_krate
            ))
            .with_code("B009")
            .with_labels(vec![self.ban_cfg.into_label().with_message("banned here")])
            .into()
    }
}

pub(crate) struct UnmatchedSkipRoot {
    pub(crate) skip_root_cfg: CfgCoord,
}

impl Into<Diag> for UnmatchedSkipRoot {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message("skip tree root was not found in the dependency graph")
            .with_code("B010")
            .with_labels(vec![self
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

impl<'a> Into<Diag> for SkippedByRoot<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Help)
            .with_message(format!("skipping crate '{}' due to root skip", self.krate))
            .with_labels(vec![self
                .skip_root_cfg
                .into_label()
                .with_message("matched skip root")])
            .into()
    }
}
