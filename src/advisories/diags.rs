use super::cfg::IgnoreId;
use crate::{
    LintLevel,
    diag::{Check, Diagnostic, FileId, Label, Pack, Severity},
};
use rustsec::{
    Advisory,
    advisory::{Informational, Metadata},
};

impl IgnoreId {
    fn to_labels(&self, id: FileId, msg: impl Into<String>) -> Vec<Label> {
        let mut v = Vec::with_capacity(self.reason.as_ref().map_or(1, |_| 2));
        v.push(Label {
            style: codespan_reporting::diagnostic::LabelStyle::Primary,
            file_id: id,
            range: self.id.span.into(),
            message: msg.into(),
        });

        if let Some(reason) = &self.reason {
            v.push(Label::secondary(id, reason.0.span).with_message("ignore reason"));
        }

        v
    }
}

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
    Vulnerability,
    Notice,
    Unmaintained,
    Unsound,
    Yanked,
    AdvisoryIgnored,
    YankedIgnored,
    IndexFailure,
    IndexCacheLoadFailure,
    AdvisoryNotDetected,
    YankedNotDetected,
    UnknownAdvisory,
}

impl Code {
    #[inline]
    pub fn description(self) -> &'static str {
        match self {
            Self::Vulnerability => "A vulnerability advisory was detected",
            Self::Unmaintained => "An unmaintained advisory was detected",
            Self::Unsound => "An unsound advisory was detected",
            Self::Notice => "A notice advisory was detected",
            Self::Yanked => "Detected a crate version yanked from its remote registry",
            Self::AdvisoryIgnored => "An advisory was ignored",
            Self::YankedIgnored => "A yanked crate version was ignored",
            Self::IndexFailure => "Failed to get index information for a registry",
            Self::IndexCacheLoadFailure => "Failed to load cached index information for a registry",
            Self::AdvisoryNotDetected => "An advisory was ignored, but not detected",
            Self::YankedNotDetected => "A yanked crate version was ignored, but not detected",
            Self::UnknownAdvisory => "An ignored advisory does not exist in any advisory database",
        }
    }
}

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
}

#[inline]
fn diag(diag: Diagnostic, code: Code) -> crate::diag::Diag {
    crate::diag::Diag::new(diag, Some(crate::diag::DiagnosticCode::Advisory(code)))
}

fn get_notes_from_advisory(advisory: &Metadata) -> Vec<String> {
    let mut n = vec![format!("ID: {}", advisory.id)];
    if let Some(url) = advisory.id.url() {
        n.push(format!("Advisory: {url}"));
    }

    n.push(advisory.description.clone());

    if let Some(url) = &advisory.url {
        n.push(format!("Announcement: {url}"));
    }

    n
}

impl crate::CheckCtx<'_, super::cfg::ValidConfig> {
    pub(crate) fn diag_for_advisory<F>(
        &self,
        krate: &crate::Krate,
        advisory: &Advisory,
        mut on_ignore: F,
    ) -> Pack
    where
        F: FnMut(usize),
    {
        #[derive(Clone, Copy)]
        enum AdvisoryType {
            Vulnerability,
            Notice,
            Unmaintained,
            Unsound,
        }

        let md = &advisory.metadata;

        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());

        let (severity, ty) = {
            let adv_ty = md.informational.as_ref().map_or(AdvisoryType::Vulnerability, |info| {
                match info {
                    // Crate is unmaintained / abandoned
                    Informational::Unmaintained => AdvisoryType::Unmaintained,
                    Informational::Unsound => AdvisoryType::Unsound,
                    Informational::Notice => AdvisoryType::Notice,
                    Informational::Other(other) => {
                        unreachable!("rustsec only returns Informational::Other({other}) advisories if we ask, and there are none at the moment to ask for");
                    }
                    _ => unreachable!("non_exhaustive enums are the worst"),
                }
            });

            // Ok, we found a crate whose version lies within the range of an
            // advisory, but the user might have decided to ignore it
            // for "reasons", but in that case we still emit it to the log
            // so it doesn't just disappear into the aether
            let lint_level =
                if let Ok(index) = self.cfg.ignore.binary_search_by(|i| i.id.value.cmp(&md.id)) {
                    on_ignore(index);

                    pack.push(diag(
                        Diagnostic::note()
                            .with_message("advisory ignored")
                            .with_labels(
                                self.cfg.ignore[index]
                                    .to_labels(self.cfg.file_id, "advisory ignored here"),
                            ),
                        Code::AdvisoryIgnored,
                    ));

                    LintLevel::Allow
                } else {
                    LintLevel::Deny
                };

            (lint_level.into(), adv_ty)
        };

        let mut notes = get_notes_from_advisory(md);

        if advisory.versions.patched().is_empty() {
            notes.push("Solution: No safe upgrade is available!".to_owned());
        } else {
            notes.push(format!(
                "Solution: Upgrade to {} (try `cargo update -p {}`)",
                advisory
                    .versions
                    .patched()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .as_slice()
                    .join(" OR "),
                krate.name,
            ));
        }

        let (message, code) = match ty {
            AdvisoryType::Vulnerability => ("security vulnerability detected", Code::Vulnerability),
            AdvisoryType::Notice => ("notice advisory detected", Code::Notice),
            AdvisoryType::Unmaintained => ("unmaintained advisory detected", Code::Unmaintained),
            AdvisoryType::Unsound => ("unsound advisory detected", Code::Unsound),
        };

        let diag = pack.push(diag(
            Diagnostic::new(severity)
                .with_message(&md.title)
                .with_labels(vec![
                    Label::primary(
                        self.krate_spans.lock_id,
                        self.krate_spans.lock_span(&krate.id).total,
                    )
                    .with_message(message),
                ])
                .with_notes(notes),
            code,
        ));

        if self.serialize_extra {
            diag.extra = Some(crate::diag::Extra::Advisory(advisory.clone()));
        }

        pack
    }

    pub(crate) fn diag_for_yanked(&self, krate: &crate::Krate) -> Pack {
        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());
        pack.push(diag(
            Diagnostic::new(self.cfg.yanked.value.into())
                .with_message(format_args!(
                    "detected yanked crate (try `cargo update -p {}`)",
                    krate.name
                ))
                .with_labels(vec![
                    Label::primary(
                        self.krate_spans.lock_id,
                        self.krate_spans.lock_span(&krate.id).total,
                    )
                    .with_message("yanked version"),
                ]),
            Code::Yanked,
        ));

        pack
    }

    pub(crate) fn diag_for_yanked_ignore(&self, krate: &crate::Krate, ignore: usize) -> Pack {
        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());
        pack.push(diag(
            Diagnostic::note()
                .with_message(format_args!("yanked crate '{krate}' detected, but ignored",))
                .with_labels(self.cfg.ignore_yanked[ignore].to_labels(Some("yanked ignore"))),
            Code::YankedIgnored,
        ));

        pack
    }

    pub(crate) fn diag_for_index_failure<D: std::fmt::Display>(
        &self,
        krate: &crate::Krate,
        error: D,
    ) -> Pack {
        let mut labels = vec![
            Label::secondary(
                self.krate_spans.lock_id,
                self.krate_spans.lock_span(&krate.id).total,
            )
            .with_message("crate whose registry we failed to query"),
        ];

        // Don't show the config location if it's the default, since it just points
        // to the beginning and confuses users
        if !self.cfg.yanked.span.is_empty() {
            labels.push(
                Label::primary(self.cfg.file_id, self.cfg.yanked.span)
                    .with_message("lint level defined here"),
            );
        }

        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());
        pack.push(diag(
            Diagnostic::new(Severity::Warning)
                .with_message("unable to check for yanked crates")
                .with_labels(labels)
                .with_notes(vec![error.to_string()]),
            Code::IndexFailure,
        ));
        pack
    }

    pub fn diag_for_index_load_failure(&self, error: impl std::fmt::Display) -> Pack {
        (
            Check::Advisories,
            diag(
                Diagnostic::new(Severity::Error)
                    .with_message("failed to load index cache")
                    .with_notes(vec![error.to_string()]),
                Code::IndexCacheLoadFailure,
            ),
        )
            .into()
    }

    pub(crate) fn diag_for_advisory_not_encountered(
        &self,
        not_hit: &IgnoreId,
        severity: Severity,
    ) -> Pack {
        (
            Check::Advisories,
            diag(
                Diagnostic::new(severity)
                    .with_message("advisory was not encountered")
                    .with_labels(
                        not_hit.to_labels(self.cfg.file_id, "no crate matched advisory criteria"),
                    ),
                Code::AdvisoryNotDetected,
            ),
        )
            .into()
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn diag_for_ignored_yanked_not_encountered(
        &self,
        not_hit: &crate::bans::SpecAndReason,
        severity: Severity,
    ) -> Pack {
        (
            Check::Advisories,
            diag(
                Diagnostic::new(severity)
                    .with_message("yanked crate was not encountered")
                    .with_labels(not_hit.to_labels(Some("yanked crate not detected"))),
                Code::YankedNotDetected,
            ),
        )
            .into()
    }

    pub(crate) fn diag_for_unknown_advisory(&self, unknown: &IgnoreId) -> Pack {
        (
            Check::Advisories,
            diag(
                Diagnostic::new(Severity::Warning)
                    .with_message("advisory not found in any advisory database")
                    .with_labels(unknown.to_labels(self.cfg.file_id, "unknown advisory")),
                Code::UnknownAdvisory,
            ),
        )
            .into()
    }
}
