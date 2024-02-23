use super::cfg::IgnoreId;
use crate::{
    diag::{Check, Diagnostic, FileId, Label, Pack, Severity},
    LintLevel,
};
use rustsec::advisory::{Informational, Metadata, Versions};

impl IgnoreId {
    fn to_labels(&self, id: FileId, msg: impl Into<String>) -> Vec<Label> {
        let mut v = Vec::with_capacity(self.reason.as_ref().map_or(1, |_| 2));
        v.push(Label::primary(id, self.id.span).with_message(msg));

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

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
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

impl<'a> crate::CheckCtx<'a, super::cfg::ValidConfig> {
    pub(crate) fn diag_for_advisory<F>(
        &self,
        krate: &crate::Krate,
        krate_index: krates::NodeId,
        advisory: &Metadata,
        versions: Option<&Versions>,
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

        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());

        let (severity, ty) = {
            let adv_ty = advisory.informational.as_ref().map_or(AdvisoryType::Vulnerability, |info| {
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
            let lint_level = if let Ok(index) = self
                .cfg
                .ignore
                .binary_search_by(|i| i.id.value.cmp(&advisory.id))
            {
                on_ignore(index);

                pack.push(
                    Diagnostic::note()
                        .with_message("advisory ignored")
                        .with_code(Code::AdvisoryIgnored)
                        .with_labels(
                            self.cfg.ignore[index]
                                .to_labels(self.cfg.file_id, "advisory ignored here"),
                        ),
                );

                LintLevel::Allow
            } else if let Some(deprecated) = &self.cfg.deprecated {
                'll: {
                    if let (Some(st), Some(sev)) = (
                        deprecated.severity_threshold,
                        advisory.cvss.as_ref().map(|c| c.severity()),
                    ) {
                        if sev < st {
                            break 'll LintLevel::Allow;
                        }
                    }

                    match adv_ty {
                        AdvisoryType::Vulnerability => deprecated.vulnerability,
                        AdvisoryType::Unmaintained => deprecated.unmaintained,
                        AdvisoryType::Unsound => deprecated.unsound,
                        AdvisoryType::Notice => deprecated.notice,
                    }
                }
            } else {
                LintLevel::Deny
            };

            (lint_level.into(), adv_ty)
        };

        let mut notes = get_notes_from_advisory(advisory);

        if let Some(versions) = versions {
            if versions.patched().is_empty() {
                notes.push("Solution: No safe upgrade is available!".to_owned());
            } else {
                notes.push(format!(
                    "Solution: Upgrade to {} (try `cargo update -p {}`)",
                    versions
                        .patched()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .as_slice()
                        .join(" OR "),
                    krate.name,
                ));
            }
        };

        let (message, code) = match ty {
            AdvisoryType::Vulnerability => ("security vulnerability detected", Code::Vulnerability),
            AdvisoryType::Notice => ("notice advisory detected", Code::Notice),
            AdvisoryType::Unmaintained => ("unmaintained advisory detected", Code::Unmaintained),
            AdvisoryType::Unsound => ("unsound advisory detected", Code::Unsound),
        };

        let diag = pack.push(
            Diagnostic::new(severity)
                .with_message(advisory.title.clone())
                .with_labels(vec![self
                    .krate_spans
                    .label_for_index(krate_index.index(), message)])
                .with_code(code)
                .with_notes(notes),
        );

        if self.serialize_extra {
            diag.extra = serde_json::to_value(advisory).ok().map(|v| ("advisory", v));
        }

        pack
    }

    pub(crate) fn diag_for_yanked(
        &self,
        krate: &crate::Krate,
        krate_index: krates::NodeId,
    ) -> Pack {
        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());
        pack.push(
            Diagnostic::new(self.cfg.yanked.value.into())
                .with_message(format!(
                    "detected yanked crate (try `cargo update -p {}`)",
                    krate.name
                ))
                .with_code(Code::Yanked)
                .with_labels(vec![self
                    .krate_spans
                    .label_for_index(krate_index.index(), "yanked version")]),
        );

        pack
    }

    pub(crate) fn diag_for_yanked_ignore(&self, krate: &crate::Krate, ignore: usize) -> Pack {
        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());
        pack.push(
            Diagnostic::note()
                .with_message(format!("yanked crate '{krate}' detected, but ignored",))
                .with_code(Code::YankedIgnored)
                .with_labels(self.cfg.ignore_yanked[ignore].to_labels(Some("yanked ignore"))),
        );

        pack
    }

    pub(crate) fn diag_for_index_failure<D: std::fmt::Display>(
        &self,
        krate: &crate::Krate,
        krate_index: krates::NodeId,
        error: D,
    ) -> Pack {
        let mut labels = vec![self.krate_spans.label_for_index(
            krate_index.index(),
            "crate whose registry we failed to query",
        )];

        // Don't show the config location if it's the default, since it just points
        // to the beginning and confuses users
        if !self.cfg.yanked.span.is_empty() {
            labels.push(
                Label::primary(self.cfg.file_id, self.cfg.yanked.span)
                    .with_message("lint level defined here"),
            );
        }

        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());
        pack.push(
            Diagnostic::new(Severity::Warning)
                .with_message("unable to check for yanked crates")
                .with_code(Code::IndexFailure)
                .with_labels(labels)
                .with_notes(vec![error.to_string()]),
        );
        pack
    }

    pub fn diag_for_index_load_failure(&self, error: impl std::fmt::Display) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Error)
                .with_message("failed to load index cache")
                .with_code(Code::IndexCacheLoadFailure)
                .with_notes(vec![error.to_string()]),
        )
            .into()
    }

    pub(crate) fn diag_for_advisory_not_encountered(&self, not_hit: &IgnoreId) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Warning)
                .with_message("advisory was not encountered")
                .with_code(Code::AdvisoryNotDetected)
                .with_labels(
                    not_hit.to_labels(self.cfg.file_id, "no crate matched advisory criteria"),
                ),
        )
            .into()
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn diag_for_ignored_yanked_not_encountered(
        &self,
        not_hit: &crate::bans::SpecAndReason,
    ) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Warning)
                .with_message("yanked crate was not encountered")
                .with_code(Code::YankedNotDetected)
                .with_labels(not_hit.to_labels(Some("yanked crate not detected"))),
        )
            .into()
    }

    pub(crate) fn diag_for_unknown_advisory(&self, unknown: &IgnoreId) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Warning)
                .with_message("advisory not found in any advisory database")
                .with_code(Code::UnknownAdvisory)
                .with_labels(unknown.to_labels(self.cfg.file_id, "unknown advisory")),
        )
            .into()
    }
}
