use crate::{
    diag::{Check, Diag, Diagnostic, KrateCoord, Label, Pack, Severity},
    Krate, LintLevel,
};
use rustsec::advisory::{informational::Informational, metadata::Metadata, versions::Versions, Id};

fn get_notes_from_advisory(advisory: &Metadata) -> Vec<String> {
    let mut n = Vec::new();

    n.push(format!("ID: {}", advisory.id));
    if let Some(url) = advisory.id.url() {
        n.push(format!("Advisory: {}", &url));
    }
    n.push(advisory.description.clone());

    if let Some(ref url) = advisory.url {
        n.push(format!("Announcement: {}", url));
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

        let (severity, ty) = {
            let (lint_level, msg) = match &advisory.informational {
                // Everything that isn't an informational advisory is a vulnerability
                None => (self.cfg.vulnerability, AdvisoryType::Vulnerability),
                Some(info) => match info {
                    // Security notices for a crate which are published on https://rustsec.org
                    // but don't represent a vulnerability in a crate itself.
                    Informational::Notice => (self.cfg.notice, AdvisoryType::Notice),
                    // Crate is unmaintained / abandoned
                    Informational::Unmaintained => {
                        (self.cfg.unmaintained, AdvisoryType::Unmaintained)
                    }
                    Informational::Unsound => (self.cfg.unsound, AdvisoryType::Unsound),
                    // Other types of informational advisories: left open-ended to add
                    // more of them in the future.
                    Informational::Other(_) => {
                        unreachable!("rustsec only returns these if we ask, and there are none at the moment to ask for");
                    }
                    _ => unreachable!("unknown advisory type encountered"),
                },
            };

            // Ok, we found a crate whose version lies within the range of an
            // advisory, but the user might have decided to ignore it
            // for "reasons", but in that case we still emit it to the log
            // so it doesn't just disappear into the aether
            let lint_level = if let Ok(index) = self
                .cfg
                .ignore
                .binary_search_by(|i| i.value.cmp(&advisory.id))
            {
                on_ignore(index);
                LintLevel::Allow
            } else if let Some(severity_threshold) = self.cfg.severity_threshold {
                if let Some(advisory_severity) = advisory.cvss.as_ref().map(|cvss| cvss.severity())
                {
                    if advisory_severity < severity_threshold {
                        LintLevel::Allow
                    } else {
                        lint_level
                    }
                } else {
                    lint_level
                }
            } else {
                lint_level
            };

            (
                match lint_level {
                    LintLevel::Warn => Severity::Warning,
                    LintLevel::Deny => Severity::Error,
                    LintLevel::Allow => Severity::Help,
                },
                msg,
            )
        };

        let mut notes = get_notes_from_advisory(&advisory);

        if let Some(versions) = versions {
            if versions.patched.is_empty() {
                notes.push("Solution: No safe upgrade is available!".to_owned())
            } else {
                notes.push(format!(
                    "Solution: Upgrade to {}",
                    versions
                        .patched
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .as_slice()
                        .join(" OR ")
                ))
            }
        };

        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());

        let (message, code) = match ty {
            AdvisoryType::Vulnerability => ("security vulnerability detected", "A001"),
            AdvisoryType::Notice => ("notice advisory detected", "A002"),
            AdvisoryType::Unmaintained => ("unmaintained advisory detected", "A003"),
            AdvisoryType::Unsound => ("unsound advisory detected", "A004"),
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
            diag.extra = serde_json::to_value(&advisory)
                .ok()
                .map(|v| ("advisory", v));
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
            Diagnostic::new(match self.cfg.yanked.value {
                LintLevel::Allow => Severity::Help,
                LintLevel::Deny => Severity::Error,
                LintLevel::Warn => Severity::Warning,
            })
            .with_message("detected yanked crate")
            .with_code("A005")
            .with_labels(vec![self
                .krate_spans
                .label_for_index(krate_index.index(), "yanked version")]),
        );

        pack
    }

    pub(crate) fn diag_for_index_failure<D: std::fmt::Display>(&self, error: D) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Warning)
                .with_message(format!("unable to check for yanked crates: {}", error))
                .with_code("A006")
                .with_labels(vec![Label::primary(
                    self.cfg.file_id,
                    self.cfg.yanked.span.clone(),
                )
                .with_message("lint level defined here")]),
        )
            .into()
    }

    pub(crate) fn diag_for_advisory_not_encountered(
        &self,
        not_hit: &crate::cfg::Spanned<Id>,
    ) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Warning)
                .with_message("advisory was not encountered")
                .with_code("A007")
                .with_labels(vec![Label::primary(self.cfg.file_id, not_hit.span.clone())
                    .with_message("no crate matched advisory criteria")]),
        )
            .into()
    }

    pub(crate) fn diag_for_unknown_advisory(&self, unknown: &crate::cfg::Spanned<Id>) -> Pack {
        (
            Check::Advisories,
            Diagnostic::new(Severity::Warning)
                .with_message("advisory not found in any advisory database")
                .with_code("A008")
                .with_labels(vec![Label::primary(self.cfg.file_id, unknown.span.clone())
                    .with_message("unknown advisory")]),
        )
            .into()
    }

    pub(crate) fn diag_for_prerelease_skipped(
        &self,
        krate: &crate::Krate,
        krate_index: krates::NodeId,
        advisory: &Metadata,
        patched: &semver::VersionReq,
    ) -> Pack {
        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());

        let notes = {
            let mut n = Vec::new();
            n.push(format!("ID: {}", advisory.id));
            if let Some(url) = advisory.id.url() {
                n.push(format!("Advisory: {}", &url));
            }

            n.push(format!("Satisfied patch requirement: {}", patched));

            n
        };

        pack.push(
            Diagnostic::new(Severity::Warning)
                .with_message(
                    "advisory for a crate with a pre-release was skipped as it matched a patch",
                )
                .with_code("A009")
                .with_notes(notes)
                .with_labels(vec![self
                    .krate_spans
                    .label_for_index(krate_index.index(), "pre-release crate")]),
        );

        pack
    }
}

pub(crate) struct NoAvailablePatches<'a> {
    pub(crate) affected_krate_coord: KrateCoord,
    pub(crate) advisory: &'a Metadata,
}

impl<'a> Into<Diag> for NoAvailablePatches<'a> {
    fn into(self) -> Diag {
        let notes = get_notes_from_advisory(self.advisory);
        Diagnostic::new(Severity::Error)
            .with_message("advisory has no available patches")
            .with_code("AF001")
            .with_labels(vec![self
                .affected_krate_coord
                .into_label()
                .with_message("affected crate")])
            .with_notes(notes)
            .into()
    }
}

pub(crate) struct NoAvailablePatchedVersions<'a> {
    pub(crate) affected_krate_coord: KrateCoord,
    pub(crate) advisory: &'a Metadata,
}

impl<'a> Into<Diag> for NoAvailablePatchedVersions<'a> {
    fn into(self) -> Diag {
        let notes = get_notes_from_advisory(self.advisory);
        Diagnostic::new(Severity::Error)
            .with_message("affected crate has no available patched versions")
            .with_code("AF002")
            .with_labels(vec![self
                .affected_krate_coord
                .into_label()
                .with_message("affected crate")])
            .with_notes(notes)
            .into()
    }
}

pub(crate) struct UnableToFindMatchingVersion<'a> {
    pub(crate) parent_krate: &'a Krate,
    pub(crate) dep: &'a Krate,
    pub(crate) reason: super::fix::NoVersionReason,
}

impl<'a> Into<Diag> for UnableToFindMatchingVersion<'a> {
    fn into(self) -> Diag {
        let mut diag: Diag = Diagnostic::new(Severity::Error)
            .with_message(format!(
                "unable to patch {} => {}: {}",
                self.parent_krate, self.dep.name, self.reason
            ))
            .with_code("AF003")
            .into();

        diag.kids.push(self.dep.id.clone());
        diag
    }
}

pub(crate) struct UnpatchableSource<'a> {
    pub(crate) parent_krate: &'a Krate,
}

impl<'a> Into<Diag> for UnpatchableSource<'a> {
    fn into(self) -> Diag {
        let mut diag: Diag = Diagnostic::new(Severity::Error)
            .with_message(format!(
                "unable to patch '{}', not a 'registry' or 'local'",
                self.parent_krate
            ))
            .with_code("AF004")
            .into();

        diag.kids.push(self.parent_krate.id.clone());
        diag
    }
}

fn to_string<T: std::fmt::Display>(v: &[T]) -> String {
    let mut dv = String::with_capacity(64);

    for req in v {
        use std::fmt::Write;
        write!(&mut dv, "{}, ", req).expect("failed to write string");
    }

    dv.truncate(dv.len() - 2);
    dv
}

pub(crate) struct IncompatibleLocalKrate<'a> {
    pub(crate) local_krate: &'a Krate,
    pub(crate) dep_req: &'a semver::VersionReq,
    pub(crate) dep: &'a Krate,
    pub(crate) required_versions: &'a [semver::Version],
}

impl<'a> Into<Diag> for IncompatibleLocalKrate<'a> {
    fn into(self) -> Diag {
        let mut diag: Diag = Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "local crate {} has a requirement of '{}' on '{}', which does not match any required version",
                self.local_krate,
                self.dep_req,
                self.dep.name,
            ))
            .with_notes(vec![format!("Required versions: [{}]", to_string(self.required_versions))])
            .with_code("AF005")
            .into();

        diag.kids.push(self.dep.id.clone());
        diag
    }
}

pub(crate) struct NoNewerVersionAvailable<'a> {
    pub(crate) local_krate: &'a Krate,
    pub(crate) dep: &'a Krate,
}

impl<'a> Into<Diag> for NoNewerVersionAvailable<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "unable to patch '{}' => '{}', no newer versions of '{}' are available",
                self.local_krate, self.dep, self.dep.name,
            ))
            .with_code("AF006")
            .into()
    }
}
