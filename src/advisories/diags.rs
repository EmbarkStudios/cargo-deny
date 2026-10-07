use super::{
    cfg::IgnoreId,
    model::{Advisory, Informational, Metadata},
};
use crate::{
    LintLevel,
    diag::{Check, Diagnostic, FileId, Label, Pack, Severity},
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

crate::simple_enum!(
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    Code,
    [
        Vulnerability = "vulnerability",
        Notice = "notice",
        Unmaintained = "unmaintained",
        Unsound = "unsound",
        Yanked = "yanked",
        AdvisoryIgnored = "advisory-ignored",
        AdvisoryIgnoreExpired = "advisory-ignore-expired",
        AdvisoryIgnoreDisallowedDependent = "advisory-ignore-disallowed-dependent",
        AdvisoryIgnoreAllowedDependentMissing = "advisory-ignore-allowed-dependent-missing",
        YankedIgnored = "yanked-ignored",
        IndexFailure = "index-failure",
        IndexCacheLoadFailure = "index-cache-load-failure",
        AdvisoryNotDetected = "advisory-not-detected",
        YankedNotDetected = "yanked-not-detected",
        UnknownAdvisory = "unknown-advisory",
    ]
);

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
            Self::AdvisoryIgnoreExpired => "An ignore for an advisory expired",
            Self::AdvisoryIgnoreDisallowedDependent => {
                "An ignore for an advisory did not explicitly a direct dependency"
            }
            Self::AdvisoryIgnoreAllowedDependentMissing => {
                "An ignore an advisory explicitly allowed a crate that is not a direct dependency"
            }
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

fn get_notes_from_advisory(advisory: &Metadata<'_>) -> Vec<String> {
    let mut n = vec![format!("ID: {}", advisory.id)];

    #[inline]
    fn advisory_url(id: &str) -> Option<String> {
        let (kind, _) = id.split_once('-')?;
        let url = match kind {
            "RUSTSEC" => format!("Advisory: https://rustsec.org/advisories/{id}"),
            "CVE" => format!("Advisory: https://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"),
            "GHSA" => format!("Advisory: https://github.com/advisories/{id}"),
            "TALOS" => format!("Advisory: https://www.talosintelligence.com/reports/{id}"),
            _ => return None,
        };

        Some(url)
    }

    if let Some(url) = advisory_url(advisory.id) {
        n.push(url);
    }

    n.push(advisory.description.to_owned());

    if let Some(url) = &advisory.url {
        n.push(format!("Announcement: {url}"));
    }

    n
}

impl<'ctx> crate::CheckCtx<'ctx, super::cfg::ValidConfig> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn diag_for_advisory<F>(
        &self,
        krate: &crate::Krate,
        serialize_advisories: crate::SerializeAdvisory,
        advisory: &Advisory<'_>,
        date: jiff::civil::Date,
        direct_dependents: &Vec<krates::DirectDependent<'ctx, crate::Krate>>,
        indices: Option<&super::Indices<'_>>,
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

        let md = &advisory.advisory;

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
                }
            });

            // Ok, we found a crate whose version lies within the range of an advisory, but the user might have decided
            // to ignore it for "reasons", but in that case we still emit it to the log so it doesn't just disappear
            // into the aether
            let lint_level = 'll: {
                if let Ok(index) = self
                    .cfg
                    .ignore
                    .binary_search_by(|i| i.id.value.as_str().cmp(md.id))
                {
                    // This just marks the ignore as seen, even if we ultimately don't ignore it due to when it was issued,
                    // or if a crate not explicitly allowed depended on it
                    on_ignore(index);

                    let ignore = &self.cfg.ignore[index];

                    // There are no notice advisories at this time, and unmaintained advisories are uninteresting since if
                    // the crate transitions back to being maintained the advisory will/should be withdrawn, but otherwise
                    // unmaintained advisories won't ever have a fix/unaffected version
                    if matches!(adv_ty, AdvisoryType::Vulnerability | AdvisoryType::Unsound)
                        && let Some(expiry) =
                            ignore.expiry.as_ref().or(self.cfg.ignore_expiry.as_ref())
                        && let Ok(max) = md.date.checked_add(expiry.value)
                        && date > max
                    {
                        let mut l = ignore.to_labels(self.cfg.file_id, "advisory ignored here");
                        l.push(Label {
                            style: codespan_reporting::diagnostic::LabelStyle::Primary,
                            file_id: self.cfg.file_id,
                            range: expiry.span.into(),
                            message: "expiry which was exceeded".into(),
                        });
                        pack.push(diag(
                            Diagnostic::note()
                                .with_message("ignored advisory expired")
                                .with_labels(l),
                            Code::AdvisoryIgnoreExpired,
                        ));

                        break 'll LintLevel::Deny;
                    }

                    if let Some(allow) = &ignore.allow {
                        let before = pack.len();
                        for dd in direct_dependents {
                            if !allow
                                .value
                                .iter()
                                .any(|allowed| crate::match_krate(dd.krate, &allowed.spec))
                            {
                                pack.push(diag(
                                    Diagnostic::warning()
                                        .with_message(format!(
                                            "direct dependent '{}' was not explicitly allowed",
                                            dd.krate
                                        ))
                                        .with_label(Label::primary(self.cfg.file_id, allow.span)),
                                    Code::AdvisoryIgnoreDisallowedDependent,
                                ));
                            }
                        }

                        if pack.len() > before {
                            break 'll LintLevel::Deny;
                        }
                    }

                    pack.push(diag(
                        Diagnostic::note()
                            .with_message("advisory ignored")
                            .with_labels(
                                ignore.to_labels(self.cfg.file_id, "advisory ignored here"),
                            ),
                        Code::AdvisoryIgnored,
                    ));

                    LintLevel::Allow
                } else {
                    LintLevel::Deny
                }
            };

            (lint_level.into(), adv_ty)
        };

        let mut notes = get_notes_from_advisory(md);

        if advisory.versions.patched.is_empty() {
            notes.push("Solution: No safe upgrade is available!".to_owned());
        } else {
            // Attempt to detect if any of the direct dependents have a version requirement that precludes updating to a patched version
            let updatable = 'u: {
                let Some(versions) = indices.and_then(|i| i.versions(krate)) else {
                    // We can't tell what versions are available, but maybe it will work out for the user
                    break 'u true;
                };

                let available: Vec<_> = versions
                    .iter()
                    .filter_map(|(v, yanked)| {
                        if *yanked {
                            return None;
                        }

                        (advisory.versions.patched.iter().any(|vr| vr.matches(v))
                            || advisory.versions.unaffected.iter().any(|vr| vr.matches(v)))
                        .then_some(v)
                    })
                    .collect();

                let incompatible: smallvec::SmallVec<[_; 4]> = direct_dependents
                    .iter()
                    .filter_map(|dd| {
                        let deps: smallvec::SmallVec<[_; 2]> = dd
                            .krate
                            .deps
                            .iter()
                            .filter(|dep| {
                                if dep.name != krate.name
                                    || !dep.req.matches(&krate.version)
                                    || dep
                                        .source
                                        .as_ref()
                                        .is_none_or(|src| !crate::Source::is_raw_crates_io(src))
                                {
                                    return false;
                                }

                                !available.iter().any(|av| dep.req.matches(av))
                            })
                            .collect();

                        (!deps.is_empty()).then_some((dd.krate, deps))
                    })
                    .collect();

                if incompatible.is_empty() {
                    break 'u true;
                }

                if incompatible.len() == 1 {
                    notes.push(
                        "1 dependent has version requirements that preclude updating:".to_owned(),
                    );
                } else {
                    notes.push(format!(
                        "{} dependents have version requirements that preclude updating:",
                        incompatible.len()
                    ));
                }

                for (dependent, deps) in incompatible {
                    notes.push(format!("{dependent}"));

                    for dep in deps {
                        let mut s = format!(
                            "  - {} = '{}'",
                            dep.rename.as_deref().unwrap_or(&dep.name),
                            dep.req,
                        );
                        match dep.kind {
                            krates::cm::DependencyKind::Normal => {}
                            krates::cm::DependencyKind::Development => s.push_str(" (dev)"),
                            krates::cm::DependencyKind::Build => s.push_str(" (build)"),
                        }
                        notes.push(s);
                    }
                }

                false
            };

            if updatable {
                let mut patched = String::with_capacity(
                    advisory.versions.patched.len() * 9 + advisory.versions.patched.len() - 4,
                );

                for (i, req) in advisory.versions.patched.iter().enumerate() {
                    if i > 0 {
                        patched.push_str(" OR ");
                    }

                    use std::fmt::Write;
                    write!(&mut patched, "{req}").expect("unreachable unless OOM");
                }

                notes.push(format!(
                    "Solution: Upgrade to {patched} (try `cargo update -p {}`)",
                    krate.name,
                ));
            }
        }

        let (message, code) = match ty {
            AdvisoryType::Vulnerability => ("security vulnerability detected", Code::Vulnerability),
            AdvisoryType::Notice => ("notice advisory detected", Code::Notice),
            AdvisoryType::Unmaintained => ("unmaintained advisory detected", Code::Unmaintained),
            AdvisoryType::Unsound => ("unsound advisory detected", Code::Unsound),
        };

        let diag = pack.push(diag(
            Diagnostic::new(severity)
                .with_message(md.title)
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

        match serialize_advisories {
            crate::SerializeAdvisory::No => {}
            crate::SerializeAdvisory::Json => diag.advisory = Some(advisory.to_json()),
            crate::SerializeAdvisory::Sarif => diag.advisory = Some(advisory.to_sarif()),
        }

        pack
    }

    pub(crate) fn diag_for_allowed_missing(
        &self,
        ignore: Option<&IgnoreId>,
        dds: Vec<krates::DirectDependent<'_, crate::Krate>>,
    ) -> Pack {
        let mut pack = Pack::new(Check::Advisories);

        if let Some(ignore) = ignore
            && let Some(allowed) = &ignore.allow
            && !dds.is_empty()
        {
            // Inform the user if they've allowed a direct dependency that doesn't/no longer exist/s
            for allow in &allowed.value {
                if !dds
                    .iter()
                    .any(|dd| crate::match_krate(dd.krate, &allow.spec))
                {
                    pack.push(diag(
                        Diagnostic::warning()
                            .with_message("direct dependency not found")
                            .with_label(Label::primary(self.cfg.file_id, allow.spec.name.span)),
                        Code::AdvisoryIgnoreAllowedDependentMissing,
                    ));
                }
            }
        }

        pack
    }

    pub(crate) fn diag_for_yanked(
        &self,
        krate: &crate::Krate,
        direct_dependents: Vec<krates::DirectDependent<'ctx, crate::Krate>>,
        indices: Option<&super::Indices<'_>>,
    ) -> Pack {
        let mut pack = Pack::with_kid(Check::Advisories, krate.id.clone());

        let mut notes = Vec::new();

        if let Some(versions) = indices.and_then(|i| i.versions(krate))
            && let Some(ksrc) = &krate.source
        {
            let incompatible: smallvec::SmallVec<[_; 4]> = direct_dependents
                .iter()
                .filter_map(|dd| {
                    let deps: smallvec::SmallVec<[_; 2]> = dd
                        .krate
                        .deps
                        .iter()
                        .filter(|dep| {
                            if dep.name != krate.name
                                || !dep.req.matches(&krate.version)
                                || dep.source.as_ref().is_none_or(|src| !ksrc.matches_raw(src))
                            {
                                return false;
                            }

                            !versions
                                .iter()
                                .any(|(av, yanked)| !*yanked && dep.req.matches(av))
                        })
                        .collect();

                    (!deps.is_empty()).then_some((dd.krate, deps))
                })
                .collect();

            if !incompatible.is_empty() {
                if incompatible.len() == 1 {
                    notes.push(
                        "1 dependent has version requirements that preclude updating:".to_owned(),
                    );
                } else {
                    notes.push(format!(
                        "{} dependents have version requirements that preclude updating:",
                        incompatible.len()
                    ));
                }

                for (dependent, deps) in incompatible {
                    notes.push(format!("{dependent}"));

                    for dep in deps {
                        let mut s = format!(
                            "  - {} = '{}'",
                            dep.rename.as_deref().unwrap_or(&dep.name),
                            dep.req,
                        );
                        match dep.kind {
                            krates::cm::DependencyKind::Normal => {}
                            krates::cm::DependencyKind::Development => s.push_str(" (dev)"),
                            krates::cm::DependencyKind::Build => s.push_str(" (build)"),
                        }
                        notes.push(s);
                    }
                }
            }
        }

        pack.push(diag(
            Diagnostic::new(self.cfg.yanked.value.into())
                .with_message(if notes.is_empty() {
                    format!(
                        "detected yanked crate (try `cargo update -p {}`)",
                        krate.name
                    )
                } else {
                    format!(
                        "detected yanked crate (`cargo update -p {}` will most likely not work)",
                        krate.name
                    )
                })
                .with_labels(vec![
                    Label::primary(
                        self.krate_spans.lock_id,
                        self.krate_spans.lock_span(&krate.id).total,
                    )
                    .with_message("yanked version"),
                ])
                .with_notes(notes),
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
