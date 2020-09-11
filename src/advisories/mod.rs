pub mod cfg;
#[cfg(feature = "fix")]
pub mod fix;
mod helpers;

use crate::{
    diag::{self, Check, Diagnostic, Label, Severity},
    LintLevel,
};
use helpers::*;
pub use helpers::{load_lockfile, DbSet, Fetch, PrunedLockfile, Report};

pub trait AuditReporter {
    fn report(&mut self, report: serde_json::Value);
}

/// For when you just want to satisfy AuditReporter without doing anything
pub struct NoneReporter;
impl AuditReporter for NoneReporter {
    fn report(&mut self, _report: serde_json::Value) {}
}

impl<F> AuditReporter for F
where
    F: FnMut(serde_json::Value),
{
    fn report(&mut self, report: serde_json::Value) {
        self(report)
    }
}

/// Check crates against the advisory database to detect vulnerabilities or
/// unmaintained crates
pub fn check<R>(
    ctx: crate::CheckCtx<'_, cfg::ValidConfig>,
    advisory_dbs: &DbSet,
    lockfile: PrunedLockfile,
    audit_compatible_reporter: Option<R>,
    sender: crossbeam::channel::Sender<diag::Pack>,
) where
    R: AuditReporter,
{
    use rustsec::{
        advisory::{informational::Informational, metadata::Metadata},
        package::Package,
    };

    let emit_audit_compatible_reports = audit_compatible_reporter.is_some();

    let (report, yanked) = rayon::join(
        || Report::generate(advisory_dbs, &lockfile, emit_audit_compatible_reports),
        || {
            let index = rustsec::registry::Index::open()?;
            let mut yanked = Vec::new();

            for package in &lockfile.0.packages {
                if let Ok(index_entry) = index.find(&package.name, &package.version) {
                    if index_entry.is_yanked {
                        yanked.push(package);
                    }
                }
            }

            Ok(yanked)
        },
    );

    // rust is having trouble doing type inference
    let yanked: Result<_, rustsec::Error> = yanked;

    use bitvec::prelude::*;
    let mut ignore_hits = bitvec![0; ctx.cfg.ignore.len()];

    let mut make_diag = |pkg: &Package, advisory: &Metadata| -> diag::Pack {
        match krate_for_pkg(&ctx.krates, pkg) {
            Some((i, krate)) => {
                let id = &advisory.id;

                let (severity, message) = {
                    let (lint_level, msg) = match &advisory.informational {
                        // Everything that isn't an informational advisory is a vulnerability
                        None => (
                            ctx.cfg.vulnerability,
                            "security vulnerability detected".to_owned(),
                        ),
                        Some(info) => match info {
                            // Security notices for a crate which are published on https://rustsec.org
                            // but don't represent a vulnerability in a crate itself.
                            Informational::Notice => {
                                (ctx.cfg.notice, "notice advisory detected".to_owned())
                            }
                            // Crate is unmaintained / abandoned
                            Informational::Unmaintained => (
                                ctx.cfg.unmaintained,
                                "unmaintained advisory detected".to_owned(),
                            ),
                            Informational::Unsound => {
                                (ctx.cfg.unsound, "unsound advisory detected".to_owned())
                            }
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
                    let lint_level =
                        if let Ok(index) = ctx.cfg.ignore.binary_search_by(|i| i.value.cmp(id)) {
                            ignore_hits.as_mut_bitslice().set(index, true);
                            LintLevel::Allow
                        } else if let Some(severity_threshold) = ctx.cfg.severity_threshold {
                            if let Some(advisory_severity) =
                                advisory.cvss.as_ref().map(|cvss| cvss.severity())
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

                let notes = {
                    let mut n = Vec::new();

                    n.push(advisory.description.clone());

                    if let Some(ref url) = advisory.url {
                        n.push(format!("URL: {}", url));
                    }

                    n
                };

                let mut pack = diag::Pack::with_kid(Check::Advisories, krate.id.clone());
                let diag = pack.push(
                    Diagnostic::new(severity)
                        .with_message(advisory.title.clone())
                        .with_labels(vec![ctx.label_for_span(i.index(), message)])
                        .with_code(id.as_str().to_owned())
                        .with_notes(notes),
                );

                if ctx.serialize_extra {
                    diag.extra = serde_json::to_value(&advisory)
                        .ok()
                        .map(|v| ("advisory", v));
                }

                pack
            }
            None => {
                unreachable!(
                    "the advisory database report contained an advisory 
                    that somehow matched a crate we don't know about:\n{:#?}",
                    advisory
                );
            }
        }
    };

    // Emit diagnostics for any vulnerabilities that were found
    for vuln in &report.vulnerabilities {
        sender
            .send(make_diag(&vuln.package, &vuln.advisory))
            .unwrap();
    }

    // Emit diagnostics for informational advisories for crates, including unmaintained and unsound
    for (warning, advisory) in report
        .iter_warnings()
        .filter_map(|(_, wi)| wi.advisory.as_ref().map(|wia| (wi, wia)))
    {
        sender.send(make_diag(&warning.package, &advisory)).unwrap();
    }

    match yanked {
        Ok(yanked) => {
            for pkg in yanked {
                let diag = match krate_for_pkg(&ctx.krates, &pkg) {
                    Some((ind, krate)) => {
                        let mut pack = diag::Pack::with_kid(Check::Advisories, krate.id.clone());
                        pack.push(
                            Diagnostic::new(match ctx.cfg.yanked.value {
                                LintLevel::Allow => Severity::Help,
                                LintLevel::Deny => Severity::Error,
                                LintLevel::Warn => Severity::Warning,
                            })
                            .with_message("detected yanked crate")
                            .with_labels(vec![ctx.label_for_span(ind.index(), "yanked version")]),
                        );

                        pack
                    }
                    None => unreachable!(
                        "the advisory database warned about yanked crate that we don't have: {:#?}",
                        pkg
                    ),
                };

                sender.send(diag).unwrap();
            }
        }
        Err(e) => {
            if ctx.cfg.yanked.value != LintLevel::Allow {
                let mut diag = diag::Pack::new(Check::Advisories);
                diag.push(
                    Diagnostic::warning()
                        .with_message(format!("unable to check for yanked crates: {}", e))
                        .with_labels(vec![Label::primary(ctx.cfg.file_id, ctx.cfg.yanked.span)
                            .with_message("lint level defined here")]),
                );
                sender.send(diag).unwrap();
            }
        }
    }

    // Check for advisory identifers that were set to be ignored, but
    // are not actually in any database. Warn the user about.
    for (ignored, mut ignored_hit) in ctx.cfg.ignore.iter().zip(ignore_hits.iter_mut()) {
        if advisory_dbs.get(&ignored.value).is_none() {
            sender
                .send(
                    (
                        Check::Advisories,
                        Diagnostic::warning()
                            .with_message("this advisory is not in any RustSec database")
                            .with_labels(vec![Label::primary(
                                ctx.cfg.file_id,
                                ignored.span.clone(),
                            )
                            .with_message("unknown advisory")]),
                    )
                        .into(),
                )
                .unwrap();
            // Set advisory as used. Otherwise we would get two warings for the same advisory.
            *ignored_hit = true;
        }
    }

    // Check for advisory identifers that were set to be ignored, but
    // were not actually encountered, for cases where a crate, or specific
    // verison of that crate, has been removed or replaced and the advisory
    // no longer applies to it so that users can cleanup their configuration
    for ignore in ignore_hits
        .into_iter()
        .zip(ctx.cfg.ignore.into_iter())
        .filter_map(|(hit, ignore)| if !hit { Some(ignore) } else { None })
    {
        sender
            .send(
                (
                    Check::Advisories,
                    Diagnostic::warning()
                        .with_message("advisory was not encountered")
                        .with_labels(vec![Label::primary(ctx.cfg.file_id, ignore.span)
                            .with_message("no crate matched advisory criteria")]),
                )
                    .into(),
            )
            .unwrap();
    }

    if let Some(mut reporter) = audit_compatible_reporter {
        for ser_report in report.serialized_reports {
            reporter.report(ser_report);
        }
    }
}
