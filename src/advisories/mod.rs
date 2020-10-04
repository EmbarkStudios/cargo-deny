pub mod cfg;
mod diags;
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
    mut sink: diag::ErrorSink,
) where
    R: AuditReporter,
{
    use rustsec::{advisory::metadata::Metadata, package::Package};

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

    let mut send_diag = |pkg: &Package, advisory: &Metadata| match krate_for_pkg(&ctx.krates, pkg) {
        Some((i, krate)) => {
            let diag = ctx.diag_for_advisory(krate, i, advisory, |index| {
                ignore_hits.as_mut_bitslice().set(index, true)
            });

            sink.push(diag);
        }
        None => {
            unreachable!(
                "the advisory database report contained an advisory 
                    that somehow matched a crate we don't know about:\n{:#?}",
                advisory
            );
        }
    };

    // Emit diagnostics for any vulnerabilities that were found
    for vuln in &report.vulnerabilities {
        send_diag(&vuln.package, &vuln.advisory);
    }

    // Emit diagnostics for informational advisories for crates, including unmaintained and unsound
    for (warning, advisory) in report
        .iter_warnings()
        .filter_map(|(_, wi)| wi.advisory.as_ref().map(|wia| (wi, wia)))
    {
        send_diag(&warning.package, &advisory);
    }

    match yanked {
        Ok(yanked) => {
            for pkg in yanked {
                match krate_for_pkg(&ctx.krates, &pkg) {
                    Some((ind, krate)) => {
                        sink.push(ctx.diag_for_yanked(krate, ind));
                    }
                    None => unreachable!(
                        "the advisory database warned about yanked crate that we don't have: {:#?}",
                        pkg
                    ),
                };
            }
        }
        Err(e) => {
            if ctx.cfg.yanked.value != LintLevel::Allow {
                sink.push(ctx.diag_for_index_failure(e));
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
    // version of that crate, has been removed or replaced and the advisory
    // no longer applies to it, so that users can cleanup their configuration
    for ignore in ignore_hits
        .into_iter()
        .zip(ctx.cfg.ignore.iter())
        .filter_map(|(hit, ignore)| if !hit { Some(ignore) } else { None })
    {
        sink.push(ctx.diag_for_advisory_not_encountered(ignore));
    }

    if let Some(mut reporter) = audit_compatible_reporter {
        for ser_report in report.serialized_reports {
            reporter.report(ser_report);
        }
    }
}
