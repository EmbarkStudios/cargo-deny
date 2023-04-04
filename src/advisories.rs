pub mod cfg;
mod diags;
mod helpers;

use crate::{diag, LintLevel};
pub use diags::Code;
use helpers::*;
pub use helpers::{load_lockfile, DbSet, Fetch, PrunedLockfile, Report};

pub trait AuditReporter {
    fn report(&mut self, report: serde_json::Value);
}

/// For when you just want to satisfy `AuditReporter` without doing anything
pub struct NoneReporter;
impl AuditReporter for NoneReporter {
    fn report(&mut self, _report: serde_json::Value) {}
}

impl<F> AuditReporter for F
where
    F: FnMut(serde_json::Value),
{
    fn report(&mut self, report: serde_json::Value) {
        self(report);
    }
}

/// Check crates against the advisory database to detect vulnerabilities or
/// unmaintained crates
pub fn check<R, S>(
    ctx: crate::CheckCtx<'_, cfg::ValidConfig>,
    advisory_dbs: &DbSet,
    lockfile: PrunedLockfile,
    audit_compatible_reporter: Option<R>,
    sink: S,
) where
    R: AuditReporter,
    S: Into<diag::ErrorSink>,
{
    use rustsec::{advisory::Metadata, advisory::Versions, package::Package};

    let mut sink = sink.into();
    let emit_audit_compatible_reports = audit_compatible_reporter.is_some();

    let (report, yanked) = rayon::join(
        || Report::generate(advisory_dbs, &lockfile, emit_audit_compatible_reports),
        || {
            // TODO: Once rustsec fully supports non-crates.io sources we'll want
            // to also fetch those as well
            let git_index = crates_index::Index::new_cargo_default().ok();
            let http_index =
                crates_index::SparseIndex::from_url("sparse+https://index.crates.io/").ok();
            let mut yanked = Vec::new();

            for package in &lockfile.0.packages {
                // Ignore non-registry crates when checking, as a crate sourced
                // locally or via git can have the same name as a registry package
                if package.source.as_ref().map_or(true, |s| !s.is_registry()) {
                    continue;
                }

                let pkg_name = package.name.as_str();

                if let Some(krate) = http_index
                    .as_ref()
                    .and_then(|h| h.crate_from_cache(pkg_name).ok())
                    .or_else(|| git_index.as_ref().and_then(|g| g.crate_(pkg_name)))
                {
                    if krate
                        .versions()
                        .iter()
                        .any(|kv| kv.version() == package.version.to_string() && kv.is_yanked())
                    {
                        yanked.push(package);
                    }
                }
            }

            Ok(yanked)
        },
    );

    // rust is having trouble doing type inference
    let yanked: Result<_, anyhow::Error> = yanked;

    use bitvec::prelude::*;
    let mut ignore_hits: BitVec = BitVec::repeat(false, ctx.cfg.ignore.len());

    let mut send_diag =
        |pkg: &Package, advisory: &Metadata, versions: Option<&Versions>| match krate_for_pkg(
            ctx.krates, pkg,
        ) {
            Some((i, krate)) => {
                let diag = ctx.diag_for_advisory(krate, i, advisory, versions, |index| {
                    ignore_hits.as_mut_bitslice().set(index, true);
                });

                sink.push(diag);
            }
            None => {
                unreachable!(
                    "the advisory database report contained an advisory
                    that somehow matched a crate we don't know about:\n{advisory:#?}"
                );
            }
        };

    // Emit diagnostics for any vulnerabilities that were found
    for vuln in &report.vulnerabilities {
        send_diag(&vuln.package, &vuln.advisory, Some(&vuln.versions));
    }

    // Emit diagnostics for informational advisories for crates, including unmaintained and unsound
    for (warning, advisory) in report
        .iter_warnings()
        .filter_map(|(_, wi)| wi.advisory.as_ref().map(|wia| (wi, wia)))
    {
        send_diag(&warning.package, advisory, warning.versions.as_ref());
    }

    match yanked {
        Ok(yanked) => {
            for pkg in yanked {
                match krate_for_pkg(ctx.krates, pkg) {
                    Some((ind, krate)) => {
                        sink.push(ctx.diag_for_yanked(krate, ind));
                    }
                    None => unreachable!(
                        "the advisory database warned about yanked crate that we don't have: {pkg:#?}"
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
    // are not actually in any database.
    for ignored in &ctx.cfg.ignore {
        if !advisory_dbs.has_advisory(&ignored.value) {
            sink.push(ctx.diag_for_unknown_advisory(ignored));
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
