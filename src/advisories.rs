pub mod cfg;
mod diags;
mod helpers;

use crate::{diag, LintLevel};
pub use diags::Code;
pub use helpers::{
    db::{DbSet, Fetch, Report},
    index::Indices,
};

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
    audit_compatible_reporter: Option<R>,
    indices: Option<Indices<'_>>,
    sink: S,
) where
    R: AuditReporter,
    S: Into<diag::ErrorSink>,
{
    let mut sink = sink.into();
    let emit_audit_compatible_reports = audit_compatible_reporter.is_some();

    let (report, yanked) = rayon::join(
        || Report::generate(advisory_dbs, ctx.krates, emit_audit_compatible_reports),
        || {
            if let Some(indices) = indices {
            } else {
            }
            if ctx.cfg.disable_yank_checking {
                return Ok(Vec::new());
            }

            helpers::index::Indices::load(ctx.krates).map(|indices| {
                let yanked: Vec<_> = ctx
                    .krates
                    .krates()
                    .filter_map(|package| match indices.is_yanked(package) {
                        Ok(is_yanked) => {
                            if is_yanked {
                                Some((package, None))
                            } else {
                                None
                            }
                        }
                        Err(err) => Some((package, Some(err))),
                    })
                    .collect();

                yanked
            })
        },
    );

    use bitvec::prelude::*;
    let mut ignore_hits: BitVec = BitVec::repeat(false, ctx.cfg.ignore.len());

    // Emit diagnostics for any advisories found that matched crates in the graph
    for (krate, krate_index, advisory) in &report.advisories {
        let diag = ctx.diag_for_advisory(
            krate,
            *krate_index,
            &advisory.metadata,
            Some(&advisory.versions),
            |index| {
                ignore_hits.as_mut_bitslice().set(index, true);
            },
        );

        sink.push(diag);
    }

    match yanked {
        Ok(yanked) => {
            for (krate, status) in yanked {
                let Some(ind) = ctx.krates.nid_for_kid(&krate.id) else { log::warn!("failed to locate node id for '{krate}'"); continue };

                if let Some(e) = status {
                    if ctx.cfg.yanked.value != LintLevel::Allow {
                        sink.push(ctx.diag_for_index_failure(krate, ind, e));
                    }
                } else {
                    sink.push(ctx.diag_for_yanked(krate, ind));
                }
            }
        }
        Err(err) => {
            sink.push(ctx.diag_for_index_load_failure(err));
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
