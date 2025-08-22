pub mod cfg;
pub(crate) mod diags;
mod helpers;

use crate::{LintLevel, diag};
pub use diags::Code;
pub use helpers::{
    db::{AdvisoryDb, DbSet, Fetch, Id, Report},
    index::{Entry, Indices},
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
            } else {
                Vec::new()
            }
        },
    );

    use bitvec::prelude::*;
    let mut ignore_hits: BitVec = BitVec::repeat(false, ctx.cfg.ignore.len());
    let mut ignore_yanked_hits: BitVec = BitVec::repeat(false, ctx.cfg.ignore_yanked.len());

    use crate::cfg::Scope;
    let ws_set = if matches!(
        ctx.cfg.unmaintained.value,
        Scope::Workspace | Scope::Transitive
    ) {
        ctx.krates
            .workspace_members()
            .filter_map(|wm| {
                if let krates::Node::Krate { id, .. } = wm {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<std::collections::BTreeSet<_>>()
    } else {
        Default::default()
    };

    // Emit diagnostics for any advisories found that matched crates in the graph
    'lup: for (krate, advisory) in &report.advisories {
        'block: {
            if advisory
                .metadata
                .informational
                .as_ref()
                .is_some_and(|info| info.is_unmaintained())
            {
                match ctx.cfg.unmaintained.value {
                    Scope::All => break 'block,
                    Scope::None => continue 'lup,
                    Scope::Workspace | Scope::Transitive => {
                        let nid = ctx.krates.nid_for_kid(&krate.id).unwrap();
                        let dds = ctx.krates.direct_dependents(nid);

                        let transitive = ctx.cfg.unmaintained.value == Scope::Transitive;
                        if dds
                            .iter()
                            .any(|dd| ws_set.contains(&dd.krate.id) ^ transitive)
                        {
                            break 'block;
                        }

                        continue 'lup;
                    }
                }
            }
        }

        let diag = ctx.diag_for_advisory(krate, advisory, |index| {
            ignore_hits.as_mut_bitslice().set(index, true);
        });

        sink.push(diag);
    }

    for (krate, status) in yanked {
        if let Some(e) = status {
            if ctx.cfg.yanked.value != LintLevel::Allow {
                sink.push(ctx.diag_for_index_failure(krate, e));
            }
        } else {
            // Check to see if the user has added an ignore for the yanked
            // crate, eg. see https://github.com/EmbarkStudios/cargo-deny/issues/579
            // this should be extremely rare and very temporary as in most cases
            // a new semver compatible version of the yanked version is published
            // around the same time as a yank occurs
            if let Some(i) = ctx
                .cfg
                .ignore_yanked
                .iter()
                .position(|iy| crate::match_krate(krate, &iy.spec))
            {
                sink.push(ctx.diag_for_yanked_ignore(krate, i));
                ignore_yanked_hits.as_mut_bitslice().set(i, true);
            } else {
                sink.push(ctx.diag_for_yanked(krate));
            }
        }
    }

    // Check for advisory identifiers that were set to be ignored, but
    // are not actually in any database.
    for ignored in &ctx.cfg.ignore {
        if !advisory_dbs.has_advisory(&ignored.id.value) {
            sink.push(ctx.diag_for_unknown_advisory(ignored));
        }
    }

    // Check for advisory identifiers that were set to be ignored, but
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

    for ignore in ignore_yanked_hits
        .into_iter()
        .zip(ctx.cfg.ignore_yanked.iter())
        .filter_map(|(hit, ignore)| if !hit { Some(ignore) } else { None })
    {
        sink.push(ctx.diag_for_ignored_yanked_not_encountered(ignore));
    }

    if let Some(mut reporter) = audit_compatible_reporter {
        for ser_report in report.serialized_reports {
            reporter.report(ser_report);
        }
    }
}
