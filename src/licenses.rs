//! ## `cargo deny check licenses`
//!
//! One important aspect that one must always keep in mind when using code from
//! other people is what the licensing of that code is and whether it fits the
//! requirements of your project. Luckily, most of the crates in the Rust
//! ecosystem tend to follow the example set forth by Rust itself, namely
//! dual-license `MIT OR Apache-2.0`, but of course, that is not always the case.
//!
//! `cargo-deny` allows you to ensure that all of your dependencies have license
//! requirements that are satisfied by the licenses you choose to use for your
//! project, and notifies you via warnings or errors if the license requirements
//! for any crate aren't compatible with your configuration.

/// Configuration for license checking
pub mod cfg;
mod diags;
mod gather;

use crate::diag::{CfgCoord, Check, Diagnostic, Label, Pack, Severity};
pub use gather::{Gatherer, LicenseInfo, LicenseStore, Summary};
use gather::{KrateLicense, LicenseExprInfo, LicenseExprSource};

pub use diags::Code;

use bitvec::prelude::*;

struct Hits {
    allowed: BitVec<usize, LocalBits>,
    allowed_expressions: BitVec<usize, LocalBits>,
    exceptions: BitVec<usize, LocalBits>,
}

/// Returns true iff `allow_expr` covers `dep_expr`.
///
/// Coverage means every interpretation of `allow_expr` (every subset of its
/// requirements that satisfies the expression) also satisfies `dep_expr`.
/// This is the "for all licensing choices my project commits to offering, the
/// dependency must remain usable" semantics requested in #827, and is
/// strictly stronger than "any allow licensee satisfies any dep requirement."
///
/// Concretely, allow `GPL-2.0-only OR GPL-3.0-only` covers a dep licensed
/// `GPL-2.0-only OR GPL-3.0-only` (both disjuncts have a satisfying choice in
/// the dep), but does **not** cover a dep licensed `GPL-2.0-only` alone (the
/// `GPL-3.0-only` disjunct of the allow has no satisfying choice in the dep).
fn compound_allow_covers_dep(allow_expr: &spdx::Expression, dep_expr: &spdx::Expression) -> bool {
    let allow_reqs: Vec<&spdx::LicenseReq> = allow_expr.requirements().map(|er| &er.req).collect();
    let n = allow_reqs.len();

    // Bail on absurdly large allow expressions; the enumeration is 2^n so we
    // cap n to keep the worst case bounded.  16 is comfortably above what any
    // realistic license expression would reach.
    if n > 16 {
        return false;
    }

    let satisfies_in_world = |granted: &[&spdx::LicenseReq], req: &spdx::LicenseReq| -> bool {
        granted.iter().any(|g| {
            let licensee = spdx::Licensee::new(g.license.clone(), g.addition.clone());
            licensee.satisfies(req)
        })
    };

    let total = 1u32 << n;
    for mask in 0u32..total {
        let granted: Vec<&spdx::LicenseReq> = (0..n)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| allow_reqs[i])
            .collect();

        if !allow_expr.evaluate(|req| satisfies_in_world(&granted, req)) {
            continue;
        }

        if !dep_expr.evaluate(|req| satisfies_in_world(&granted, req)) {
            return false;
        }
    }

    true
}

fn evaluate_expression(
    ctx: &crate::CheckCtx<'_, cfg::ValidConfig>,
    krate: &crate::Krate,
    mut notes: Vec<String>,
    expr: &spdx::Expression,
    nfo: &LicenseExprInfo,
    hits: &mut Hits,
) -> crate::diag::Diag {
    // TODO: If an expression with the same hash is encountered
    // just use the same result as a memoized one
    #[derive(Debug)]
    enum Reason {
        ExplicitAllowance,
        ExplicitAllowanceCompound,
        ExplicitException,
        NotExplicitlyAllowed,
    }

    let mut reasons = smallvec::SmallVec::<[(Reason, bool); 8]>::new();

    macro_rules! deny {
        ($reason:ident) => {
            reasons.push((Reason::$reason, false));
            return false;
        };
    }

    macro_rules! allow {
        ($reason:ident) => {
            reasons.push((Reason::$reason, true));
            return true;
        };
    }

    let cfg = &ctx.cfg;

    // Check to see if the crate matches an exception, which is additional to
    // the general allow list
    let exception_ind = cfg
        .exceptions
        .iter()
        .position(|exc| crate::match_krate(krate, &exc.spec));

    // Compound allow expressions are checked before the per-requirement
    // eval, since the matching semantics are over the whole dep expression
    // rather than a single requirement.  See `compound_allow_covers_dep`.
    let compound_hit = cfg
        .allowed_expressions
        .iter()
        .enumerate()
        .find(|(_, allow_expr)| compound_allow_covers_dep(&allow_expr.value, expr));

    if let Some((i, _)) = compound_hit {
        hits.allowed_expressions.as_mut_bitslice().set(i, true);
        reasons.push((Reason::ExplicitAllowanceCompound, true));
    }

    let eval_res = if compound_hit.is_some() {
        Ok(())
    } else {
        expr.evaluate_with_failures(|req| {
            // 1. Exceptions are additional per-crate licenses that aren't blanket
            // allowed by all crates, note that we check these before denials so you
            // can allow an exception
            if let Some(ind) = exception_ind {
                let exception = &cfg.exceptions[ind];
                for allow in &exception.allowed {
                    if allow.0.value.satisfies(req) {
                        // Note that hit the exception
                        hits.exceptions.as_mut_bitslice().set(ind, true);
                        allow!(ExplicitException);
                    }
                }
            }

            // 2. A license that is specifically allowed will of course mean
            // that the requirement is met.
            for (i, allow) in cfg.allowed.iter().enumerate() {
                if allow.0.value.satisfies(req) {
                    hits.allowed.as_mut_bitslice().set(i, true);
                    allow!(ExplicitAllowance);
                }
            }

            deny!(NotExplicitlyAllowed);
        })
    };

    let (message, severity) = match eval_res {
        Err(_) => ("failed to satisfy license requirements", Severity::Error),
        Ok(_) => ("license requirements satisfied", Severity::Help),
    };

    let mut labels = Vec::with_capacity(reasons.len() + 1);

    let (lab, original_loc) = match &nfo.source {
        LicenseExprSource::Metadata(location) => {
            let lab = if let Some(loc) = location {
                Label::secondary(loc.0, loc.1.clone())
            } else {
                Label::secondary(nfo.file_id, nfo.offset..nfo.offset + expr.as_ref().len())
            };

            (lab, location.clone())
        }
        LicenseExprSource::UserOverride => (
            Label::secondary(nfo.file_id, nfo.offset..nfo.offset + expr.as_ref().len())
                .with_message("license expression retrieved via user override"),
            None,
        ),
        LicenseExprSource::LicenseFiles(lfs) => {
            let mut s = "license expression retrieved via license files: ".to_owned();

            for (i, lf) in lfs.iter().enumerate() {
                if i != 0 {
                    if lfs.len() == 2 {
                        s.push_str(" and ");
                    } else if lfs.len() > 2 && i == lfs.len() - 1 {
                        s.push_str(", and ");
                    } else {
                        s.push_str(", ");
                    }
                }

                s.push_str(lf);
            }
            (
                Label::secondary(nfo.file_id, nfo.offset..nfo.offset + expr.as_ref().len())
                    .with_message(s),
                None,
            )
        }
        LicenseExprSource::OverlayOverride => unreachable!(),
    };
    labels.push(lab);

    for ((reason, accepted), failed_req) in reasons.into_iter().zip(expr.requirements()) {
        if accepted && ctx.log_level < log::LevelFilter::Info {
            continue;
        }

        if !accepted && severity == Severity::Error {
            if let Some(id) = failed_req.req.license.id() {
                notes.push(format!("{} - {}:", id.name, id.full_name));

                let len = notes.len();

                if id.is_deprecated() {
                    notes.push("  - **DEPRECATED**".into());
                }

                if id.is_osi_approved() {
                    notes.push("  - OSI approved".into());
                }

                if id.is_fsf_free_libre() {
                    notes.push("  - FSF Free/Libre".into());
                }

                if id.is_copyleft() {
                    notes.push("  - Copyleft".into());
                }

                if len == notes.len() {
                    notes.push("  - No additional metadata available for license".into());
                }
            } else {
                // This would only happen if askalono used a newer license list
                // than spdx, but we update both simultaneously
                notes.push(format!("{} is not an SPDX license", failed_req.req));
            }
        }

        let (id, offset) = if let Some((file_id, range)) = &original_loc {
            (*file_id, range.start)
        } else {
            (nfo.file_id, nfo.offset)
        };

        let start = offset + failed_req.span.start as usize;

        // TODO: fix this in spdx, but we only get the span for the license, not the exception
        let end = if let Some(ai) = &failed_req.req.addition {
            failed_req.span.end as usize + 6 /*" WITH "*/ + match ai {
                spdx::AdditionItem::Spdx(exc) => exc.name.len(),
                spdx::AdditionItem::Other(other) => {
                    /*AdditionRef-*/ 12 + other.add_ref.len() + other.doc_ref.as_deref().map_or(0, |dr| {
                        /*DocumentRef-:*/ 13 + dr.len()
                    })
                }
            }
        } else {
            failed_req.span.end as usize
        };

        labels.push(
            Label::primary(id, start..offset + end).with_message(format_args!(
                "{}: {}",
                if accepted { "accepted" } else { "rejected" },
                match reason {
                    Reason::ExplicitAllowance => "license is explicitly allowed",
                    Reason::ExplicitAllowanceCompound => {
                        "license expression is allowed by a compound allow entry"
                    }
                    Reason::ExplicitException => "license is explicitly allowed via an exception",
                    Reason::NotExplicitlyAllowed => "license is not explicitly allowed",
                }
            )),
        );
    }

    crate::diag::Diag::new(
        Diagnostic::new(severity)
            .with_message(message)
            .with_labels(labels)
            .with_notes(notes),
        Some(crate::diag::DiagnosticCode::License(
            if severity != Severity::Error {
                diags::Code::Accepted
            } else {
                diags::Code::Rejected
            },
        )),
    )
}

pub fn check(
    ctx: crate::CheckCtx<'_, cfg::ValidConfig>,
    summary: Summary<'_>,
    mut sink: crate::diag::ErrorSink,
) {
    let mut hits = Hits {
        allowed: BitVec::repeat(false, ctx.cfg.allowed.len()),
        allowed_expressions: BitVec::repeat(false, ctx.cfg.allowed_expressions.len()),
        exceptions: BitVec::repeat(false, ctx.cfg.exceptions.len()),
    };

    let private_registries: Vec<_> = ctx
        .cfg
        .private
        .registries
        .iter()
        .map(|s| s.as_str())
        .collect();

    for krate_lic_nfo in summary.nfos {
        let mut pack = Pack::with_kid(Check::Licenses, krate_lic_nfo.krate.id.clone());

        // If the user has set this, check if it's a private workspace crate or
        // a crate from a private registry and just print out a help message
        // that we skipped it
        if ctx.cfg.private.ignore
            && (krate_lic_nfo.krate.is_private(&private_registries)
                || ctx
                    .cfg
                    .ignore_sources
                    .iter()
                    .any(|url| krate_lic_nfo.krate.matches_url(url, true)))
        {
            pack.push(diags::SkippedPrivateWorkspaceCrate {
                krate: krate_lic_nfo.krate,
            });
            sink.push(pack);
            continue;
        }

        let KrateLicense {
            krate,
            lic_info,
            notes,
            diags,
        } = krate_lic_nfo;

        for diag in diags {
            pack.push(diag);
        }

        match lic_info {
            LicenseInfo::SpdxExpression { expr, nfo } => {
                pack.push(evaluate_expression(
                    &ctx, krate, notes, &expr, &nfo, &mut hits,
                ));
            }
            LicenseInfo::Unlicensed => {
                pack.push(diags::Unlicensed {
                    krate,
                    severity: Severity::Error,
                });
            }
        }

        if !pack.is_empty() {
            sink.push(pack);
        }
    }

    {
        let mut pack = Pack::new(Check::Licenses);

        let severity = ctx.cfg.unused_license_exception.into();

        // Print out warnings for exceptions that pertain to crates that
        // weren't actually encountered
        for exc in hits
            .exceptions
            .into_iter()
            .zip(ctx.cfg.exceptions.into_iter())
            .filter_map(|(hit, exc)| if !hit { Some(exc) } else { None })
        {
            // Don't print warnings for exception overrides
            if exc.file_id != ctx.cfg.file_id {
                continue;
            }

            pack.push(diags::UnmatchedLicenseException {
                severity,
                license_exc_cfg: CfgCoord {
                    file: exc.file_id,
                    span: exc.spec.name.span,
                },
            });
        }

        if !pack.is_empty() {
            sink.push(pack);
        }
    }

    {
        let mut pack = Pack::new(Check::Licenses);

        // Print diagnostics for allowed licenses that weren't encountered.
        // Note that we don't do the same for denied licenses
        for allowed in hits
            .allowed
            .into_iter()
            .zip(ctx.cfg.allowed.into_iter())
            .filter_map(|(hit, allowed)| if !hit { Some(allowed) } else { None })
        {
            pack.push(diags::UnmatchedLicenseAllowance {
                severity: ctx.cfg.unused_allowed_license.into(),
                allowed_license_cfg: CfgCoord {
                    file: ctx.cfg.file_id,
                    span: allowed.0.span,
                },
            });
        }

        for allowed_expr in hits
            .allowed_expressions
            .into_iter()
            .zip(ctx.cfg.allowed_expressions.into_iter())
            .filter_map(|(hit, allowed)| if !hit { Some(allowed) } else { None })
        {
            pack.push(diags::UnmatchedLicenseAllowance {
                severity: ctx.cfg.unused_allowed_license.into(),
                allowed_license_cfg: CfgCoord {
                    file: ctx.cfg.file_id,
                    span: allowed_expr.span,
                },
            });
        }

        if !pack.is_empty() {
            sink.push(pack);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::compound_allow_covers_dep;

    fn parse(s: &str) -> spdx::Expression {
        spdx::Expression::parse(s).unwrap_or_else(|err| panic!("failed to parse '{s}': {err:?}"))
    }

    /// The motivating case from #827: a project licensed
    /// `GPL-2.0-only OR GPL-3.0-only` that allows the same compound
    /// expression must accept a dep with the same expression but reject a
    /// dep that constrains the project to only one of the disjuncts.
    #[test]
    fn compound_or_covers_same_compound() {
        let allow = parse("GPL-2.0-only OR GPL-3.0-only");
        let dep = parse("GPL-2.0-only OR GPL-3.0-only");
        assert!(compound_allow_covers_dep(&allow, &dep));
    }

    #[test]
    fn compound_or_does_not_cover_lone_disjunct() {
        let allow = parse("GPL-2.0-only OR GPL-3.0-only");
        let dep_2_only = parse("GPL-2.0-only");
        let dep_3_only = parse("GPL-3.0-only");
        assert!(!compound_allow_covers_dep(&allow, &dep_2_only));
        assert!(!compound_allow_covers_dep(&allow, &dep_3_only));
    }

    /// `GPL-2.0-or-later` is semantically a superset of `GPL-2.0-only` and
    /// `GPL-3.0-only`, so a dep licensed `GPL-2.0-or-later` ought to be
    /// covered.  The `spdx` crate's `Licensee::satisfies` does not relate
    /// the canonical-form identifiers `GPL-2.0-only` and `GPL-2.0-or-later`
    /// (it only handles version comparison through the legacy `+` syntax),
    /// so this case is not currently covered.  See the PR description for
    /// the limitation; lifting it is upstream spdx work.
    #[test]
    fn compound_or_does_not_yet_cover_or_later() {
        let allow = parse("GPL-2.0-only OR GPL-3.0-only");
        let dep = parse("GPL-2.0-or-later");
        assert!(!compound_allow_covers_dep(&allow, &dep));
    }

    /// A dep that requires both MIT and Apache-2.0 cannot be covered by an
    /// allow expression that doesn't include both.
    #[test]
    fn compound_or_does_not_cover_unrelated_and() {
        let allow = parse("GPL-2.0-only OR GPL-3.0-only");
        let dep = parse("MIT AND Apache-2.0");
        assert!(!compound_allow_covers_dep(&allow, &dep));
    }

    /// An allow expression with only AND requires the dep to satisfy each
    /// conjunct under the single granted world.
    #[test]
    fn compound_and_covers_dep_satisfied_by_each_conjunct() {
        let allow = parse("MIT AND Apache-2.0");
        let dep_either = parse("MIT OR Apache-2.0");
        // Granted world {MIT, Apache-2.0} satisfies allow.  Under that
        // world, dep `MIT OR Apache-2.0` is true, so dep is covered.
        assert!(compound_allow_covers_dep(&allow, &dep_either));
    }

    #[test]
    fn compound_single_licensee_covers_same() {
        let allow = parse("MIT");
        let dep = parse("MIT");
        assert!(compound_allow_covers_dep(&allow, &dep));
    }
}
