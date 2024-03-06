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

use crate::{
    diag::{CfgCoord, Check, Diagnostic, Label, Pack, Severity},
    LintLevel,
};
use cfg::BlanketAgreement;
pub use gather::{Gatherer, LicenseInfo, LicenseStore};
use gather::{KrateLicense, LicenseExprInfo, LicenseExprSource, Summary};

pub use diags::Code;

use bitvec::prelude::*;

struct Hits {
    allowed: BitVec<usize, LocalBits>,
    exceptions: BitVec<usize, LocalBits>,
}

fn evaluate_expression(
    ctx: &crate::CheckCtx<'_, cfg::ValidConfig>,
    krate_lic_nfo: &KrateLicense<'_>,
    expr: &spdx::Expression,
    nfo: &LicenseExprInfo,
    hits: &mut Hits,
) -> Diagnostic {
    // TODO: If an expression with the same hash is encountered
    // just use the same result as a memoized one
    #[derive(Debug)]
    enum Reason {
        Denied,
        IsFsfFree,
        IsOsiApproved,
        IsBothFreeAndOsi,
        ExplicitAllowance,
        ExplicitException,
        IsCopyleft,
        Default,
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

    let mut warnings = 0;

    let cfg = &ctx.cfg;

    // Check to see if the crate matches an exception, which is additional to
    // the general allow list
    let exception_ind = cfg
        .exceptions
        .iter()
        .position(|exc| crate::match_krate(krate_lic_nfo.krate, &exc.spec));

    let eval_res = expr.evaluate_with_failures(|req| {
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

        // 2. Licenses explicitly denied are of course hard failures,
        // but failing one license in an expression is not necessarily
        // going to actually ban the crate, for example, the canonical
        // "Apache-2.0 OR MIT" used in by a lot crates means that
        // banning Apache-2.0, but allowing MIT, will allow the crate
        // to be used as you are upholding at least one license requirement
        for deny in &cfg.denied {
            if deny.0.value.satisfies(req) {
                deny!(Denied);
            }
        }

        // 3. A license that is specifically allowed will of course mean
        // that the requirement is met.
        for (i, allow) in cfg.allowed.iter().enumerate() {
            if allow.0.value.satisfies(req) {
                hits.allowed.as_mut_bitslice().set(i, true);
                allow!(ExplicitAllowance);
            }
        }

        if let Some(dep_cfg) = &cfg.deprecated {
            // 4. If the license isn't explicitly allowed, it still may
            // be allowed by the blanket "OSI Approved" or "FSF Free/Libre"
            // allowances
            if let spdx::LicenseItem::Spdx { id, .. } = req.license {
                if id.is_copyleft() {
                    match dep_cfg.copyleft {
                        LintLevel::Allow => {
                            allow!(IsCopyleft);
                        }
                        LintLevel::Warn => {
                            warnings += 1;
                            allow!(IsCopyleft);
                        }
                        LintLevel::Deny => {
                            deny!(IsCopyleft);
                        }
                    }
                }

                match dep_cfg.allow_osi_fsf_free {
                    BlanketAgreement::Neither => {}
                    BlanketAgreement::Either => {
                        if id.is_osi_approved() {
                            allow!(IsOsiApproved);
                        } else if id.is_fsf_free_libre() {
                            allow!(IsFsfFree);
                        }
                    }
                    BlanketAgreement::Both => {
                        if id.is_fsf_free_libre() && id.is_osi_approved() {
                            allow!(IsBothFreeAndOsi);
                        }
                    }
                    BlanketAgreement::Osi => {
                        if id.is_osi_approved() {
                            allow!(IsOsiApproved);
                        }
                    }
                    BlanketAgreement::Fsf => {
                        if id.is_fsf_free_libre() {
                            allow!(IsFsfFree);
                        }
                    }
                    BlanketAgreement::OsiOnly => {
                        if id.is_osi_approved() {
                            if id.is_fsf_free_libre() {
                                deny!(IsFsfFree);
                            } else {
                                allow!(IsOsiApproved);
                            }
                        }
                    }
                    BlanketAgreement::FsfOnly => {
                        if id.is_fsf_free_libre() {
                            if id.is_osi_approved() {
                                deny!(IsOsiApproved);
                            } else {
                                allow!(IsFsfFree);
                            }
                        }
                    }
                }
            }

            // 5. Whelp, this license just won't do!
            match dep_cfg.default {
                LintLevel::Deny => {
                    deny!(Default);
                }
                LintLevel::Warn => {
                    warnings += 1;
                    allow!(Default);
                }
                LintLevel::Allow => {
                    allow!(Default);
                }
            }
        } else {
            deny!(NotExplicitlyAllowed);
        }
    });

    let (message, severity) = match eval_res {
        Err(_) => ("failed to satisfy license requirements", Severity::Error),
        Ok(_) => (
            "license requirements satisfied",
            if warnings > 0 {
                Severity::Warning
            } else {
                Severity::Help
            },
        ),
    };

    let mut labels = Vec::with_capacity(reasons.len() + 1);
    labels.extend(krate_lic_nfo.labels.clone());

    labels.push(
        Label::secondary(nfo.file_id, nfo.offset..nfo.offset + expr.as_ref().len()).with_message(
            format!(
                "license expression retrieved via {}",
                match &nfo.source {
                    LicenseExprSource::Metadata => "Cargo.toml `license`".to_owned(),
                    LicenseExprSource::UserOverride => "user override".to_owned(),
                    LicenseExprSource::LicenseFiles(lfs) => lfs.join(", "),
                    LicenseExprSource::OverlayOverride => unreachable!(),
                }
            ),
        ),
    );

    let mut notes = krate_lic_nfo.notes.clone();

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
                // This would only happen if askalono used a newer license list than spdx, but we update
                // both simultaneously
                notes.push(format!("{} is not an SPDX license", failed_req.req));
            }
        }

        labels.push(
            Label::primary(
                nfo.file_id,
                nfo.offset + failed_req.span.start as usize
                    ..nfo.offset + failed_req.span.end as usize,
            )
            .with_message(format!(
                "{}: {}",
                if accepted { "accepted" } else { "rejected" },
                match reason {
                    Reason::Denied => "explicitly denied",
                    Reason::IsFsfFree =>
                        "license is FSF approved https://www.gnu.org/licenses/license-list.en.html",
                    Reason::IsOsiApproved =>
                        "license is OSI approved https://opensource.org/licenses",
                    Reason::ExplicitAllowance => "license is explicitly allowed",
                    Reason::ExplicitException => "license is explicitly allowed via an exception",
                    Reason::NotExplicitlyAllowed => "license was not explicitly allowed",
                    Reason::IsBothFreeAndOsi => "license is FSF AND OSI approved",
                    Reason::IsCopyleft => "license is considered copyleft",
                    Reason::Default => {
                        match cfg
                            .deprecated
                            .as_ref()
                            .map_or(LintLevel::Deny, |d| d.default)
                        {
                            LintLevel::Deny => "not explicitly allowed",
                            LintLevel::Warn => "warned by default",
                            LintLevel::Allow => "allowed by default",
                        }
                    }
                }
            )),
        );
    }

    Diagnostic::new(severity)
        .with_message(message)
        .with_code(if severity != Severity::Error {
            diags::Code::Accepted
        } else {
            diags::Code::Rejected
        })
        .with_labels(labels)
        .with_notes(notes)
}

pub fn check(
    ctx: crate::CheckCtx<'_, cfg::ValidConfig>,
    summary: Summary<'_>,
    mut sink: crate::diag::ErrorSink,
) {
    let mut hits = Hits {
        allowed: BitVec::repeat(false, ctx.cfg.allowed.len()),
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

        // If the user has set this, check if it's a private workspace
        // crate or a crate from a private registry and just print out
        // a help message that we skipped it
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

        match &krate_lic_nfo.lic_info {
            LicenseInfo::SpdxExpression { expr, nfo } => {
                pack.push(evaluate_expression(
                    &ctx,
                    &krate_lic_nfo,
                    expr,
                    nfo,
                    &mut hits,
                ));
            }
            LicenseInfo::Unlicensed => {
                let severity = match ctx
                    .cfg
                    .deprecated
                    .as_ref()
                    .map_or(LintLevel::Deny, |d| d.unlicensed)
                {
                    LintLevel::Allow => Severity::Note,
                    LintLevel::Warn => Severity::Warning,
                    LintLevel::Deny => Severity::Error,
                };

                pack.push(diags::Unlicensed {
                    krate: krate_lic_nfo.krate,
                    severity,
                    breadcrumbs: krate_lic_nfo.labels.into_iter().collect(),
                });
            }
        }

        if !pack.is_empty() {
            sink.push(pack);
        }
    }

    {
        let mut pack = Pack::new(Check::Licenses);

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

        if !pack.is_empty() {
            sink.push(pack);
        }
    }
}
