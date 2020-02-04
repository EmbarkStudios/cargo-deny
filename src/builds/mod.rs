mod cfg;
pub use cfg::{Config, ValidConfig};

use crate::diag::{Diagnostic, Label, Pack, Severity};
use crate::LintLevel;

pub fn check(
    ctx: crate::CheckCtx<'_, ValidConfig>,
    sender: crossbeam::channel::Sender<crate::diag::Pack>,
) {
    // early out if everything is allowed
    if ctx.cfg.custom_builds == LintLevel::Allow && ctx.cfg.proc_macros == LintLevel::Allow {
        return;
    }

    // scan through each crate and check the source of it

    for (i, krate) in ctx.krates.krates().map(|kn| &kn.krate).enumerate() {
        for target in &krate.targets {
            let has_custom_build = target.kind.iter().any(|k| k == "custom-build");
            let has_proc_macro = target.kind.iter().any(|k| k == "proc-macro");

            if has_custom_build || has_proc_macro {
                let lint_level = if has_custom_build {
                    ctx.cfg.custom_builds
                } else {
                    ctx.cfg.proc_macros
                };

                let mut pack = Pack::with_kid(krate.id.clone());
                pack.push(Diagnostic::new(
                    match lint_level {
                        LintLevel::Warn => Severity::Warning,
                        LintLevel::Deny => Severity::Error,
                        LintLevel::Allow => Severity::Note,
                    },
                    format!(
                        "detected crate {}: {} = {}\nsource: \"{}\"",
                        if has_custom_build {
                            "using custom build.rs"
                        } else {
                            "using proc macro"
                        },
                        krate.name,
                        krate.version,
                        target.src_path.display()
                    ),
                    Label::new(ctx.spans_id, ctx.krate_spans[i].clone(), "crate"),
                ));
                sender.send(pack).unwrap();
            }
        }
    }
}
