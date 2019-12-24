mod cfg;
pub use cfg::{Config, ValidConfig};

use crate::diag::{self, Diagnostic, Label, Pack, Severity};
use crate::LintLevel;

pub fn check(
    cfg: ValidConfig,
    krates: &crate::Krates,
    (krate_spans, spans_id): (&diag::KrateSpans, codespan::FileId),
    sender: crossbeam::channel::Sender<Pack>,
) {
    // early out if everything is allowed
    if cfg.custom_builds == LintLevel::Allow && cfg.proc_macros == LintLevel::Allow {
        return;
    }

    // scan through each crate and check the source of it

    for (i, krate) in krates.krates.iter().enumerate() {
        for target in &krate.targets {
            let has_custom_build = target.kind.iter().any(|k| k == "custom-build");
            let has_proc_macro = target.kind.iter().any(|k| k == "proc-macro");

            if has_custom_build || has_proc_macro {
                let lint_level = if has_custom_build {
                    cfg.custom_builds
                } else {
                    cfg.proc_macros
                };

                sender
                    .send(Pack {
                        krate_id: Some(krate.id.clone()),
                        diagnostics: vec![Diagnostic::new(
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
                            Label::new(spans_id, krate_spans[i].clone(), "crate"),
                        )],
                    })
                    .unwrap();
            }
        }
    }
}
