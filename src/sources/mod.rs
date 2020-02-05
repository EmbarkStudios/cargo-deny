mod cfg;
pub use cfg::{Config, ValidConfig};

use crate::{
    diag::{Diagnostic, Label, Pack, Severity},
    LintLevel,
};

pub fn check(ctx: crate::CheckCtx<'_, ValidConfig>, sender: crossbeam::channel::Sender<Pack>) {
    use bitvec::prelude::*;

    // early out if everything is allowed
    if ctx.cfg.unknown_registry == LintLevel::Allow && ctx.cfg.unknown_git == LintLevel::Allow {
        return;
    }

    // scan through each crate and check the source of it

    // keep track of which sources are actually encountered, so we can emit a
    // warning if the user has listed a source that no crates are actually using
    let mut source_hits = bitvec![0; ctx.cfg.allowed_sources.len()];

    for (i, krate) in ctx.krates.krates().map(|kn| &kn.krate).enumerate() {
        let source = match &krate.source {
            Some(source) => source,
            None => continue,
        };

        // get URL without git revision (query & fragment)
        // example URL in Cargo.lock: https://github.com/RustSec/rustsec-crate.git?rev=aaba369#aaba369bebc4fcfb9133b1379bcf430b707188a2
        // where we only want:        https://github.com/RustSec/rustsec-crate.git
        let source_url = {
            let mut url = source.url().clone();
            url.set_query(None);
            url.set_fragment(None);
            url
        };

        // get allowed list of sources to check

        let (lint_level, type_name) = if source.is_registry() {
            (ctx.cfg.unknown_registry, "registry")
        } else if source.is_git() {
            (ctx.cfg.unknown_git, "git")
        } else {
            continue;
        };

        // check if the source URL is list of allowed sources
        match ctx
            .cfg
            .allowed_sources
            .iter()
            .position(|src| src == &source_url)
        {
            Some(ind) => source_hits.as_mut_bitslice().set(ind, true),
            None => {
                let mut span = ctx.krate_spans[i].clone();

                // The krate span is the complete id, but we only want
                // to highlight the source component
                let last_space = krate.id.repr.rfind(' ').unwrap();

                span.start = span.start + last_space as u32 + 1;

                let mut pack = Pack::with_kid(krate.id.clone());
                pack.push(Diagnostic::new(
                    match lint_level {
                        LintLevel::Warn => Severity::Warning,
                        LintLevel::Deny => Severity::Error,
                        LintLevel::Allow => Severity::Note,
                    },
                    format!("detected '{}' source not specifically allowed", type_name,),
                    Label::new(ctx.spans_id, span, "source"),
                ));

                sender.send(pack).unwrap();
            }
        }
    }

    for src in source_hits
        .into_iter()
        .zip(ctx.cfg.allowed_sources.into_iter())
        .filter_map(|(hit, src)| if !hit { Some(src) } else { None })
    {
        sender
            .send(
                Diagnostic::new(
                    Severity::Warning,
                    "allowed source was not encountered",
                    Label::new(
                        ctx.cfg.file_id,
                        src.span,
                        "no crate source matched these criteria",
                    ),
                )
                .into(),
            )
            .unwrap();
    }
}
