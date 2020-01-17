mod cfg;
pub use cfg::{Config, ValidConfig};

use crate::{
    cm,
    diag::{Diagnostic, Label, Pack, Severity},
    LintLevel,
};
use anyhow::{bail, ensure, Context, Error};
use std::convert::TryFrom;
use url::Url;

enum Source {
    Registry(Url),
    Git(Url),
}

impl Source {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Registry(_) => "registry",
            Self::Git(_) => "git",
        }
    }
    pub fn url(&self) -> &Url {
        match self {
            Self::Registry(url) => url,
            Self::Git(url) => url,
        }
    }
}

impl TryFrom<&cm::Source> for Source {
    type Error = Error;

    fn try_from(source: &cm::Source) -> Result<Self, Self::Error> {
        // registry sources are in either of these formats:
        // git+https://github.com/RustSec/rustsec-crate.git?rev=aaba369#aaba369bebc4fcfb9133b1379bcf430b707188a2
        // registry+https://github.com/rust-lang/crates.io-index

        let s = source.to_string();
        let parts = s.split('+').collect::<Vec<_>>();
        ensure!(parts.len() == 2, "Invalid amount of parts: {}", parts.len());

        if let (Some(source_type), Some(url)) = (parts.get(0), parts.get(1)) {
            let url = Url::parse(url).context("Couldn't parse URL")?;
            match *source_type {
                "registry" => Ok(Source::Registry(url)),
                "git" => Ok(Source::Git(url)),
                _ => bail!("Unknown source type: {}", source_type),
            }
        } else {
            bail!("Couldn't parse")
        }
    }
}

pub fn check(ctx: crate::CheckCtx<'_, ValidConfig>, sender: crossbeam::channel::Sender<Pack>) {
    // early out if everything is allowed
    if ctx.cfg.unknown_registry == LintLevel::Allow && ctx.cfg.unknown_git == LintLevel::Allow {
        return;
    }

    // scan through each crate and check the source of it

    for (i, krate) in ctx.krates.krates().map(|kn| &kn.krate).enumerate() {
        // determine source of crate

        let source = match &krate.source {
            Some(source) => source,
            None => continue,
        };
        let source = match Source::try_from(source) {
            Ok(source) => source,
            Err(_err) => {
                sender
                    .send(Pack {
                        krate_id: Some(krate.id.clone()),
                        diagnostics: vec![Diagnostic::new(
                            Severity::Error,
                            "detected unknown or unsupported crate source",
                            ctx.label_for_span(i, "source"),
                        )],
                    })
                    .unwrap();
                continue;
            }
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

        let lint_level = match source {
            Source::Registry(_) => ctx.cfg.unknown_registry,
            Source::Git(_) => ctx.cfg.unknown_git,
        };

        // check if the source URL is list of allowed sources
        match ctx
            .cfg
            .allowed_sources
            .iter()
            .position(|src| src.url == source_url)
        {
            Some(ind) => source_hits.as_mut_bitslice().set(ind, true),
            None => {
                let mut span = ctx.krate_spans[i].clone();

                // The krate span is the complete id, but we only want
                // to highlight the source component
                let last_space = krate.id.repr.rfind(' ').unwrap();

                span.start = span.start + last_space as u32 + 1;

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
                                "detected '{}' source not specifically allowed",
                                source.type_name(),
                            ),
                            Label::new(ctx.spans_id, span, "source"),
                        )],
                    })
                    .unwrap();
            }
        }
    }
                        ),
                        Label::new(spans_id, krate_spans[i].clone(), "source"),
                    )],
                })
                .unwrap();
        }
    }
}
