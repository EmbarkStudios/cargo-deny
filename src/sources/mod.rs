mod cfg;
pub use cfg::{Config, ValidConfig};

use crate::diag::{self, Diagnostic, Label, Pack, Severity};
use crate::LintLevel;
use anyhow::{bail, Context, Error};
use std::str::FromStr;
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

impl FromStr for Source {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split("+").collect::<Vec<_>>();

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

pub fn check(
    cfg: ValidConfig,
    krates: &crate::Krates,
    (krate_spans, spans_id): (&diag::KrateSpans, codespan::FileId),
    sender: crossbeam::channel::Sender<Pack>,
) {
    // early out if everything is allowed
    if cfg.unknown_registry == LintLevel::Allow && cfg.unknown_git == LintLevel::Allow {
        return;
    }

    // scan through each crate and check the source of it

    for (i, krate) in krates.krates.iter().enumerate() {
        // determine source of crate

        let source = match &krate.source {
            Some(source) => match Source::from_str(&format!("{}", source)) {
                Ok(source) => source,
                Err(_err) => {
                    sender
                        .send(Pack {
                            krate_id: Some(krate.id.clone()),
                            diagnostics: vec![Diagnostic::new(
                                Severity::Error,
                                "detected unknown or unsupported crate source",
                                Label::new(spans_id, krate_spans[i].clone(), "source"),
                            )],
                        })
                        .unwrap();
                    continue;
                }
            },
            None => continue,
        };

        // get allowed list of sources to check

        let (allowed_sources, lint_level) = match source {
            Source::Registry(_) => (&cfg.allow_registry, cfg.unknown_registry),
            Source::Git(_) => (&cfg.allow_git, cfg.unknown_git),
        };

        // get URL without git revision (query & fragment)
        // example URL in Cargo.lock: https://github.com/RustSec/rustsec-crate.git?rev=aaba369#aaba369bebc4fcfb9133b1379bcf430b707188a2
        // where we only want:        https://github.com/RustSec/rustsec-crate.git
        let source_url_str = {
            let mut url = source.url().clone();
            url.set_query(None);
            url.set_fragment(None);
            url.as_str().to_owned()
        };

        // check if the source URL is list of allowed sources
        if !allowed_sources.contains(&source_url_str) {
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
                            "detected crate {} source \"{}\" not specifically allowed",
                            source.type_name(),
                            source_url_str,
                        ),
                        Label::new(spans_id, krate_spans[i].clone(), "source"),
                    )],
                })
                .unwrap();
        }
    }
}
