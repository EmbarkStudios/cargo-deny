mod cfg;
pub use cfg::{Config, ValidConfig};

use crate::{
    diag::{Check, Diagnostic, Label, Pack, Severity},
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
    let mut org_hits = bitvec![0; ctx.cfg.allowed_orgs.len()];

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

        let source_label = {
            let mut span = ctx.krate_spans[i].clone();

            // The krate span is the complete id, but we only want
            // to highlight the source component
            let last_space = krate.id.repr.rfind(' ').unwrap();

            span.start = span.start + last_space + 1;
            Label::primary(ctx.spans_id, span).with_message("source")
        };

        // check if the source URL is list of allowed sources
        match ctx
            .cfg
            .allowed_sources
            .iter()
            .position(|src| src == &source_url)
        {
            Some(ind) => {
                // Show the location of the config that allowed this source, unless
                // it's crates.io since that will be a vast majority of crates and
                // is the default, so we might not have a real source location anyways
                if source_url.as_str() != "https://github.com/rust-lang/crates.io-index" {
                    let mut pack = Pack::with_kid(Check::Sources, krate.id.clone());
                    pack.push(
                        Diagnostic::new(Severity::Note)
                            .with_message(format!("'{}' source explicitly allowed", type_name,))
                            .with_labels(vec![
                                source_label,
                                Label::primary(
                                    ctx.cfg.file_id,
                                    ctx.cfg.allowed_sources[ind].span.clone(),
                                )
                                .with_message("url allowance"),
                            ]),
                    );

                    sender.send(pack).unwrap();
                }

                source_hits.as_mut_bitslice().set(ind, true)
            }
            None => {
                // Check to see if the url is still allowed due to its org
                if !ctx.cfg.allowed_orgs.is_empty() {
                    if let Some((orgt, orgname)) = get_org(&source_url) {
                        if let Some(ind) = ctx.cfg.allowed_orgs.iter().position(|(sorgt, sorgn)| {
                            orgt == *sorgt && sorgn.value.as_str() == orgname
                        }) {
                            let mut pack = Pack::with_kid(Check::Sources, krate.id.clone());
                            pack.push(
                                Diagnostic::new(Severity::Note)
                                    .with_message(format!(
                                        "'{}' source explicitly allowed",
                                        type_name,
                                    ))
                                    .with_labels(vec![
                                        source_label,
                                        Label::primary(
                                            ctx.cfg.file_id,
                                            ctx.cfg.allowed_orgs[ind].1.span.clone(),
                                        )
                                        .with_message("org allowance"),
                                    ]),
                            );

                            sender.send(pack).unwrap();
                            org_hits.as_mut_bitslice().set(ind, true);
                            continue;
                        }
                    }
                }

                let mut pack = Pack::with_kid(Check::Sources, krate.id.clone());
                pack.push(
                    Diagnostic::new(match lint_level {
                        LintLevel::Warn => Severity::Warning,
                        LintLevel::Deny => Severity::Error,
                        LintLevel::Allow => Severity::Note,
                    })
                    .with_message(format!(
                        "detected '{}' source not specifically allowed",
                        type_name,
                    ))
                    .with_labels(vec![source_label]),
                );

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
                (
                    Check::Sources,
                    Diagnostic::warning()
                        .with_message("allowed source was not encountered")
                        .with_labels(vec![Label::primary(ctx.cfg.file_id, src.span)
                            .with_message("no crate source matched these criteria")]),
                )
                    .into(),
            )
            .unwrap();
    }

    for (orgt, orgs) in org_hits
        .into_iter()
        .zip(ctx.cfg.allowed_orgs.into_iter())
        .filter_map(|(hit, src)| if !hit { Some(src) } else { None })
    {
        sender
            .send(
                (
                    Check::Sources,
                    Diagnostic::warning()
                        .with_message(format!("allowed {} organization was not encountered", orgt))
                        .with_labels(vec![Label::primary(ctx.cfg.file_id, orgs.span)
                            .with_message("no crate source fell under this organization")]),
                )
                    .into(),
            )
            .unwrap();
    }
}

#[derive(PartialEq, Debug)]
pub enum OrgType {
    Github,
    Gitlab,
    Bitbucket,
}

use std::fmt;
impl fmt::Display for OrgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Github => "github.com",
            Self::Gitlab => "gitlab.com",
            Self::Bitbucket => "bitbucket.org",
        })
    }
}

fn get_org(url: &url::Url) -> Option<(OrgType, &str)> {
    url.domain().and_then(|domain| {
        let org_type = if domain.eq_ignore_ascii_case("github.com") {
            OrgType::Github
        } else if domain.eq_ignore_ascii_case("gitlab.com") {
            OrgType::Gitlab
        } else if domain.eq_ignore_ascii_case("bitbucket.org") {
            OrgType::Bitbucket
        } else {
            return None;
        };

        url.path_segments()
            .and_then(|mut f| f.next())
            .map(|org| (org_type, org))
    })
}
