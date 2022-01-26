mod cfg;
mod diags;
pub use cfg::{Config, GitSpec, ValidConfig};

use crate::{
    diag::{CfgCoord, Check, ErrorSink, Label, Pack},
    LintLevel,
};
use url::Url;

const CRATES_IO_URL: &str = "https://github.com/rust-lang/crates.io-index";

pub fn check(ctx: crate::CheckCtx<'_, ValidConfig>, mut sink: ErrorSink) {
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

    let min_git_spec = ctx.cfg.required_git_spec.as_ref().map(|rgs| {
        (
            rgs.value,
            CfgCoord {
                span: rgs.span.clone(),
                file: ctx.cfg.file_id,
            },
        )
    });

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
            normalize_url(&mut url);
            url
        };

        let mut pack = Pack::with_kid(Check::Sources, krate.id.clone());

        let source_label = {
            let mut span = ctx.krate_spans[i].clone();

            // The krate span is the complete id, but we only want
            // to highlight the source component
            let last_space = krate.id.repr.rfind(' ').unwrap();

            span.start = span.start + last_space + 1;
            Label::primary(ctx.krate_spans.file_id, span).with_message("source")
        };

        // get allowed list of sources to check
        let (lint_level, type_name) = if source.is_registry() {
            (ctx.cfg.unknown_registry, "registry")
        } else if source.is_git() {
            // Ensure the git source has at least the minimum specification
            if let Some((min, cfg_coord)) = &min_git_spec {
                pub use rustsec::package::source::GitReference;

                let spec = source
                    .git_reference()
                    .map(|gr| match gr {
                        GitReference::Branch(name) => {
                            // TODO: Workaround logic hardcoded in the rustsec crate,
                            // that crate can be changed to support the new v3 lock format
                            // whenever it is stabilized https://github.com/rust-lang/cargo/pull/8522
                            if name == "master" {
                                GitSpec::Any
                            } else {
                                GitSpec::Branch
                            }
                        }
                        GitReference::Tag(_) => GitSpec::Tag,
                        GitReference::Rev(_) => GitSpec::Rev,
                    })
                    .unwrap_or_default();

                if spec < *min {
                    pack.push(diags::BelowMinimumRequiredSpec {
                        src_label: &source_label,
                        min_spec: *min,
                        actual_spec: spec,
                        min_spec_cfg: cfg_coord.clone(),
                    });
                }
            }

            (ctx.cfg.unknown_git, "git")
        } else {
            continue;
        };

        // check if the source URL is list of allowed sources
        match ctx.cfg.allowed_sources.iter().position(|src| {
            if src.exact {
                src.url == source_url
            } else {
                source_url.host() == src.url.value.host()
                    && source_url.path().starts_with(src.url.value.path())
            }
        }) {
            Some(ind) => {
                // Show the location of the config that allowed this source, unless
                // it's crates.io since that will be a vast majority of crates and
                // is the default, so we might not have a real source location anyways
                if source_url.as_str() != CRATES_IO_URL {
                    pack.push(diags::ExplicitlyAllowedSource {
                        src_label: &source_label,
                        type_name,
                        allow_cfg: CfgCoord {
                            file: ctx.cfg.file_id,
                            span: ctx.cfg.allowed_sources[ind].url.span.clone(),
                        },
                    });
                }

                source_hits.as_mut_bitslice().set(ind, true);
            }
            None => {
                let diag: crate::diag::Diag = match get_org(&source_url) {
                    Some((orgt, orgname)) => {
                        match ctx.cfg.allowed_orgs.iter().position(|(sorgt, sorgn)| {
                            orgt == *sorgt && sorgn.value.as_str() == orgname
                        }) {
                            Some(ind) => {
                                org_hits.as_mut_bitslice().set(ind, true);
                                diags::SourceAllowedByOrg {
                                    src_label: &source_label,
                                    org_cfg: CfgCoord {
                                        file: ctx.cfg.file_id,
                                        span: ctx.cfg.allowed_orgs[ind].1.span.clone(),
                                    },
                                }
                                .into()
                            }
                            None => diags::SourceNotExplicitlyAllowed {
                                src_label: &source_label,
                                lint_level,
                                type_name,
                            }
                            .into(),
                        }
                    }
                    None => diags::SourceNotExplicitlyAllowed {
                        src_label: &source_label,
                        lint_level,
                        type_name,
                    }
                    .into(),
                };

                pack.push(diag);
            }
        }

        if !pack.is_empty() {
            sink.push(pack);
        }
    }

    let mut pack = Pack::new(Check::Sources);

    for src in source_hits
        .into_iter()
        .zip(ctx.cfg.allowed_sources.into_iter())
        .filter_map(|(hit, src)| if !hit { Some(src) } else { None })
    {
        // If someone in is in a situation that they want to disallow crates
        // from crates.io, they should set the allowed registries manually
        if src.url.as_ref().as_str() == CRATES_IO_URL {
            continue;
        }

        pack.push(diags::UnmatchedAllowSource {
            allow_src_cfg: CfgCoord {
                span: src.url.span,
                file: ctx.cfg.file_id,
            },
        });
    }

    for (org_type, orgs) in org_hits
        .into_iter()
        .zip(ctx.cfg.allowed_orgs.into_iter())
        .filter_map(|(hit, src)| if !hit { Some(src) } else { None })
    {
        pack.push(diags::UnmatchedAllowOrg {
            allow_org_cfg: CfgCoord {
                span: orgs.span,
                file: ctx.cfg.file_id,
            },
            org_type,
        });
    }

    if !pack.is_empty() {
        sink.push(pack);
    }
}

pub(crate) fn normalize_url(url: &mut Url) {
    // Normalizes the URL so that different representations can be compared to each other.
    // At the moment we just remove a tailing `.git` but there are more possible optimisations.
    // See https://github.com/rust-lang/cargo/blob/1f6c6bd5e7bbdf596f7e88e6db347af5268ab113/src/cargo/util/canonical_url.rs#L31-L57
    // for what cargo does

    let git_extension = ".git";
    let needs_chopping = url.path().ends_with(&git_extension);
    if needs_chopping {
        let last = {
            let last = url.path_segments().unwrap().last().unwrap();
            last[..last.len() - git_extension.len()].to_owned()
        };
        url.path_segments_mut().unwrap().pop().push(&last);
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
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
