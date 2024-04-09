pub mod cfg;
mod diags;
use cfg::ValidConfig;
pub use diags::Code;

use crate::{
    diag::{CfgCoord, Check, ErrorSink, Label, Pack},
    LintLevel,
};

const CRATES_IO_URL: &str = "https://github.com/rust-lang/crates.io-index";

pub fn check(ctx: crate::CheckCtx<'_, ValidConfig>, sink: impl Into<ErrorSink>) {
    use bitvec::prelude::*;

    // early out if everything is allowed
    if ctx.cfg.unknown_registry == LintLevel::Allow && ctx.cfg.unknown_git == LintLevel::Allow {
        return;
    }

    let mut sink = sink.into();

    // scan through each crate and check the source of it

    // keep track of which sources are actually encountered, so we can emit a
    // warning if the user has listed a source that no crates are actually using
    let mut source_hits: BitVec = BitVec::repeat(false, ctx.cfg.allowed_sources.len());
    let mut org_hits: BitVec = BitVec::repeat(false, ctx.cfg.allowed_orgs.len());

    let min_git_spec = ctx.cfg.required_git_spec.as_ref().map(|rgs| {
        (
            rgs.value,
            CfgCoord {
                span: rgs.span,
                file: ctx.cfg.file_id,
            },
        )
    });

    for (i, krate) in ctx.krates.krates().enumerate() {
        let source = match &krate.source {
            Some(source) => source,
            None => continue,
        };

        let mut pack = Pack::with_kid(Check::Sources, krate.id.clone());

        let mut sl = None;
        let label = || {
            let span = &ctx.krate_spans[i];
            Label::primary(ctx.krate_spans.file_id, span.source..span.total.end)
                .with_message("source")
        };

        // get allowed list of sources to check
        let (lint_level, type_name) = if source.is_registry() {
            (ctx.cfg.unknown_registry, "registry")
        } else if let Some(spec) = source.git_spec() {
            // Ensure the git source has at least the minimum specification
            if let Some((min, cfg_coord)) = &min_git_spec {
                if spec < *min {
                    pack.push(diags::BelowMinimumRequiredSpec {
                        src_label: sl.get_or_insert_with(label),
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

        // check if the source URL is in the list of allowed sources
        let diag: crate::diag::Diag = if let Some(ind) = ctx
            .cfg
            .allowed_sources
            .iter()
            .position(|src| krate.matches_url(&src.url.value, src.exact))
        {
            source_hits.as_mut_bitslice().set(ind, true);

            // Show the location of the config that allowed this source, unless
            // it's crates.io since that will be a vast majority of crates and
            // is the default, so we might not have a real source location anyways
            if krate.is_crates_io() {
                continue;
            }

            diags::ExplicitlyAllowedSource {
                src_label: sl.get_or_insert_with(label),
                type_name,
                allow_cfg: CfgCoord {
                    file: ctx.cfg.file_id,
                    span: ctx.cfg.allowed_sources[ind].url.span,
                },
            }
            .into()
        } else if let Some((orgt, orgname)) = krate.source.as_ref().and_then(|s| {
            let crate::Source::Git { url, .. } = s else {
                return None;
            };
            get_org(url)
        }) {
            // .to_lowercase() (ln. 113) enables case insensitivity, as GitHub and
            // GitLab are case insensitive in regards to namespaces.
            if let Some(ind) = ctx.cfg.allowed_orgs.iter().position(|(sorgt, sorgn)| {
                orgt == *sorgt && sorgn.value.as_str().to_lowercase() == orgname.to_lowercase()
            }) {
                org_hits.as_mut_bitslice().set(ind, true);
                diags::SourceAllowedByOrg {
                    src_label: sl.get_or_insert_with(label),
                    org_cfg: CfgCoord {
                        file: ctx.cfg.file_id,
                        span: ctx.cfg.allowed_orgs[ind].1.span,
                    },
                }
                .into()
            } else {
                diags::SourceNotExplicitlyAllowed {
                    src_label: sl.get_or_insert_with(label),
                    lint_level,
                    type_name,
                }
                .into()
            }
        } else {
            diags::SourceNotExplicitlyAllowed {
                src_label: sl.get_or_insert_with(label),
                lint_level,
                type_name,
            }
            .into()
        };

        pack.push(diag);
        sink.push(pack);
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

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
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
