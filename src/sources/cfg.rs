use super::OrgType;
use crate::{
    LintLevel, Spanned,
    cfg::{self, ValidationContext},
    diag::FileId,
};
use toml_span::{DeserError, Deserialize, de_helpers::TableHelper, value::Value};

#[derive(Default)]
pub struct Orgs {
    /// The list of Github organizations that crates can be sourced from.
    github: Vec<Spanned<String>>,
    /// The list of Gitlab organizations that crates can be sourced from.
    gitlab: Vec<Spanned<String>>,
    /// The list of Bitbucket organizations that crates can be sourced from.
    bitbucket: Vec<Spanned<String>>,
}

impl<'de> Deserialize<'de> for Orgs {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let github = th.optional("github").unwrap_or_default();
        let gitlab = th.optional("gitlab").unwrap_or_default();
        let bitbucket = th.optional("bitbucket").unwrap_or_default();
        th.finalize(None)?;

        Ok(Self {
            github,
            gitlab,
            bitbucket,
        })
    }
}

/// The types of specifiers that can be used on git sources by cargo, in order
/// of their specificity from least to greatest
#[derive(
    PartialEq,
    Eq,
    Debug,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Default,
    strum::VariantArray,
    strum::VariantNames,
)]
#[strum(serialize_all = "kebab-case")]
pub enum GitSpec {
    /// Specifies the `HEAD` of the remote
    #[default]
    Any,
    /// Specifies the `HEAD` of a particular branch
    Branch,
    /// Specifies the commit pointed to by a particular tag
    Tag,
    /// Specifies an exact commit
    Rev,
}

crate::enum_deser!(GitSpec);

use std::fmt;

impl fmt::Display for GitSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Any => "any",
            Self::Branch => "branch",
            Self::Tag => "tag",
            Self::Rev => "rev",
        })
    }
}

pub struct Config {
    /// How to handle registries that weren't listed
    pub unknown_registry: LintLevel,
    /// How to handle git sources that weren't listed
    pub unknown_git: LintLevel,
    /// The list of registries that crates can be sourced from.
    /// Defaults to the crates.io registry if not specified.
    pub allow_registry: Vec<Spanned<String>>,
    /// The list of git repositories that crates can be sourced from.
    pub allow_git: Vec<Spanned<String>>,
    /// The lists of source control organizations that crates can be sourced from.
    pub allow_org: Orgs,
    /// The list of hosts with optional paths from which one or more git repos
    /// can be sourced.
    pub private: Vec<Spanned<String>>,
    /// The minimum specification required for git sources. Defaults to allowing
    /// any.
    pub required_git_spec: Option<Spanned<GitSpec>>,
    /// Determines the response to sources in th `allow`ed list which do not
    /// exist in the dependency tree.
    pub unused_allowed_source: LintLevel,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let unknown_registry = th.optional("unknown-registry").unwrap_or(LintLevel::Warn);
        let unknown_git = th.optional("unknown-git").unwrap_or(LintLevel::Warn);
        let allow_registry = th
            .optional("allow-registry")
            .unwrap_or_else(|| vec![Spanned::new(super::CRATES_IO_URL.to_owned())]);
        let allow_git = th.optional("allow-git").unwrap_or_default();
        let allow_org = th.optional("allow-org").unwrap_or_default();
        let private = th.optional("private").unwrap_or_default();
        let required_git_spec = th.optional("required-git-spec");
        let unused_allowed_source = th.optional("unused-allowed-source").unwrap_or(LintLevel::Warn);

        th.finalize(None)?;

        Ok(Self {
            unknown_registry,
            unknown_git,
            allow_registry,
            allow_git,
            allow_org,
            private,
            required_git_spec,
            unused_allowed_source,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            unknown_registry: LintLevel::Warn,
            unknown_git: LintLevel::Warn,
            allow_registry: vec![Spanned::new(super::CRATES_IO_URL.to_owned())],
            allow_git: Vec::new(),
            allow_org: Orgs::default(),
            private: Vec::new(),
            required_git_spec: None,
            unused_allowed_source: LintLevel::Warn,
        }
    }
}

use crate::diag::{Diagnostic, Label};

impl cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, mut ctx: ValidationContext<'_>) -> Self::ValidCfg {
        let mut allowed_sources = Vec::with_capacity(
            self.allow_registry.len() + self.allow_git.len() + self.private.len(),
        );

        for (aurl, exact, is_git) in self
            .allow_registry
            .into_iter()
            .map(|u| (u, true, false))
            .chain(self.allow_git.into_iter().map(|u| (u, true, true)))
            .chain(self.private.into_iter().map(|u| (u, false, false)))
        {
            let astr = aurl.as_ref();
            let mut skip = 0;

            if let Some(start_scheme) = astr.find("://") {
                if let Some(i) = astr[..start_scheme].find('+') {
                    skip = i + 1;
                }
            }

            match url::Url::parse(&astr[skip..]) {
                Ok(mut url) => {
                    if is_git {
                        crate::normalize_git_url(&mut url);
                    }

                    allowed_sources.push(UrlSource {
                        url: UrlSpan {
                            value: url,
                            span: aurl.span,
                        },
                        exact,
                    });
                }
                Err(pe) => {
                    ctx.push(
                        Diagnostic::error()
                            .with_message("failed to parse url")
                            .with_labels(vec![
                                Label::primary(ctx.cfg_id, aurl.span).with_message(pe),
                            ]),
                    );
                }
            }
        }

        let allowed_orgs = self
            .allow_org
            .github
            .into_iter()
            .map(|o| (OrgType::Github, o))
            .chain(
                self.allow_org
                    .gitlab
                    .into_iter()
                    .map(|o| (OrgType::Gitlab, o)),
            )
            .chain(
                self.allow_org
                    .bitbucket
                    .into_iter()
                    .map(|o| (OrgType::Bitbucket, o)),
            )
            .collect();

        ValidConfig {
            file_id: ctx.cfg_id,
            unknown_registry: self.unknown_registry,
            unknown_git: self.unknown_git,
            allowed_sources,
            allowed_orgs,
            required_git_spec: self.required_git_spec,
            unused_allowed_source: self.unused_allowed_source,
        }
    }
}

pub type UrlSpan = Spanned<url::Url>;

#[derive(PartialEq, Eq, Debug)]
pub struct UrlSource {
    pub url: UrlSpan,
    pub exact: bool,
}

#[doc(hidden)]
#[cfg_attr(test, derive(Debug))]
pub struct ValidConfig {
    pub file_id: FileId,

    pub unknown_registry: LintLevel,
    pub unknown_git: LintLevel,
    pub allowed_sources: Vec<UrlSource>,
    pub allowed_orgs: Vec<(OrgType, Spanned<String>)>,
    pub required_git_spec: Option<Spanned<GitSpec>>,
    pub unused_allowed_source: LintLevel,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{ConfigData, write_diagnostics};

    #[test]
    fn deserializes_sources_cfg() {
        struct Sources {
            sources: Config,
        }

        impl<'de> toml_span::Deserialize<'de> for Sources {
            fn deserialize(
                value: &mut toml_span::value::Value<'de>,
            ) -> Result<Self, toml_span::DeserError> {
                let mut th = toml_span::de_helpers::TableHelper::new(value)?;
                let sources = th.required("sources").unwrap();
                th.finalize(None)?;
                Ok(Self { sources })
            }
        }

        let cd = ConfigData::<Sources>::load("tests/cfg/sources.toml");
        let validated = cd.validate_with_diags(
            |s| s.sources,
            |files, diags| {
                let diags = write_diagnostics(files, diags.into_iter());
                insta::assert_snapshot!(diags);
            },
        );

        insta::assert_debug_snapshot!(validated);
    }
}
