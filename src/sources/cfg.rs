use super::OrgType;
use crate::{cfg, diag::FileId, LintLevel, Spanned};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Orgs {
    /// The list of Github organizations that crates can be sourced from.
    #[serde(default)]
    github: Vec<Spanned<String>>,
    /// The list of Gitlab organizations that crates can be sourced from.
    #[serde(default)]
    gitlab: Vec<Spanned<String>>,
    /// The list of Bitbucket organizations that crates can be sourced from.
    #[serde(default)]
    bitbucket: Vec<Spanned<String>>,
}

/// The types of specifiers that can be used on git sources by cargo, in order
/// of their specificity from least to greatest
#[derive(Deserialize, PartialEq, Eq, Debug, PartialOrd, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum GitSpec {
    /// Specifies the HEAD of the `master` branch, though eventually this might
    /// change to the default branch
    #[default]
    Any,
    /// Specifies the HEAD of a particular branch
    Branch,
    /// Specifies the commit pointed to by a particular tag
    Tag,
    /// Specifies an exact commit
    Rev,
}

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

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// How to handle registries that weren't listed
    #[serde(default = "crate::lint_warn")]
    pub unknown_registry: LintLevel,
    /// How to handle git sources that weren't listed
    #[serde(default = "crate::lint_warn")]
    pub unknown_git: LintLevel,
    /// The list of registries that crates can be sourced from.
    /// Defaults to the crates.io registry if not specified.
    #[serde(default = "default_allow_registry")]
    pub allow_registry: Vec<Spanned<String>>,
    /// The list of git repositories that crates can be sourced from.
    #[serde(default)]
    pub allow_git: Vec<Spanned<String>>,
    /// The lists of source control organizations that crates can be sourced from.
    #[serde(default)]
    pub allow_org: Orgs,
    /// The list of hosts with optional paths from which one or more git repos
    /// can be sourced.
    #[serde(default)]
    pub private: Vec<Spanned<String>>,
    /// The minimum specification required for git sources. Defaults to allowing
    /// any.
    #[serde(default)]
    pub required_git_spec: Option<Spanned<GitSpec>>,
}

#[inline]
fn default_allow_registry() -> Vec<Spanned<String>> {
    // This is always valid, so we don't have to worry about the span being fake,
    // this is actually a lie though because if we try to print this span it will
    // fail if it falls outside of the range of the config file, and even if it
    // doesn't will just point to whatever text happens to be there, so we instead
    // lie and just ignore it instead since a vast majority of usage should
    // use this source
    vec![Spanned::new(
        super::CRATES_IO_URL.to_owned(),
        0..super::CRATES_IO_URL.len(),
    )]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            unknown_registry: LintLevel::Warn,
            unknown_git: LintLevel::Warn,
            allow_registry: default_allow_registry(),
            allow_git: Vec::new(),
            allow_org: Orgs::default(),
            private: Vec::new(),
            required_git_spec: None,
        }
    }
}

use crate::diag::{Diagnostic, Label};

impl cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId, diags: &mut Vec<Diagnostic>) -> Self::ValidCfg {
        let mut allowed_sources = Vec::with_capacity(
            self.allow_registry.len() + self.allow_git.len() + self.private.len(),
        );

        for (aurl, exact) in self
            .allow_registry
            .into_iter()
            .map(|u| (u, true))
            .chain(self.allow_git.into_iter().map(|u| (u, true)))
            .chain(self.private.into_iter().map(|u| (u, false)))
        {
            match url::Url::parse(aurl.as_ref()) {
                Ok(mut url) => {
                    crate::normalize_url(&mut url);
                    allowed_sources.push(UrlSource {
                        url: UrlSpan {
                            value: url,
                            span: aurl.span,
                        },
                        exact,
                    });
                }
                Err(pe) => {
                    diags.push(
                        Diagnostic::error()
                            .with_message("failed to parse url")
                            .with_labels(vec![
                                Label::primary(cfg_file, aurl.span).with_message(pe.to_string())
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
            file_id: cfg_file,
            unknown_registry: self.unknown_registry,
            unknown_git: self.unknown_git,
            allowed_sources,
            allowed_orgs,
            required_git_spec: self.required_git_spec,
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
pub struct ValidConfig {
    pub file_id: FileId,

    pub unknown_registry: LintLevel,
    pub unknown_git: LintLevel,
    pub allowed_sources: Vec<UrlSource>,
    pub allowed_orgs: Vec<(OrgType, Spanned<String>)>,
    pub required_git_spec: Option<Spanned<GitSpec>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, *};

    #[test]
    fn deserializes_sources_cfg() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Sources {
            sources: Config,
        }

        let cd: ConfigData<Sources> = load("tests/cfg/sources.toml");

        let mut diags = Vec::new();
        let validated = cd.config.sources.validate(cd.id, &mut diags);
        assert!(diags.is_empty());

        assert!(diags.is_empty());

        assert_eq!(validated.file_id, cd.id);
        assert_eq!(validated.unknown_registry, LintLevel::Allow);
        assert_eq!(validated.unknown_git, LintLevel::Deny);

        assert_eq!(
            validated.allowed_sources,
            vec![
                UrlSource {
                    url: url::Url::parse("https://sekretz.com/registry/index")
                        .unwrap()
                        .fake(),
                    exact: true,
                },
                UrlSource {
                    url: url::Url::parse("https://notgithub.com/orgname/reponame")
                        .unwrap()
                        .fake(),
                    exact: true,
                },
                UrlSource {
                    url: url::Url::parse("https://internal-host/repos")
                        .unwrap()
                        .fake(),
                    exact: false,
                },
            ],
            "{:#?}",
            validated.allowed_sources
        );

        // Obviously order could change here, but for now just hardcode it
        assert_eq!(
            validated.allowed_orgs,
            vec![
                (OrgType::Github, "yourghid".to_owned().fake()),
                (OrgType::Github, "YourOrg".to_owned().fake()),
                (OrgType::Gitlab, "gitlab-org".to_owned().fake()),
                (OrgType::Bitbucket, "atlassian".to_owned().fake()),
            ]
        );

        assert_eq!(validated.required_git_spec.unwrap().value, GitSpec::Tag);
    }
}
