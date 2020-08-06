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
}

fn default_allow_registry() -> Vec<Spanned<String>> {
    // This is always valid, so we don't have to worry about the span being fake
    vec![Spanned::new(
        "https://github.com/rust-lang/crates.io-index".to_owned(),
        0..44,
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
        }
    }
}

use crate::diag::{Diagnostic, Label};

impl cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId) -> Result<Self::ValidCfg, Vec<Diagnostic>> {
        let mut diags = Vec::new();

        let mut allowed_sources =
            Vec::with_capacity(self.allow_registry.len() + self.allow_git.len());

        for aurl in self
            .allow_registry
            .into_iter()
            .chain(self.allow_git.into_iter())
        {
            match url::Url::parse(aurl.as_ref()) {
                Ok(url) => {
                    allowed_sources.push(UrlSpan {
                        value: url,
                        span: aurl.span,
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

        if !diags.is_empty() {
            return Err(diags);
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

        Ok(ValidConfig {
            file_id: cfg_file,
            unknown_registry: self.unknown_registry,
            unknown_git: self.unknown_git,
            allowed_sources,
            allowed_orgs,
        })
    }
}

pub type UrlSpan = Spanned<url::Url>;

#[doc(hidden)]
pub struct ValidConfig {
    pub file_id: FileId,

    pub unknown_registry: LintLevel,
    pub unknown_git: LintLevel,
    pub allowed_sources: Vec<UrlSpan>,
    pub allowed_orgs: Vec<(OrgType, Spanned<String>)>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, *};

    #[test]
    fn works() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Sources {
            sources: Config,
        }

        let cd: ConfigData<Sources> = load("tests/cfg/sources.toml");

        let validated = cd.config.sources.validate(cd.id).unwrap();

        assert_eq!(validated.file_id, cd.id);
        assert_eq!(validated.unknown_registry, LintLevel::Allow);
        assert_eq!(validated.unknown_git, LintLevel::Deny);

        assert_eq!(
            validated.allowed_sources,
            vec![
                url::Url::parse("https://sekretz.com/registry/index")
                    .unwrap()
                    .fake(),
                url::Url::parse("https://notgithub.com/orgname/reponame")
                    .unwrap()
                    .fake()
            ]
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
    }
}
