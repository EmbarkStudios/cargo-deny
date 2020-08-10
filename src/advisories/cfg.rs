use crate::{
    diag::{Diagnostic, FileId},
    LintLevel, Spanned,
};
use rustsec::advisory;
use serde::Deserialize;
use std::path::PathBuf;

#[allow(clippy::reversed_empty_ranges)]
fn yanked() -> Spanned<LintLevel> {
    Spanned::new(LintLevel::Warn, 0..0)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Path to the local copy of advisory database's git repo (default: ~/.cargo/advisory-db)
    pub db_path: Option<PathBuf>,
    /// List of paths to local copies of different advisory databases.
    #[serde(default)]
    pub db_paths: Vec<PathBuf>,
    /// URL to the advisory database's git repo (default: https://github.com/RustSec/advisory-db)
    pub db_url: Option<String>,
    /// List of urls to git repositories of different advisory databases.
    #[serde(default)]
    pub db_urls: Vec<String>,
    /// How to handle crates that have a security vulnerability
    #[serde(default = "crate::lint_deny")]
    pub vulnerability: LintLevel,
    /// How to handle crates that have been marked as unmaintained in the advisory database
    #[serde(default = "crate::lint_warn")]
    pub unmaintained: LintLevel,
    /// How to handle crates that have been yanked from eg crates.io
    #[serde(default = "yanked")]
    pub yanked: Spanned<LintLevel>,
    /// How to handle crates that have been marked with a notice in the advisory database
    #[serde(default = "crate::lint_warn")]
    pub notice: LintLevel,
    /// Ignore advisories for the given IDs
    #[serde(default)]
    pub ignore: Vec<Spanned<advisory::Id>>,
    /// CVSS Qualitative Severity Rating Scale threshold to alert at.
    ///
    /// Vulnerabilities with explicit CVSS info which have a severity below
    /// this threshold will be ignored.
    pub severity_threshold: Option<advisory::Severity>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: None,
            db_paths: Vec::new(),
            db_url: None,
            db_urls: Vec::new(),
            ignore: Vec::new(),
            vulnerability: LintLevel::Deny,
            unmaintained: LintLevel::Warn,
            yanked: yanked(),
            notice: LintLevel::Warn,
            severity_threshold: None,
        }
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId) -> Result<Self::ValidCfg, Vec<Diagnostic>> {
        let mut ignored: Vec<_> = self.ignore.into_iter().map(AdvisoryId::from).collect();
        ignored.sort();

        let mut db_urls = self.db_urls;
        if let Some(db_url) = self.db_url {
            log::warn!("the 'db_url' option is deprecated, use 'db_urls' instead");
            db_urls.push(db_url);
        }

        let mut db_paths = self.db_paths;
        if let Some(db_path) = self.db_path {
            log::warn!("the 'db_path' option is deprecated, use 'db_paths' instead");
            db_paths.push(db_path);
        }

        Ok(ValidConfig {
            file_id: cfg_file,
            db_paths,
            db_urls,
            ignore: ignored,
            vulnerability: self.vulnerability,
            unmaintained: self.unmaintained,
            yanked: self.yanked,
            notice: self.notice,
            severity_threshold: self.severity_threshold,
        })
    }
}

pub(crate) type AdvisoryId = Spanned<advisory::Id>;

pub struct ValidConfig {
    pub file_id: FileId,
    pub db_paths: Vec<PathBuf>,
    pub db_urls: Vec<String>,
    pub(crate) ignore: Vec<AdvisoryId>,
    pub vulnerability: LintLevel,
    pub unmaintained: LintLevel,
    pub yanked: Spanned<LintLevel>,
    pub notice: LintLevel,
    pub severity_threshold: Option<advisory::Severity>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, UnvalidatedConfig};
    use std::borrow::Cow;

    #[test]
    fn works() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Advisories {
            advisories: Config,
        }

        let cd: ConfigData<Advisories> = load("tests/cfg/advisories.toml");
        let validated = cd.config.advisories.validate(cd.id).unwrap();

        assert_eq!(validated.file_id, cd.id);
        assert!(validated
            .db_paths
            .iter()
            .map(|dp| dp.to_string_lossy())
            .eq(vec![Cow::Borrowed("~/.cargo/advisory-db")]));
        assert!(validated
            .db_urls
            .iter()
            .eq(vec!["https://github.com/RustSec/advisory-db"]));
        assert_eq!(validated.vulnerability, LintLevel::Deny);
        assert_eq!(validated.unmaintained, LintLevel::Warn);
        assert_eq!(validated.yanked, LintLevel::Warn);
        assert_eq!(validated.notice, LintLevel::Warn);
        assert_eq!(
            validated.ignore,
            vec!["RUSTSEC-0000-0000"
                .parse::<rustsec::advisory::Id>()
                .unwrap()]
        );
        assert_eq!(
            validated.severity_threshold,
            Some(rustsec::advisory::Severity::Medium)
        );
    }
}
