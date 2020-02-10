use crate::{LintLevel, Spanned};
use rustsec::advisory;
use serde::Deserialize;
use std::path::PathBuf;

fn yanked() -> Spanned<LintLevel> {
    Spanned::new(LintLevel::Warn, 0..0)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Path to the local copy of advisory database's git repo (default: ~/.cargo/advisory-db)
    pub db_path: Option<PathBuf>,
    /// URL to the advisory database's git repo (default: https://github.com/RustSec/advisory-db)
    pub db_url: Option<String>,
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
            db_url: None,
            ignore: Vec::new(),
            vulnerability: LintLevel::Deny,
            unmaintained: LintLevel::Warn,
            yanked: yanked(),
            notice: LintLevel::Warn,
            severity_threshold: None,
        }
    }
}

impl Config {
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
    ) -> Result<ValidConfig, Vec<crate::diag::Diagnostic>> {
        let mut ignored: Vec<_> = self.ignore.into_iter().map(AdvisoryId::from).collect();
        ignored.sort();

        Ok(ValidConfig {
            file_id: cfg_file,
            db_path: self.db_path,
            db_url: self.db_url,
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
    pub file_id: codespan::FileId,
    pub db_path: Option<PathBuf>,
    pub db_url: Option<String>,
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
    use crate::cfg::test::*;

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
        assert_eq!(
            validated.db_path.as_ref().map(|dp| dp.to_string_lossy()),
            Some(std::borrow::Cow::Borrowed("~/.cargo/advisory-db"))
        );
        assert_eq!(
            validated.db_url.as_ref().map(|s| s.as_str()),
            Some("https://github.com/RustSec/advisory-db")
        );
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
