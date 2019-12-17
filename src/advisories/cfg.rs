use crate::LintLevel;
use rustsec::advisory;
use serde::Deserialize;
use std::path::PathBuf;

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
    /// How to handle crates that have been marked with a notice in the advisory database
    #[serde(default = "crate::lint_warn")]
    pub notice: LintLevel,
    /// Ignore advisories for the given IDs
    #[serde(default)]
    pub ignore: Vec<advisory::Id>,
    // How to handle crates that have been marked with an informational advisory
    // in the advisory database, which is NOT `unmaintained` or `notice`
    // #[serde(default = "lint_warn")]
    // pub other: LintLevel,
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
        Ok(ValidConfig {
            file_id: cfg_file,
            db_path: self.db_path,
            db_url: self.db_url,
            ignore: self.ignore,
            vulnerability: self.vulnerability,
            unmaintained: self.unmaintained,
            notice: self.notice,
            severity_threshold: self.severity_threshold,
        })
    }
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,
    pub db_path: Option<PathBuf>,
    pub db_url: Option<String>,
    pub ignore: Vec<advisory::Id>,
    pub vulnerability: LintLevel,
    pub unmaintained: LintLevel,
    pub notice: LintLevel,
    pub severity_threshold: Option<advisory::Severity>,
}
