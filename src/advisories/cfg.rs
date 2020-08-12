use crate::{
    diag::{Diagnostic, FileId, Label},
    LintLevel, Spanned,
};
use rustsec::advisory;
use serde::Deserialize;
use std::path::PathBuf;
use url::Url;

#[allow(clippy::reversed_empty_ranges)]
fn yanked() -> Spanned<LintLevel> {
    Spanned::new(LintLevel::Warn, 0..0)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Path to the root directory where advisory databases are stored (default: ~/.cargo/advisory-dbs)
    pub db_path: Option<PathBuf>,
    /// URL to the advisory database's git repo (default: https://github.com/RustSec/advisory-db)
    pub db_url: Option<Spanned<String>>,
    /// List of urls to git repositories of different advisory databases.
    #[serde(default)]
    pub db_urls: Vec<Spanned<String>>,
    /// How to handle crates that have a security vulnerability
    #[serde(default = "crate::lint_deny")]
    pub vulnerability: LintLevel,
    /// How to handle crates that have been marked as unmaintained in an advisory database
    #[serde(default = "crate::lint_warn")]
    pub unmaintained: LintLevel,
    /// How to handle crates that have been marked as unsound in an advisory database
    #[serde(default = "crate::lint_warn")]
    pub unsound: LintLevel,
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
            db_urls: Vec::new(),
            ignore: Vec::new(),
            vulnerability: LintLevel::Deny,
            unmaintained: LintLevel::Warn,
            unsound: LintLevel::Warn,
            yanked: yanked(),
            notice: LintLevel::Warn,
            severity_threshold: None,
        }
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId, diags: &mut Vec<Diagnostic>) -> Self::ValidCfg {
        let mut ignored: Vec<_> = self.ignore.into_iter().map(AdvisoryId::from).collect();
        ignored.sort();

        let mut db_urls: Vec<_> = self
            .db_urls
            .into_iter()
            .filter_map(|dburl| match crate::cfg::parse_url(cfg_file, dburl) {
                Ok(u) => Some(u),
                Err(diag) => {
                    diags.push(diag);
                    None
                }
            })
            .collect();

        if let Some(db_url) = self.db_url {
            diags.push(
                Diagnostic::warning()
                    .with_message("'db_url' is deprecated, use 'db_urls' instead")
                    .with_labels(vec![Label::primary(cfg_file, db_url.span.clone())]),
            );

            match crate::cfg::parse_url(cfg_file, db_url) {
                Ok(url) => db_urls.push(url),
                Err(diag) => {
                    diags.push(diag);
                }
            }
        }

        db_urls.sort();

        // Warn about duplicates before removing them so the user can cleanup their config
        if db_urls.len() > 1 {
            for window in db_urls.windows(2) {
                if window[0] == window[1] {
                    diags.push(
                        Diagnostic::warning()
                            .with_message("duplicate advisory database url detected")
                            .with_labels(vec![
                                Label::secondary(cfg_file, window[0].span.clone()),
                                Label::secondary(cfg_file, window[1].span.clone()),
                            ]),
                    );
                }
            }
        }

        db_urls.dedup();

        // Require that each url has a valid domain name for when we splat it to a local path
        for url in &db_urls {
            if url.value.domain().is_none() {
                diags.push(
                    Diagnostic::error()
                        .with_message("advisory database url doesn't have a domain name")
                        .with_labels(vec![Label::secondary(cfg_file, url.span.clone())]),
                );
            }

            if url.value.scheme() != "https" {
                diags.push(
                    Diagnostic::error()
                        .with_message("advisory database url is not https")
                        .with_labels(vec![Label::secondary(cfg_file, url.span.clone())]),
                );
            }
        }

        ValidConfig {
            file_id: cfg_file,
            db_path: self.db_path,
            db_urls,
            ignore: ignored,
            vulnerability: self.vulnerability,
            unmaintained: self.unmaintained,
            unsound: self.unsound,
            yanked: self.yanked,
            notice: self.notice,
            severity_threshold: self.severity_threshold,
        }
    }
}

pub(crate) type AdvisoryId = Spanned<advisory::Id>;

pub struct ValidConfig {
    pub file_id: FileId,
    pub db_path: Option<PathBuf>,
    pub db_urls: Vec<Spanned<Url>>,
    pub(crate) ignore: Vec<AdvisoryId>,
    pub vulnerability: LintLevel,
    pub unmaintained: LintLevel,
    pub unsound: LintLevel,
    pub yanked: Spanned<LintLevel>,
    pub notice: LintLevel,
    pub severity_threshold: Option<advisory::Severity>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, Fake, UnvalidatedConfig};
    use std::borrow::Cow;

    #[test]
    fn works() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Advisories {
            advisories: Config,
        }

        let cd: ConfigData<Advisories> = load("tests/cfg/advisories.toml");
        let mut diags = Vec::new();
        let validated = cd.config.advisories.validate(cd.id, &mut diags);
        assert!(
            !diags
                .iter()
                .any(|d| d.severity >= crate::diag::Severity::Error),
            "{:#?}",
            diags
        );

        assert_eq!(validated.file_id, cd.id);
        assert!(validated
            .db_path
            .iter()
            .map(|dp| dp.to_string_lossy())
            .eq(vec![Cow::Borrowed("~/.cargo/advisory-dbs")]));
        assert!(validated.db_urls.iter().eq(vec![&Url::parse(
            "https://github.com/RustSec/advisory-db"
        )
        .unwrap()
        .fake()]));
        assert_eq!(validated.vulnerability, LintLevel::Deny);
        assert_eq!(validated.unmaintained, LintLevel::Warn);
        assert_eq!(validated.unsound, LintLevel::Warn);
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
