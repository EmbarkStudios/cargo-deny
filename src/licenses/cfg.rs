#![cfg_attr(docsrs, doc(include = "../../docs/licenses/cfg.md"))]

//! If a `[license]` configuration section, cargo-deny will use the default
//! configuration.
//!
//! ```
//! use cargo_deny::{LintLevel, licenses::Config};
//!
//! let dc = Config::default();
//!
//! assert_eq!(dc.unlicensed, LintLevel::Deny);
//! assert_eq!(
//!     dc.allow_osi_fsf_free,
//!     cargo_deny::licenses::cfg::BlanketAgreement::Neither
//! );
//! assert_eq!(dc.copyleft, LintLevel::Warn);
//! assert_eq!(dc.confidence_threshold, 0.8);
//! assert!(dc.deny.is_empty());
//! assert!(dc.allow.is_empty());
//! assert!(dc.clarify.is_empty());
//! assert!(dc.exceptions.is_empty());
//! ```

use crate::{
    diag::{Diagnostic, FileId, Label},
    LintLevel, PathBuf, Spanned,
};
use semver::VersionReq;
use serde::Deserialize;

const fn confidence_threshold() -> f32 {
    0.8
}

/// Allows agreement of licensing terms based on whether the license is
/// [OSI Approved](https://opensource.org/licenses) or [considered free](
/// https://www.gnu.org/licenses/license-list.en.html) by the FSF
#[derive(Deserialize, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum BlanketAgreement {
    /// The license must be both OSI Approved and FSF/Free Libre
    Both,
    /// The license can be be either OSI Approved or FSF/Free Libre
    Either,
    /// The license must be OSI Approved but not FSF/Free Libre
    OsiOnly,
    /// The license must be FSF/Free Libre but not OSI Approved
    FsfOnly,
    /// The license is not regarded specially
    #[default]
    Neither,
}

/// Configures how private crates are handled and detected
#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Private {
    /// If enabled, ignores workspace crates that aren't published, or are
    /// only published to private registries
    #[serde(default)]
    pub ignore: bool,
    /// One or more URLs to private registries, if a crate comes from one
    /// of these registries, the crate will not have its license checked
    #[serde(default)]
    pub ignore_sources: Vec<Spanned<String>>,
    /// One or more private registries that you might publish crates to, if
    /// a crate is only published to private registries, and ignore is true
    /// the crate will not have its license checked
    #[serde(default)]
    pub registries: Vec<String>,
}

/// The path and hash of a LICENSE file
#[derive(PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileSource {
    /// The crate relative path of the LICENSE file
    /// Spanned so we can report typos on it in case it never matches anything.
    pub path: Spanned<PathBuf>,
    /// The hash of the LICENSE text. If the `path`'s hash
    /// differs from the contents of the path, the file is
    /// parsed to determine if the license(s) contained in
    /// it are still the same
    pub hash: u32,
}

/// Some crates have complicated LICENSE files that eg contain multiple license
/// texts in a single file, or are otherwise sufficiently different from the
/// canonical license text that the confidence level cargo-deny can attribute to
/// them falls below the `confidence-threshold` you want generally across all
/// license texts. `Clarification`s allow you to manually assign the
/// [SPDX expression](https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/)
/// to use for a particular crate as well as 1 or more file sources used as the
/// ground truth for that expression. If the files change in a future version
/// of the crate, the clarification will be ignored and the crate will be checked
/// as normal.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Clarification {
    /// The name of the crate that this clarification applies to
    pub name: String,
    /// The optional version constraint for the crate. Defaults to any version.
    pub version: Option<VersionReq>,
    /// The [SPDX expression](https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/)
    /// to apply to the crate.
    pub expression: Spanned<String>,
    /// Files in the crate that are the ground truth for the expression.
    pub license_files: Vec<FileSource>,
}

/// An exception is a way for 1 or more licenses to be allowed only for a
/// particular crate.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Exception {
    /// The name of the crate to apply the exception to.
    pub name: Spanned<String>,
    /// The optional version constraint for the crate. Defaults to any version.
    pub version: Option<VersionReq>,
    /// One or more [SPDX identifiers](https://spdx.org/licenses/) that are
    /// allowed only for this crate.
    pub allow: Vec<Spanned<String>>,
}

/// Top level configuration for the a license check
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub private: Private,
    /// Determines what happens when license information cannot be determined
    /// for a crate
    #[serde(default = "crate::lint_deny")]
    pub unlicensed: LintLevel,
    /// Accepts license requirements based on whether they are OSI Approved or
    /// FSF/Free Libre
    #[serde(default)]
    pub allow_osi_fsf_free: BlanketAgreement,
    /// Determines what happens when a copyleft license is detected
    #[serde(default = "crate::lint_warn")]
    pub copyleft: LintLevel,
    /// Determines what happens when a license doesn't match any previous
    /// predicates
    #[serde(default = "crate::lint_deny")]
    pub default: LintLevel,
    /// The minimum confidence threshold we allow when determining the license
    /// in a text file, on a 0.0 (none) to 1.0 (maximum) scale
    #[serde(default = "confidence_threshold")]
    pub confidence_threshold: f32,
    /// Licenses that will be rejected in a license expression
    #[serde(default)]
    pub deny: Vec<Spanned<String>>,
    /// Licenses that will be allowed in a license expression
    #[serde(default)]
    pub allow: Vec<Spanned<String>>,
    /// Determines the response to licenses in th `allow`ed list which do not
    /// exist in the dependency tree.
    #[serde(default = "crate::lint_warn")]
    pub unused_allowed_license: LintLevel,
    /// Overrides the license expression used for a particular crate as long as
    /// it exactly matches the specified license files and hashes
    #[serde(default)]
    pub clarify: Vec<Clarification>,
    /// Allow 1 or more additional licenses on a per-crate basis, so particular
    /// licenses aren't accepted for every possible crate and must be opted into
    #[serde(default)]
    pub exceptions: Vec<Exception>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private: Private::default(),
            unlicensed: LintLevel::Deny,
            allow_osi_fsf_free: BlanketAgreement::default(),
            copyleft: LintLevel::Warn,
            default: LintLevel::Deny,
            unused_allowed_license: LintLevel::Warn,
            confidence_threshold: confidence_threshold(),
            deny: Vec::new(),
            allow: Vec::new(),
            clarify: Vec::new(),
            exceptions: Vec::new(),
        }
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    /// Validates the configuration provided by the user.
    ///
    /// 1. Ensures all SPDX identifiers are valid
    /// 1. Ensures all SPDX expressions are valid
    /// 1. Ensures the same license is not both allowed and denied
    fn validate(self, cfg_file: FileId, diags: &mut Vec<Diagnostic>) -> Self::ValidCfg {
        use rayon::prelude::*;

        let mut ignore_sources = Vec::with_capacity(self.private.ignore_sources.len());
        for aurl in &self.private.ignore_sources {
            match url::Url::parse(aurl.as_ref()) {
                Ok(mut url) => {
                    crate::normalize_git_url(&mut url);
                    ignore_sources.push(url);
                }
                Err(pe) => {
                    diags.push(
                        Diagnostic::error()
                            .with_message("failed to parse url")
                            .with_labels(vec![Label::primary(cfg_file, aurl.span.clone())
                                .with_message(pe.to_string())]),
                    );
                }
            }
        }

        let mut parse_license = |ls: &Spanned<String>, v: &mut Vec<Licensee>| {
            match spdx::Licensee::parse(ls.as_ref()) {
                Ok(licensee) => {
                    v.push(Licensee::new(licensee, ls.span.clone()));
                }
                Err(pe) => {
                    let offset = ls.span.start + 1;
                    let span = pe.span.start + offset..pe.span.end + offset;
                    diags.push(
                        Diagnostic::error()
                            .with_message("invalid licensee")
                            .with_labels(vec![Label::primary(cfg_file, span)
                                .with_message(format!("{}", pe.reason))]),
                    );
                }
            }
        };

        let mut denied = Vec::with_capacity(self.deny.len());
        for d in &self.deny {
            parse_license(d, &mut denied);
        }

        let mut allowed: Vec<Licensee> = Vec::with_capacity(self.allow.len());
        for a in &self.allow {
            parse_license(a, &mut allowed);
        }

        denied.par_sort();
        allowed.par_sort();

        let mut exceptions = Vec::with_capacity(self.exceptions.len());
        for exc in self.exceptions {
            let mut allowed = Vec::with_capacity(exc.allow.len());

            for allow in &exc.allow {
                parse_license(allow, &mut allowed);
            }

            exceptions.push(ValidException {
                name: exc.name,
                version: exc.version,
                allowed,
            });
        }

        // Ensure the config doesn't contain the same exact license as both
        // denied and allowed, that's confusing and probably not intended, so
        // they should pick one
        for (di, d) in denied.iter().enumerate() {
            if let Ok(ai) = allowed.binary_search(d) {
                diags.push(
                    Diagnostic::error()
                        .with_message("a license id was specified in both `allow` and `deny`")
                        .with_labels(vec![
                            Label::secondary(cfg_file, self.deny[di].span.clone())
                                .with_message("deny"),
                            Label::secondary(cfg_file, self.allow[ai].span.clone())
                                .with_message("allow"),
                        ]),
                );
            }
        }

        let mut clarifications = Vec::with_capacity(self.clarify.len());
        for c in self.clarify {
            let expr = match spdx::Expression::parse(c.expression.as_ref()) {
                Ok(validated) => validated,
                Err(err) => {
                    let offset = c.expression.span.start + 1;
                    let expr_span = offset + err.span.start..offset + err.span.end;

                    diags.push(
                        Diagnostic::error()
                            .with_message("unable to parse license expression")
                            .with_labels(vec![Label::primary(cfg_file, expr_span)
                                .with_message(format!("{}", err.reason))]),
                    );

                    continue;
                }
            };

            let mut license_files = c.license_files;
            license_files.sort_by(|a, b| a.path.cmp(&b.path));

            clarifications.push(ValidClarification {
                name: c.name,
                version: c.version,
                expr_offset: (c.expression.span.start + 1),
                expression: expr,
                license_files,
            });
        }

        ValidConfig {
            file_id: cfg_file,
            private: self.private,
            unlicensed: self.unlicensed,
            copyleft: self.copyleft,
            default: self.default,
            unused_allowed_license: self.unused_allowed_license,
            allow_osi_fsf_free: self.allow_osi_fsf_free,
            confidence_threshold: self.confidence_threshold,
            clarifications,
            exceptions,
            denied,
            allowed,
            ignore_sources,
        }
    }
}

#[doc(hidden)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ValidClarification {
    pub name: String,
    pub version: Option<VersionReq>,
    pub expr_offset: usize,
    pub expression: spdx::Expression,
    pub license_files: Vec<FileSource>,
}

#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidException {
    pub name: crate::Spanned<String>,
    pub version: Option<VersionReq>,
    pub allowed: Vec<Licensee>,
}

pub type Licensee = Spanned<spdx::Licensee>;

#[doc(hidden)]
pub struct ValidConfig {
    pub file_id: FileId,
    pub private: Private,
    pub unlicensed: LintLevel,
    pub copyleft: LintLevel,
    pub unused_allowed_license: LintLevel,
    pub allow_osi_fsf_free: BlanketAgreement,
    pub default: LintLevel,
    pub confidence_threshold: f32,
    pub denied: Vec<Licensee>,
    pub allowed: Vec<Licensee>,
    pub clarifications: Vec<ValidClarification>,
    pub exceptions: Vec<ValidException>,
    pub ignore_sources: Vec<url::Url>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, *};

    #[test]
    fn deserializes_licenses_cfg() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Licenses {
            licenses: Config,
        }

        let cd: ConfigData<Licenses> = load("tests/cfg/licenses.toml");

        let mut diags = Vec::new();
        let validated = cd.config.licenses.validate(cd.id, &mut diags);
        assert!(diags.is_empty());

        assert_eq!(validated.file_id, cd.id);
        assert!(validated.private.ignore);
        assert_eq!(validated.private.registries, vec!["sekrets".to_owned()]);
        assert_eq!(validated.unlicensed, LintLevel::Warn);
        assert_eq!(validated.copyleft, LintLevel::Deny);
        assert_eq!(validated.unused_allowed_license, LintLevel::Warn);
        assert_eq!(validated.default, LintLevel::Warn);
        assert_eq!(validated.allow_osi_fsf_free, BlanketAgreement::Both);
        assert_eq!(
            validated.allowed,
            vec![
                spdx::Licensee::parse("Apache-2.0 WITH LLVM-exception").unwrap(),
                spdx::Licensee::parse("EUPL-1.2").unwrap(),
            ]
        );
        assert_eq!(
            validated.denied,
            vec![
                spdx::Licensee::parse("BSD-2-Clause").unwrap(),
                spdx::Licensee::parse("Nokia").unwrap(),
            ]
        );
        assert_eq!(
            validated.exceptions,
            vec![ValidException {
                name: "adler32".to_owned().fake(),
                allowed: vec![spdx::Licensee::parse("Zlib").unwrap().fake()],
                version: Some(semver::VersionReq::parse("0.1.1").unwrap()),
            }]
        );
        let p: PathBuf = "LICENSE".into();
        assert_eq!(
            validated.clarifications,
            vec![ValidClarification {
                name: "ring".to_owned(),
                version: None,
                expression: spdx::Expression::parse("MIT AND ISC AND OpenSSL").unwrap(),
                license_files: vec![FileSource {
                    path: p.fake(),
                    hash: 0xbd0e_ed23,
                }],
                expr_offset: 450,
            }]
        );
    }
}
