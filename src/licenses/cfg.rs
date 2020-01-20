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

use crate::LintLevel;
use semver::VersionReq;
use serde::Deserialize;
use std::path::PathBuf;

const fn confidence_threshold() -> f32 {
    0.8
}

/// Allows agreement of licensing terms based on whether the license is
/// [OSI Approved](https://opensource.org/licenses) or [considered free](
/// https://www.gnu.org/licenses/license-list.en.html) by the FSF
#[derive(Deserialize, Debug, PartialEq)]
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
    Neither,
}

impl Default for BlanketAgreement {
    fn default() -> Self {
        BlanketAgreement::Neither
    }
}

/// Configures how private crates are handled and detected
#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Private {
    /// If enabled, ignores workspace crates that aren't published, or are
    /// only published to private registries
    #[serde(default)]
    pub ignore: bool,
    /// One or more private registries that you might publish crates to, if
    /// a crate it only published to private registries, and ignore is true
    /// the crate will not have its license checked
    #[serde(default)]
    pub registries: Vec<String>,
}

/// The path and hash of a LICENSE file
#[derive(PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileSource {
    /// The crate relative path of the LICENSE file
    pub path: PathBuf,
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
    /// The optional version constraint for the crate. Defaults to every version
    pub version: Option<VersionReq>,
    /// The [SPDX expression](https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/)
    /// to apply to the crate.
    pub expression: toml::Spanned<String>,
    /// Files in the crate that are the ground truth for the expression.
    pub license_files: Vec<FileSource>,
}

/// An exception is a way for 1 or more licenses to be allowed only for a
/// particular crate.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Exception {
    /// The name of the crate to apply the exception to.
    pub name: toml::Spanned<String>,
    /// The optional version constraint for the crate. Defaults to every version
    pub version: Option<VersionReq>,
    /// One or more [SPDX identifiers](https://spdx.org/licenses/) that are
    /// allowed only for this crate.
    pub allow: Vec<toml::Spanned<String>>,
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
    /// The minimum confidence threshold we allow when determining the license
    /// in a text file, on a 0.0 (none) to 1.0 (maximum) scale
    #[serde(default = "confidence_threshold")]
    pub confidence_threshold: f32,
    /// Licenses that will be rejected in a license expression
    #[serde(default)]
    pub deny: Vec<toml::Spanned<String>>,
    /// Licenses that will be allowed in a license expression
    #[serde(default)]
    pub allow: Vec<toml::Spanned<String>>,
    /// Overrides the license expression used for a particular crate as long as
    /// it exactly matches the specified license files and hashes
    #[serde(default)]
    pub clarify: Vec<Clarification>,
    /// Allow 1 or more licenses on a per-crate basis, so particular licenses
    /// aren't accepted for every possible crate and must be opted into
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
            confidence_threshold: confidence_threshold(),
            deny: Vec::new(),
            allow: Vec::new(),
            clarify: Vec::new(),
            exceptions: Vec::new(),
        }
    }
}

impl Config {
    /// Validates the configuration provided by the user.
    ///
    /// 1. Ensures all SPDX identifiers are valid
    /// 1. Ensures all SPDX expressions are valid
    /// 1. Ensures the same license is not both allowed and denied
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
    ) -> Result<ValidConfig, Vec<codespan_reporting::diagnostic::Diagnostic>> {
        use crate::diag::{Diagnostic, Label};
        use rayon::prelude::*;

        let mut diagnostics = Vec::new();

        let mut parse_license =
            |ls: &toml::Spanned<String>, v: &mut Vec<Licensee>| match spdx::Licensee::parse(
                ls.get_ref(),
            ) {
                Ok(licensee) => {
                    v.push(Licensee::newu(licensee, ls.start()..ls.end()));
                }
                Err(pe) => {
                    let offset = (ls.start() + 1) as u32;
                    let span = pe.span.start as u32 + offset..pe.span.end as u32 + offset;
                    let diag = Diagnostic::new_error(
                        "invalid licensee",
                        Label::new(cfg_file, span, format!("{}", pe.reason)),
                    );

                    diagnostics.push(diag);
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
                name: crate::Spanned::from(exc.name),
                version: exc.version.unwrap_or_else(VersionReq::any),
                allowed,
            });
        }

        exceptions.par_sort();

        // Ensure the config doesn't contain the same exact license as both
        // denied and allowed, that's confusing and probably not intended, so
        // they should pick one
        for (di, d) in denied.iter().enumerate() {
            if let Ok(ai) = allowed.binary_search(&d) {
                let dlabel = Label::new(
                    cfg_file,
                    self.deny[di].start() as u32..self.deny[di].end() as u32,
                    "marked as `deny`",
                );
                let alabel = Label::new(
                    cfg_file,
                    self.allow[ai].start() as u32..self.allow[ai].end() as u32,
                    "marked as `allow`",
                );

                // Put the one that occurs last as the primary label to make it clear
                // that the first one was "ok" until we noticed this other one
                let diag = if dlabel.span.start() > alabel.span.start() {
                    Diagnostic::new_error(
                        "a license id was specified in both `allow` and `deny`",
                        dlabel,
                    )
                    .with_secondary_labels(std::iter::once(alabel))
                } else {
                    Diagnostic::new_error(
                        "a license id was specified in both `allow` and `deny`",
                        alabel,
                    )
                    .with_secondary_labels(std::iter::once(dlabel))
                };

                diagnostics.push(diag);
            }
        }

        let mut clarifications = Vec::with_capacity(self.clarify.len());
        for c in self.clarify {
            let expr = match spdx::Expression::parse(c.expression.get_ref()) {
                Ok(validated) => validated,
                Err(err) => {
                    let offset = (c.expression.start() + 1) as u32;
                    let expr_span = offset + err.span.start as u32..offset + err.span.end as u32;

                    diagnostics.push(Diagnostic::new_error(
                        "unable to parse license expression",
                        Label::new(cfg_file, expr_span, format!("{}", err.reason)),
                    ));

                    continue;
                }
            };

            let mut license_files = c.license_files;
            license_files.sort_by(|a, b| a.path.cmp(&b.path));

            clarifications.push(ValidClarification {
                name: c.name,
                version: c.version.unwrap_or_else(VersionReq::any),
                expr_offset: (c.expression.start() + 1) as u32,
                expression: expr,
                license_files,
            });
        }

        clarifications.par_sort();

        if !diagnostics.is_empty() {
            Err(diagnostics)
        } else {
            Ok(ValidConfig {
                file_id: cfg_file,
                private: self.private,
                unlicensed: self.unlicensed,
                copyleft: self.copyleft,
                allow_osi_fsf_free: self.allow_osi_fsf_free,
                confidence_threshold: self.confidence_threshold,
                clarifications,
                exceptions,
                denied,
                allowed,
            })
        }
    }
}

#[doc(hidden)]
pub struct ValidClarification {
    pub name: String,
    pub version: VersionReq,
    pub expr_offset: u32,
    pub expression: spdx::Expression,
    pub license_files: Vec<FileSource>,
}

#[doc(hidden)]
#[derive(Debug)]
pub struct ValidException {
    pub name: crate::Spanned<String>,
    pub version: VersionReq,
    pub allowed: Vec<Licensee>,
}

pub type Licensee = crate::Spanned<spdx::Licensee>;

#[doc(hidden)]
pub struct ValidConfig {
    pub file_id: codespan::FileId,
    pub private: Private,
    pub unlicensed: LintLevel,
    pub copyleft: LintLevel,
    pub allow_osi_fsf_free: BlanketAgreement,
    pub confidence_threshold: f32,
    pub denied: Vec<Licensee>,
    pub allowed: Vec<Licensee>,
    pub clarifications: Vec<ValidClarification>,
    pub exceptions: Vec<ValidException>,
}
