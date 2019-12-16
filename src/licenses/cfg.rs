use crate::LintLevel;
use semver::VersionReq;
use serde::Deserialize;
use spdx::Licensee;
use std::path::PathBuf;

const fn confidence_threshold() -> f32 {
    0.8
}

/// Allows agreement of licensing terms based on whether the license is
/// [OSI Approved](https://opensource.org/licenses) or [considered free](
/// https://www.gnu.org/licenses/license-list.en.html) by the FSF
#[derive(Deserialize)]
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

#[derive(PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileSource {
    /// The crate relative path of the LICENSE file
    pub path: PathBuf,
    /// The hash of the LICENSE text
    pub hash: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Clarification {
    pub name: String,
    pub version: Option<VersionReq>,
    pub expression: toml::Spanned<String>,
    pub license_files: Vec<FileSource>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Determines what happens when license information cannot be
    /// determined for a crate
    #[serde(default = "crate::lint_deny")]
    pub unlicensed: LintLevel,
    /// Agrees to licenses based on whether they are OSI Approved
    /// or FSF/Free Libre
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
    /// Overrides the license expression used for a particular crate as long as it
    /// exactly matches the specified license files and hashes
    #[serde(default)]
    pub clarify: Vec<Clarification>,
}

impl Config {
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
    ) -> Result<ValidConfig, Vec<codespan_reporting::diagnostic::Diagnostic>> {
        use crate::diag::{Diagnostic, Label};
        use rayon::prelude::*;

        let mut diagnostics = Vec::new();

        let mut parse_license =
            |l: &toml::Spanned<String>, v: &mut Vec<Licensee>| match Licensee::parse(l.get_ref()) {
                Ok(l) => v.push(l),
                Err(pe) => {
                    let offset = (l.start() + 1) as u32;
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

        // Ensure the config doesn't contain the same exact license as
        // both denied and allowed, that's confusing and probably
        // not intended, so they should pick one
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
                unlicensed: self.unlicensed,
                copyleft: self.copyleft,
                allow_osi_fsf_free: self.allow_osi_fsf_free,
                confidence_threshold: self.confidence_threshold,
                clarifications,
                denied,
                allowed,
            })
        }
    }
}

pub struct ValidClarification {
    pub name: String,
    pub version: VersionReq,
    pub expr_offset: u32,
    pub expression: spdx::Expression,
    pub license_files: Vec<FileSource>,
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,
    pub unlicensed: LintLevel,
    pub copyleft: LintLevel,
    pub allow_osi_fsf_free: BlanketAgreement,
    pub confidence_threshold: f32,
    pub denied: Vec<Licensee>,
    pub allowed: Vec<Licensee>,
    pub clarifications: Vec<ValidClarification>,
}
