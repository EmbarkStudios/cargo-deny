#![cfg_attr(docsrs, doc(include = "../../docs/licenses/cfg.md"))]

//! If a `[license]` configuration section, cargo-deny will use the default
//! configuration.
//!
//! ```
//! use cargo_deny::{LintLevel, licenses::cfg::Config};
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
    cfg::{deprecated, PackageSpec, ValidationContext},
    diag::{Diagnostic, FileId, Label},
    LintLevel, PathBuf, Span, Spanned,
};
use toml_span::{de_helpers::TableHelper, value::Value, DeserError, Deserialize};

const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.8;

/// Allows agreement of licensing terms based on whether the license is
/// [OSI Approved](https://opensource.org/licenses) or [considered free](
/// https://www.gnu.org/licenses/license-list.en.html) by the FSF
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, strum::VariantArray, strum::VariantNames)]
#[cfg_attr(test, derive(serde::Serialize))]
#[strum(serialize_all = "kebab-case")]
pub enum BlanketAgreement {
    /// The license must be both OSI Approved and FSF/Free Libre
    Both,
    /// The license can be be either OSI Approved or FSF/Free Libre
    Either,
    /// The license must be OSI Approved
    Osi,
    /// The license must be FSF/Free
    Fsf,
    /// The license must be OSI Approved but not FSF/Free Libre
    OsiOnly,
    /// The license must be FSF/Free Libre but not OSI Approved
    FsfOnly,
    /// The license is not regarded specially
    #[default]
    Neither,
}

crate::enum_deser!(BlanketAgreement);

/// Configures how private crates are handled and detected
#[derive(Default)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Private {
    /// If enabled, ignores workspace crates that aren't published, or are
    /// only published to private registries
    pub ignore: bool,
    /// One or more URLs to private registries, if a crate comes from one
    /// of these registries, the crate will not have its license checked
    pub ignore_sources: Vec<Spanned<String>>,
    /// One or more private registries that you might publish crates to, if
    /// a crate is only published to private registries, and ignore is true
    /// the crate will not have its license checked
    pub registries: Vec<String>,
}

impl<'de> Deserialize<'de> for Private {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let ignore = th.optional("ignore").unwrap_or_default();
        let ignore_sources = th.optional("ignore-sources").unwrap_or_default();
        let registries = th.optional("registries").unwrap_or_default();

        th.finalize(None)?;

        Ok(Self {
            ignore,
            ignore_sources,
            registries,
        })
    }
}

/// The path and hash of a LICENSE file
#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
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

impl<'de> Deserialize<'de> for FileSource {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let path: Spanned<String> = th.required("path")?;
        let hash = th.required("hash")?;

        th.finalize(None)?;

        Ok(Self {
            path: path.map(),
            hash,
        })
    }
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
pub struct Clarification {
    /// The package spec the clarification applies to
    pub spec: PackageSpec,
    /// The [SPDX expression](https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/)
    /// to apply to the crate.
    pub expression: Spanned<String>,
    /// Files in the crate that are the ground truth for the expression.
    pub license_files: Vec<FileSource>,
}

impl<'de> Deserialize<'de> for Clarification {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let spec = PackageSpec::deserialize(value)?;

        let mut th = TableHelper::new(value)?;

        let expression = th.required("expression")?;
        let license_files = th.required("license-files")?;

        th.finalize(None)?;

        Ok(Self {
            spec,
            expression,
            license_files,
        })
    }
}

/// An exception is a way for 1 or more licenses to be allowed only for a
/// particular crate.
pub struct Exception {
    /// The package spec the exception applies to
    pub spec: PackageSpec,
    /// One or more [SPDX identifiers](https://spdx.org/licenses/) that are
    /// allowed only for this crate.
    pub allow: Vec<Licensee>,
}

impl<'de> Deserialize<'de> for Exception {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let spec = PackageSpec::deserialize(value)?;

        let mut th = TableHelper::new(value)?;
        let allow = th.required("allow")?;

        th.finalize(None)?;

        Ok(Self { spec, allow })
    }
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct Licensee(pub Spanned<spdx::Licensee>);

impl<'de> Deserialize<'de> for Licensee {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let val = value.take_string(Some("an SPDX licensee string"))?;

        match spdx::Licensee::parse(&val) {
            Ok(licensee) => Ok(Self(Spanned::with_span(licensee, value.span))),
            Err(pe) => {
                let offset = value.span.start;

                Err(toml_span::Error {
                    kind: toml_span::ErrorKind::Custom(pe.reason.to_string().into()),
                    span: (pe.span.start + offset..pe.span.end + offset).into(),
                    line_info: None,
                }
                .into())
            }
        }
    }
}

#[cfg(test)]
impl serde::Serialize for Licensee {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.value.to_string().serialize(serializer)
    }
}

/// Top level configuration for the a license check
pub struct Config {
    pub private: Private,
    /// Determines what happens when license information cannot be determined
    /// for a crate
    pub unlicensed: LintLevel,
    /// Accepts license requirements based on whether they are OSI Approved or
    /// FSF/Free Libre
    pub allow_osi_fsf_free: BlanketAgreement,
    /// Determines what happens when a copyleft license is detected
    pub copyleft: LintLevel,
    /// Determines what happens when a license doesn't match any previous
    /// predicates
    pub default: LintLevel,
    /// The minimum confidence threshold we allow when determining the license
    /// in a text file, on a 0.0 (none) to 1.0 (maximum) scale
    pub confidence_threshold: f32,
    /// Licenses that will be rejected in a license expression
    pub deny: Vec<Licensee>,
    /// Licenses that will be allowed in a license expression
    pub allow: Vec<Licensee>,
    /// Determines the response to licenses in th `allow`ed list which do not
    /// exist in the dependency tree.
    pub unused_allowed_license: LintLevel,
    /// Overrides the license expression used for a particular crate as long as
    /// it exactly matches the specified license files and hashes
    pub clarify: Vec<Clarification>,
    /// Allow 1 or more additional licenses on a per-crate basis, so particular
    /// licenses aren't accepted for every possible crate and must be opted into
    pub exceptions: Vec<Exception>,
    /// If true, performs license checks for dev-dependencies for workspace
    /// crates as well
    pub include_dev: bool,
    deprecated: Vec<Span>,
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
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            deny: Vec::new(),
            allow: Vec::new(),
            clarify: Vec::new(),
            exceptions: Vec::new(),
            include_dev: false,
            deprecated: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let mut fdeps = Vec::new();

        let private = th.optional("private").unwrap_or_default();
        let unlicensed = th.optional("unlicensed").unwrap_or(LintLevel::Deny);
        let allow_osi_fsf_free =
            deprecated(&mut th, "allow-osi-fsf-free", &mut fdeps).unwrap_or_default();
        let copyleft = deprecated(&mut th, "copyleft", &mut fdeps).unwrap_or(LintLevel::Warn);
        let default = deprecated(&mut th, "default", &mut fdeps).unwrap_or(LintLevel::Deny);
        let confidence_threshold = th
            .optional("confidence-threshold")
            .unwrap_or(DEFAULT_CONFIDENCE_THRESHOLD);
        let deny = deprecated(&mut th, "deny", &mut fdeps).unwrap_or_default();
        let allow = th.optional("allow").unwrap_or_default();
        let unused_allowed_license = th
            .optional("unused-allowed-license")
            .unwrap_or(LintLevel::Warn);
        let clarify = th.optional("clarify").unwrap_or_default();
        let exceptions = th.optional("exceptions").unwrap_or_default();
        let include_dev = th.optional("include-dev").unwrap_or_default();

        th.finalize(None)?;

        Ok(Self {
            private,
            unlicensed,
            allow_osi_fsf_free,
            copyleft,
            default,
            confidence_threshold,
            deny,
            allow,
            unused_allowed_license,
            clarify,
            exceptions,
            include_dev,
            deprecated: fdeps,
        })
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    /// Validates the configuration provided by the user.
    ///
    /// 1. Ensures all SPDX identifiers are valid
    /// 1. Ensures all SPDX expressions are valid
    /// 1. Ensures the same license is not both allowed and denied
    fn validate(self, mut ctx: ValidationContext<'_>) -> Self::ValidCfg {
        use rayon::prelude::*;

        let mut ignore_sources = Vec::with_capacity(self.private.ignore_sources.len());
        for aurl in &self.private.ignore_sources {
            match url::Url::parse(aurl.as_ref()) {
                Ok(mut url) => {
                    crate::normalize_git_url(&mut url);
                    ignore_sources.push(url);
                }
                Err(pe) => {
                    ctx.push(
                        Diagnostic::error()
                            .with_message("failed to parse url")
                            .with_labels(vec![
                                Label::primary(ctx.cfg_id, aurl.span).with_message(pe.to_string())
                            ]),
                    );
                }
            }
        }

        let mut denied = self.deny;
        let mut allowed = self.allow;

        denied.par_sort();
        allowed.par_sort();

        let mut exceptions = Vec::with_capacity(self.exceptions.len());
        exceptions.extend(self.exceptions.into_iter().map(|exc| ValidException {
            spec: exc.spec,
            allowed: exc.allow,
            file_id: ctx.cfg_id,
        }));

        // Ensure the config doesn't contain the same exact license as both
        // denied and allowed, that's confusing and probably not intended, so
        // they should pick one
        for (di, d) in denied.iter().enumerate() {
            if let Ok(ai) = allowed.binary_search(d) {
                ctx.push(
                    Diagnostic::error()
                        .with_message("a license id was specified in both `allow` and `deny`")
                        .with_labels(vec![
                            Label::secondary(ctx.cfg_id, denied[di].0.span).with_message("deny"),
                            Label::secondary(ctx.cfg_id, allowed[ai].0.span).with_message("allow"),
                        ]),
                );
            }
        }

        let mut clarifications = Vec::with_capacity(self.clarify.len());
        for c in self.clarify {
            let expr = match spdx::Expression::parse(c.expression.as_ref()) {
                Ok(validated) => validated,
                Err(err) => {
                    let offset = c.expression.span.start;
                    let expr_span = offset + err.span.start..offset + err.span.end;

                    ctx.push(
                        Diagnostic::error()
                            .with_message("unable to parse license expression")
                            .with_labels(vec![Label::primary(ctx.cfg_id, expr_span)
                                .with_message(err.reason.to_string())]),
                    );

                    continue;
                }
            };

            let mut license_files = c.license_files;
            license_files.sort_by(|a, b| a.path.cmp(&b.path));

            clarifications.push(ValidClarification {
                spec: c.spec,
                expr_offset: c.expression.span.start,
                expression: expr,
                license_files,
            });
        }

        use crate::diag::general::{Deprecated, DeprecationReason};

        // Output any deprecations, we'll remove the fields at the same time we
        // remove all the logic they drive
        for dep in self.deprecated {
            ctx.push(
                Deprecated {
                    reason: DeprecationReason::WillBeRemoved(Some(
                        "https://github.com/EmbarkStudios/cargo-deny/pull/606",
                    )),
                    key: dep,
                    file_id: ctx.cfg_id,
                }
                .into(),
            )
        }

        ValidConfig {
            file_id: ctx.cfg_id,
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
            include_dev: self.include_dev,
        }
    }
}

pub fn load_exceptions(
    cfg: &mut ValidConfig,
    path: crate::PathBuf,
    files: &mut crate::diag::Files,
    diags: &mut Vec<Diagnostic>,
) {
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(err) => {
            diags.push(
                Diagnostic::error()
                    .with_message("failed to read exceptions override")
                    .with_notes(vec![format!("path = '{path}'"), format!("error = {err:#}")]),
            );
            return;
        }
    };

    let file_id = files.add(path, content);

    let get_exceptions = || -> Result<Vec<Exception>, DeserError> {
        let mut parsed = toml_span::parse(files.source(file_id))?;
        let mut th = TableHelper::new(&mut parsed)?;
        let exceptions = th.required("exceptions")?;
        th.finalize(None)?;
        Ok(exceptions)
    };

    match get_exceptions() {
        Ok(exceptions) => {
            cfg.exceptions.reserve(exceptions.len());
            for exc in exceptions {
                cfg.exceptions.push(ValidException {
                    spec: exc.spec,
                    allowed: exc.allow,
                    file_id,
                });
            }
        }
        Err(err) => {
            diags.extend(err.errors.into_iter().map(|err| err.to_diagnostic(file_id)));
        }
    }
}

#[doc(hidden)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ValidClarification {
    pub spec: PackageSpec,
    pub expr_offset: usize,
    pub expression: spdx::Expression,
    pub license_files: Vec<FileSource>,
}

#[cfg(test)]
impl serde::Serialize for ValidClarification {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("spec", &self.spec)?;
        map.serialize_entry("expression", self.expression.as_ref())?;
        map.serialize_entry("license-files", &self.license_files)?;
        map.end()
    }
}

#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidException {
    pub spec: PackageSpec,
    pub allowed: Vec<Licensee>,
    pub file_id: FileId,
}

#[doc(hidden)]
#[cfg_attr(test, derive(serde::Serialize))]
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
    pub include_dev: bool,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{write_diagnostics, ConfigData};

    struct Licenses {
        licenses: Config,
    }

    impl<'de> toml_span::Deserialize<'de> for Licenses {
        fn deserialize(
            value: &mut toml_span::value::Value<'de>,
        ) -> Result<Self, toml_span::DeserError> {
            let mut th = toml_span::de_helpers::TableHelper::new(value)?;
            let licenses = th.required("licenses").unwrap();
            th.finalize(None)?;
            Ok(Self { licenses })
        }
    }

    #[test]
    fn deserializes_licenses_cfg() {
        let cd = ConfigData::<Licenses>::load("tests/cfg/licenses.toml");
        let validated = cd.validate_with_diags(
            |l| l.licenses,
            |files, diags| {
                let diags = write_diagnostics(files, diags.into_iter());
                insta::assert_snapshot!(diags);
            },
        );

        insta::assert_json_snapshot!(validated);
    }

    #[test]
    fn correct_duplicate_license_spans() {
        let cfg = r#"[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "Unicode-DFS-2016",
]
deny = [
   "MIT",
    "GPL-1.0",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
]"#;

        let cd = ConfigData::<Licenses>::load_str("license-in-allow-and-deny", cfg);
        let _validated = cd.validate_with_diags(
            |l| l.licenses,
            |files, diags| {
                let diags = write_diagnostics(files, diags.into_iter());
                insta::assert_snapshot!(diags);
            },
        );
    }
}
