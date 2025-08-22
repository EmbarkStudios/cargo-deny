use crate::{
    Krate,
    diag::{CfgCoord, Diag, Diagnostic, Label, Severity},
};

#[derive(
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Code {
    Accepted,
    Rejected,
    Unlicensed,
    SkippedPrivateWorkspaceCrate,
    LicenseNotEncountered,
    LicenseExceptionNotEncountered,
    MissingClarificationFile,
    ParseError,
    EmptyLicenseField,
    NoLicenseField,
    GatherFailure,
}

impl Code {
    #[inline]
    pub fn description(self) -> &'static str {
        match self {
            Self::Accepted => "A license was explicitly accepted",
            Self::Rejected => "A license was not explicitly accepted",
            Self::Unlicensed => "A license expression could not be determined for a crate",
            Self::SkippedPrivateWorkspaceCrate => {
                "A private workspace crate was skipped during the license check"
            }
            Self::LicenseNotEncountered => {
                "An allowed license was not used by any crate in the graph"
            }
            Self::LicenseExceptionNotEncountered => {
                "A license exception was not used by any crate in the graph"
            }
            Self::MissingClarificationFile => {
                "A license clarification file was not found in the crate's source"
            }
            Self::ParseError => "Failed to parse an SPDX expression",
            Self::EmptyLicenseField => "A crate declared an empty license field",
            Self::NoLicenseField => "A crate did not have a license field",
            Self::GatherFailure => {
                "An error occurred gathering a license file from the crate's source"
            }
        }
    }
}

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
}

#[inline]
pub(crate) fn diag(diag: Diagnostic, code: Code) -> Diag {
    Diag::new(diag, Some(crate::diag::DiagnosticCode::License(code)))
}

pub(crate) struct Unlicensed<'a> {
    pub(crate) severity: Severity,
    pub(crate) krate: &'a Krate,
}

impl<'a> From<Unlicensed<'a>> for Diag {
    fn from(u: Unlicensed<'a>) -> Self {
        diag(
            Diagnostic::new(u.severity).with_message(format_args!("{} is unlicensed", u.krate)),
            Code::Unlicensed,
        )
    }
}

pub(crate) struct SkippedPrivateWorkspaceCrate<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<SkippedPrivateWorkspaceCrate<'a>> for Diag {
    fn from(spwc: SkippedPrivateWorkspaceCrate<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note).with_message(format_args!(
                "skipping private workspace crate '{}'",
                spwc.krate
            )),
            Code::SkippedPrivateWorkspaceCrate,
        )
    }
}

pub(crate) struct UnmatchedLicenseAllowance {
    pub(crate) severity: Severity,
    pub(crate) allowed_license_cfg: CfgCoord,
}

impl From<UnmatchedLicenseAllowance> for Diag {
    fn from(ula: UnmatchedLicenseAllowance) -> Self {
        diag(
            Diagnostic::new(ula.severity)
                .with_message("license was not encountered")
                .with_labels(vec![
                    ula.allowed_license_cfg
                        .into_label()
                        .with_message("unmatched license allowance"),
                ]),
            Code::LicenseNotEncountered,
        )
    }
}

pub(crate) struct UnmatchedLicenseException {
    pub(crate) license_exc_cfg: CfgCoord,
}

impl From<UnmatchedLicenseException> for Diag {
    fn from(ule: UnmatchedLicenseException) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("license exception was not encountered")
                .with_labels(vec![
                    ule.license_exc_cfg
                        .into_label()
                        .with_message("unmatched license exception"),
                ]),
            Code::LicenseExceptionNotEncountered,
        )
    }
}

pub(crate) struct MissingClarificationFile<'a> {
    pub(crate) expected: &'a crate::cfg::Spanned<crate::PathBuf>,
    pub(crate) cfg_file_id: crate::diag::FileId,
}

impl<'a> From<MissingClarificationFile<'a>> for Diag {
    fn from(mcf: MissingClarificationFile<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("unable to locate specified license file")
                .with_labels(vec![Label::secondary(mcf.cfg_file_id, mcf.expected.span)]),
            Code::MissingClarificationFile,
        )
    }
}

pub(crate) struct ParseError {
    pub(crate) span: std::ops::Range<usize>,
    pub(crate) file_id: crate::diag::FileId,
    pub(crate) error: spdx::ParseError,
}

impl From<ParseError> for Diag {
    fn from(pe: ParseError) -> Self {
        let span = pe.span.start + pe.error.span.start..pe.span.start + pe.error.span.end;

        diag(
            Diagnostic::new(Severity::Warning)
                .with_message("error parsing SPDX license expression")
                .with_labels(vec![
                    Label::secondary(pe.file_id, span).with_message(pe.error.reason),
                ]),
            Code::ParseError,
        )
    }
}

/// crates.io used to allow empty license fields, this is a distinct error
/// from an invalid or missing license field <https://github.com/ehuss/license-exprs/issues/23>
pub(crate) struct EmptyLicenseField {
    pub(crate) span: std::ops::Range<usize>,
    pub(crate) file_id: crate::diag::FileId,
}

impl From<EmptyLicenseField> for Diag {
    fn from(value: EmptyLicenseField) -> Self {
        diag(
            Diagnostic::warning()
                .with_message("license field was present but empty")
                .with_label(
                    Label::secondary(value.file_id, value.span).with_message("empty field"),
                ),
            Code::EmptyLicenseField,
        )
    }
}

pub(crate) struct NoLicenseField;

impl From<NoLicenseField> for Diag {
    fn from(_value: NoLicenseField) -> Self {
        diag(
            Diagnostic::warning().with_message("license expression was not specified in manifest"),
            Code::NoLicenseField,
        )
    }
}
