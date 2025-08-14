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
}

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
}

pub(crate) struct Unlicensed<'a> {
    pub(crate) severity: Severity,
    pub(crate) krate: &'a Krate,
}

impl<'a> From<Unlicensed<'a>> for Diag {
    fn from(u: Unlicensed<'a>) -> Self {
        Diagnostic::new(u.severity)
            .with_message(format_args!("{} is unlicensed", u.krate))
            .with_code(Code::Unlicensed)
            .into()
    }
}

pub(crate) struct SkippedPrivateWorkspaceCrate<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> From<SkippedPrivateWorkspaceCrate<'a>> for Diag {
    fn from(spwc: SkippedPrivateWorkspaceCrate<'a>) -> Self {
        Diagnostic::new(Severity::Note)
            .with_message(format_args!(
                "skipping private workspace crate '{}'",
                spwc.krate
            ))
            .with_code(Code::SkippedPrivateWorkspaceCrate)
            .into()
    }
}

pub(crate) struct UnmatchedLicenseAllowance {
    pub(crate) severity: Severity,
    pub(crate) allowed_license_cfg: CfgCoord,
}

impl From<UnmatchedLicenseAllowance> for Diag {
    fn from(ula: UnmatchedLicenseAllowance) -> Self {
        Diagnostic::new(ula.severity)
            .with_message("license was not encountered")
            .with_code(Code::LicenseNotEncountered)
            .with_labels(vec![
                ula.allowed_license_cfg
                    .into_label()
                    .with_message("unmatched license allowance"),
            ])
            .into()
    }
}

pub(crate) struct UnmatchedLicenseException {
    pub(crate) license_exc_cfg: CfgCoord,
}

impl From<UnmatchedLicenseException> for Diag {
    fn from(ule: UnmatchedLicenseException) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message("license exception was not encountered")
            .with_code(Code::LicenseExceptionNotEncountered)
            .with_labels(vec![
                ule.license_exc_cfg
                    .into_label()
                    .with_message("unmatched license exception"),
            ])
            .into()
    }
}

pub(crate) struct MissingClarificationFile<'a> {
    pub(crate) expected: &'a crate::cfg::Spanned<crate::PathBuf>,
    pub(crate) cfg_file_id: crate::diag::FileId,
}

impl<'a> From<MissingClarificationFile<'a>> for Diagnostic {
    fn from(mcf: MissingClarificationFile<'a>) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message("unable to locate specified license file")
            .with_code(Code::MissingClarificationFile)
            .with_labels(vec![Label::secondary(mcf.cfg_file_id, mcf.expected.span)])
    }
}

pub(crate) struct ParseError {
    pub(crate) span: std::ops::Range<usize>,
    pub(crate) file_id: crate::diag::FileId,
    pub(crate) error: spdx::ParseError,
}

impl From<ParseError> for Diagnostic {
    fn from(pe: ParseError) -> Self {
        let span = pe.span.start + pe.error.span.start..pe.span.start + pe.error.span.end;

        Diagnostic::new(Severity::Warning)
            .with_message("error parsing SPDX license expression")
            .with_code(Code::ParseError)
            .with_labels(vec![
                Label::secondary(pe.file_id, span).with_message(pe.error.reason),
            ])
    }
}
