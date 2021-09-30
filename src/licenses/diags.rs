use crate::{
    diag::{CfgCoord, Diag, Diagnostic, Label, Severity},
    Krate,
};

pub(crate) struct Unlicensed<'a> {
    pub(crate) severity: Severity,
    pub(crate) krate: &'a Krate,
    pub(crate) breadcrumbs: Vec<Label>,
}

impl<'a> Into<Diag> for Unlicensed<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(self.severity)
            .with_message(format!("{} is unlicensed", self.krate))
            .with_code("L003")
            .with_labels(self.breadcrumbs)
            .into()
    }
}

pub(crate) struct SkippedPrivateWorkspaceCrate<'a> {
    pub(crate) krate: &'a Krate,
}

impl<'a> Into<Diag> for SkippedPrivateWorkspaceCrate<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Help)
            .with_message(format!("skipping private workspace crate '{}'", self.krate))
            .with_code("L004")
            .into()
    }
}

pub(crate) struct UnmatchedLicenseException {
    pub(crate) license_exc_cfg: CfgCoord,
}

impl Into<Diag> for UnmatchedLicenseException {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message("license exception was not encountered")
            .with_code("L005")
            .with_labels(vec![self
                .license_exc_cfg
                .into_label()
                .with_message("unmatched license exception")])
            .into()
    }
}

pub(crate) struct UnmatchedLicenseAllowance {
    pub(crate) severity: Severity,
    pub(crate) allowed_license_cfg: CfgCoord,
}

impl Into<Diag> for UnmatchedLicenseAllowance {
    fn into(self) -> Diag {
        Diagnostic::new(self.severity)
            .with_message("license was not encountered")
            .with_code("L006")
            .with_labels(vec![self
                .allowed_license_cfg
                .into_label()
                .with_message("unmatched license allowance")])
            .into()
    }
}

pub(crate) struct MissingClarificationFile<'a> {
    pub(crate) expected: &'a crate::cfg::Spanned<std::path::PathBuf>,
    pub(crate) cfg_file_id: crate::diag::FileId,
}

impl<'a> Into<Label> for MissingClarificationFile<'a> {
    fn into(self) -> Label {
        Label::secondary(self.cfg_file_id, self.expected.span.clone())
            .with_message("unable to locate specified license file")
    }
}
