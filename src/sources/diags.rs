use crate::{
    diag::{CfgCoord, Diag, Diagnostic, Label, Severity},
    LintLevel,
};

pub(crate) struct BelowMinimumRequiredSpec<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) min_spec: super::cfg::GitSpec,
    pub(crate) actual_spec: super::cfg::GitSpec,
    pub(crate) min_spec_cfg: CfgCoord,
}

impl<'a> Into<Diag> for BelowMinimumRequiredSpec<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Error)
            .with_message(format!(
                "'git' source is underspecified, expected '{}', but found '{}'",
                self.min_spec, self.actual_spec,
            ))
            .with_code("S001")
            .with_labels(vec![
                self.src_label.clone(),
                self.min_spec_cfg
                    .into_label()
                    .with_message("minimum spec defined here"),
            ])
            .into()
    }
}

pub(crate) struct ExplicitlyAllowedSource<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) type_name: &'a str,
    pub(crate) allow_cfg: CfgCoord,
}

impl<'a> Into<Diag> for ExplicitlyAllowedSource<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Note)
            .with_message(format!("'{}' source explicitly allowed", self.type_name))
            .with_code("S002")
            .with_labels(vec![
                self.src_label.clone(),
                self.allow_cfg
                    .into_label()
                    .with_message("source allowance configuration"),
            ])
            .into()
    }
}

pub(crate) struct SourceAllowedByOrg<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) org_cfg: CfgCoord,
}

impl<'a> Into<Diag> for SourceAllowedByOrg<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Note)
            .with_message("source allowed by organization allowance")
            .with_code("S003")
            .with_labels(vec![
                self.src_label.clone(),
                self.org_cfg
                    .into_label()
                    .with_message("org allowance configuration"),
            ])
            .into()
    }
}

pub(crate) struct SourceNotExplicitlyAllowed<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) type_name: &'a str,
    pub(crate) lint_level: LintLevel,
}

impl<'a> Into<Diag> for SourceNotExplicitlyAllowed<'a> {
    fn into(self) -> Diag {
        Diagnostic::new(self.lint_level.into())
            .with_message(format!(
                "detected '{}' source not specifically allowed",
                self.type_name,
            ))
            .with_code("S004")
            .with_labels(vec![self.src_label.clone()])
            .into()
    }
}

pub(crate) struct UnmatchedAllowSource {
    pub(crate) allow_src_cfg: CfgCoord,
}

impl Into<Diag> for UnmatchedAllowSource {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message("allowed source was not encountered")
            .with_code("S005")
            .with_labels(vec![self
                .allow_src_cfg
                .into_label()
                .with_message("no crate source matched these criteria")])
            .into()
    }
}

pub(crate) struct UnmatchedAllowOrg {
    pub(crate) allow_org_cfg: CfgCoord,
    pub(crate) org_type: super::OrgType,
}

impl Into<Diag> for UnmatchedAllowOrg {
    fn into(self) -> Diag {
        Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "allowed '{}' organization  was not encountered",
                self.org_type
            ))
            .with_code("S006")
            .with_labels(vec![self
                .allow_org_cfg
                .into_label()
                .with_message("no crate source fell under this organization")])
            .into()
    }
}
