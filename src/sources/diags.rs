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

impl<'a> From<BelowMinimumRequiredSpec<'a>> for Diag {
    fn from(bmrs: BelowMinimumRequiredSpec<'a>) -> Self {
        Diagnostic::new(Severity::Error)
            .with_message(format!(
                "'git' source is underspecified, expected '{}', but found '{}'",
                bmrs.min_spec, bmrs.actual_spec,
            ))
            .with_code("S001")
            .with_labels(vec![
                bmrs.src_label.clone(),
                bmrs.min_spec_cfg
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

impl<'a> From<ExplicitlyAllowedSource<'a>> for Diag {
    fn from(eas: ExplicitlyAllowedSource<'a>) -> Self {
        Diagnostic::new(Severity::Note)
            .with_message(format!("'{}' source explicitly allowed", eas.type_name))
            .with_code("S002")
            .with_labels(vec![
                eas.src_label.clone(),
                eas.allow_cfg
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

impl<'a> From<SourceAllowedByOrg<'a>> for Diag {
    fn from(sabo: SourceAllowedByOrg<'a>) -> Self {
        Diagnostic::new(Severity::Note)
            .with_message("source allowed by organization allowance")
            .with_code("S003")
            .with_labels(vec![
                sabo.src_label.clone(),
                sabo.org_cfg
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

impl<'a> From<SourceNotExplicitlyAllowed<'a>> for Diag {
    fn from(snea: SourceNotExplicitlyAllowed<'a>) -> Self {
        Diagnostic::new(snea.lint_level.into())
            .with_message(format!(
                "detected '{}' source not explicitly allowed",
                snea.type_name,
            ))
            .with_code("S004")
            .with_labels(vec![snea.src_label.clone()])
            .into()
    }
}

pub(crate) struct UnmatchedAllowSource {
    pub(crate) allow_src_cfg: CfgCoord,
}

impl From<UnmatchedAllowSource> for Diag {
    fn from(uas: UnmatchedAllowSource) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message("allowed source was not encountered")
            .with_code("S005")
            .with_labels(vec![uas
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

impl From<UnmatchedAllowOrg> for Diag {
    fn from(uao: UnmatchedAllowOrg) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message(format!(
                "allowed '{}' organization  was not encountered",
                uao.org_type
            ))
            .with_code("S006")
            .with_labels(vec![uao
                .allow_org_cfg
                .into_label()
                .with_message("no crate source fell under this organization")])
            .into()
    }
}
