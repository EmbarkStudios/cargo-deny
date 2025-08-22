use crate::{
    LintLevel,
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
    GitSourceUnderspecified,
    AllowedSource,
    AllowedByOrganization,
    SourceNotAllowed,
    UnmatchedSource,
    UnmatchedOrganization,
}

impl Code {
    #[inline]
    pub fn description(self) -> &'static str {
        match self {
            Self::GitSourceUnderspecified => {
                "A git source is using a looser specifier than was allowed"
            }
            Self::AllowedSource => "A crate's source was explicitly allowed",
            Self::AllowedByOrganization => "A git source belonged to an allowed organization/owner",
            Self::SourceNotAllowed => "A crate's source was not explicitly allowed",
            Self::UnmatchedSource => "An allowed source was not used by any crate in the graph",
            Self::UnmatchedOrganization => {
                "An allowed git source organization was not used by any crate in the graph"
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
fn diag(diag: Diagnostic, code: Code) -> Diag {
    Diag::new(diag, Some(crate::diag::DiagnosticCode::Source(code)))
}

pub(crate) struct BelowMinimumRequiredSpec<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) min_spec: super::cfg::GitSpec,
    pub(crate) actual_spec: super::cfg::GitSpec,
    pub(crate) min_spec_cfg: CfgCoord,
}

impl<'a> From<BelowMinimumRequiredSpec<'a>> for Diag {
    fn from(bmrs: BelowMinimumRequiredSpec<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Error)
                .with_message(format_args!(
                    "'git' source is underspecified, expected '{}', but found '{}'",
                    bmrs.min_spec, bmrs.actual_spec,
                ))
                .with_labels(vec![
                    bmrs.src_label.clone(),
                    bmrs.min_spec_cfg
                        .into_label()
                        .with_message("minimum spec defined here"),
                ]),
            Code::GitSourceUnderspecified,
        )
    }
}

pub(crate) struct ExplicitlyAllowedSource<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) type_name: &'a str,
    pub(crate) allow_cfg: CfgCoord,
}

impl<'a> From<ExplicitlyAllowedSource<'a>> for Diag {
    fn from(eas: ExplicitlyAllowedSource<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note)
                .with_message(format_args!(
                    "'{}' source explicitly allowed",
                    eas.type_name
                ))
                .with_labels(vec![
                    eas.src_label.clone(),
                    eas.allow_cfg.into_label().with_message("source allowance"),
                ]),
            Code::AllowedSource,
        )
    }
}

pub(crate) struct SourceAllowedByOrg<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) org_cfg: CfgCoord,
}

impl<'a> From<SourceAllowedByOrg<'a>> for Diag {
    fn from(sabo: SourceAllowedByOrg<'a>) -> Self {
        diag(
            Diagnostic::new(Severity::Note)
                .with_message("source allowed by organization allowance")
                .with_labels(vec![
                    sabo.src_label.clone(),
                    sabo.org_cfg
                        .into_label()
                        .with_message("organization allowance"),
                ]),
            Code::AllowedByOrganization,
        )
    }
}

pub(crate) struct SourceNotExplicitlyAllowed<'a> {
    pub(crate) src_label: &'a Label,
    pub(crate) type_name: &'a str,
    pub(crate) lint_level: LintLevel,
}

impl<'a> From<SourceNotExplicitlyAllowed<'a>> for Diag {
    fn from(snea: SourceNotExplicitlyAllowed<'a>) -> Self {
        diag(
            Diagnostic::new(snea.lint_level.into())
                .with_message(format_args!(
                    "detected '{}' source not explicitly allowed",
                    snea.type_name,
                ))
                .with_labels(vec![snea.src_label.clone()]),
            Code::SourceNotAllowed,
        )
    }
}

pub(crate) struct UnmatchedAllowSource {
    pub(crate) severity: Severity,
    pub(crate) allow_src_cfg: CfgCoord,
}

impl From<UnmatchedAllowSource> for Diag {
    fn from(uas: UnmatchedAllowSource) -> Self {
        diag(
            Diagnostic::new(uas.severity)
                .with_message("allowed source was not encountered")
                .with_labels(vec![
                    uas.allow_src_cfg
                        .into_label()
                        .with_message("no crate source matched these criteria"),
                ]),
            Code::UnmatchedSource,
        )
    }
}

pub(crate) struct UnmatchedAllowOrg {
    pub(crate) allow_org_cfg: CfgCoord,
    pub(crate) org_type: super::OrgType,
}

impl From<UnmatchedAllowOrg> for Diag {
    fn from(uao: UnmatchedAllowOrg) -> Self {
        diag(
            Diagnostic::new(Severity::Warning)
                .with_message(format_args!(
                    "allowed '{}' organization  was not encountered",
                    uao.org_type
                ))
                .with_labels(vec![
                    uao.allow_org_cfg
                        .into_label()
                        .with_message("no crate source fell under this organization"),
                ]),
            Code::UnmatchedOrganization,
        )
    }
}
