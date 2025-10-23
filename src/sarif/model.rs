//! SARIF v2.1.0 format structures
//! Based on: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>

use serde::{Serialize, ser::SerializeMap};
use std::collections::BTreeMap;

pub struct SarifLog {
    pub runs: Vec<Run>,
}

impl Serialize for SarifLog {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(3))?;
        m.serialize_entry("$schema", "https://json.schemastore.org/sarif-2.1.0.json")?;
        m.serialize_entry("version", "2.1.0")?;
        m.serialize_entry("runs", &self.runs)?;
        m.end()
    }
}

#[derive(Serialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<Result>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub driver: Driver,
}

pub struct Driver {
    pub rules: Vec<Rule>,
    pub version: Option<semver::Version>,
}

impl Serialize for Driver {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(4))?;
        m.serialize_entry("name", "cargo-deny")?;
        if let Some(v) = &self.version {
            m.serialize_entry("version", &v)?;
            m.serialize_entry("semanticVersion", &v)?;
        } else {
            m.serialize_entry("version", env!("CARGO_PKG_VERSION"))?;
            m.serialize_entry("semanticVersion", env!("CARGO_PKG_VERSION"))?;
        }
        m.serialize_entry("rules", &self.rules)?;
        m.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub short_description: TextContent,
    pub full_description: TextContent,
    pub default_configuration: DefaultConfiguration,
    pub help: Help,
    pub properties: RuleProperties,
}

#[derive(Serialize)]
pub struct TextContent {
    pub text: String,
}

#[derive(Serialize)]
pub struct DefaultConfiguration {
    pub level: String,
}

pub struct Help(pub crate::diag::DiagnosticCode);

impl Serialize for Help {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(2))?;
        m.serialize_entry("text", "For more information, see cargo-deny documentation")?;

        let (check, code): (_, &'static str) = match self.0 {
            crate::diag::DiagnosticCode::Advisory(code) => ("advisories", code.into()),
            crate::diag::DiagnosticCode::Bans(code) => ("bans", code.into()),
            crate::diag::DiagnosticCode::License(code) => ("licenses", code.into()),
            crate::diag::DiagnosticCode::Source(code) => ("sources", code.into()),
            crate::diag::DiagnosticCode::General(_code) => {
                return m.end();
            }
        };

        const DOC_ROOT: &str = "https://embarkstudios.github.io/cargo-deny/";

        m.serialize_entry(
            "markdown",
            &format!("[{check} check]({DOC_ROOT}checks/{check}/index.html)\n[{code} diagnostic]({DOC_ROOT}checks/{check}/diags.html#{code})"),
        )?;
        m.end()
    }
}

#[derive(Serialize)]
pub struct RuleProperties {
    pub tags: &'static [&'static str],
    pub precision: &'static str,
    #[serde(rename = "problem.severity")]
    pub problem_severity: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Result {
    pub rule_id: String,
    pub message: Message,
    pub level: &'static str,
    pub locations: Vec<Location>,
    pub partial_fingerprints: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct Message {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

impl Message {
    #[inline]
    pub fn text(text: String) -> Self {
        Self {
            text,
            markdown: None,
        }
    }
}

#[derive(Serialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Debug, Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub start_line: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Convert cargo-deny severity to SARIF level
#[inline]
pub fn severity_to_sarif_level(severity: crate::diag::Severity) -> &'static str {
    use crate::diag::Severity;
    match severity {
        Severity::Error | Severity::Bug => "error",
        Severity::Warning => "warning",
        Severity::Note | Severity::Help => "note",
    }
}
