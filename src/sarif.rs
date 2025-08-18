use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// SARIF v2.1.0 format structures
/// Based on: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<Result>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Driver {
    pub name: String,
    pub version: String,
    pub semantic_version: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextContent {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultConfiguration {
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Help {
    pub text: String,
    pub markdown: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleProperties {
    pub tags: Vec<String>,
    pub precision: String,
    #[serde(rename = "problem.severity")]
    pub problem_severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Result {
    pub rule_id: String,
    pub message: Message,
    pub level: String,
    pub locations: Vec<Location>,
    pub partial_fingerprints: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalLocation {
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub start_line: u32,
}

impl SarifLog {
    pub fn new() -> Self {
        Self {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![],
        }
    }

    pub fn create_run(tool_name: &str, tool_version: &str) -> Run {
        Run {
            tool: Tool {
                driver: Driver {
                    name: tool_name.to_string(),
                    version: tool_version.to_string(),
                    semantic_version: tool_version.to_string(),
                    rules: vec![],
                },
            },
            results: vec![],
        }
    }
}

/// Convert cargo-deny severity to SARIF level
pub fn severity_to_sarif_level(severity: crate::diag::Severity) -> String {
    use crate::diag::Severity;
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note | Severity::Help => "note",
        Severity::Bug => "error",
    }
    .to_string()
}

/// Convert diagnostic code to SARIF rule ID
pub fn code_to_rule_id(code: crate::diag::DiagnosticCode) -> String {
    format!("{:?}", code)
}