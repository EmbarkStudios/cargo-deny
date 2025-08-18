use crate::diag::{DiagnosticCode, Severity};
use crate::sarif::{
    ArtifactLocation, DefaultConfiguration, Driver, Help, Location, Message, PhysicalLocation,
    Region, Result as SarifResult, Rule, RuleProperties, Run, SarifLog, TextContent, Tool,
};
use std::collections::{BTreeMap, HashMap};

/// Collects diagnostics and converts them to SARIF format
pub struct SarifCollector {
    diagnostics: Vec<DiagnosticData>,
    rules: HashMap<String, RuleData>,
}

struct DiagnosticData {
    code: DiagnosticCode,
    severity: Severity,
    message: String,
    file_path: String,
    line: u32,
}

struct RuleData {
    code: DiagnosticCode,
    severity: Severity,
    description: String,
}

impl SarifCollector {
    pub fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: HashMap::new(),
        }
    }

    pub fn add_diagnostic(
        &mut self,
        code: DiagnosticCode,
        severity: Severity,
        message: String,
        file_path: String,
        line: u32,
    ) {
        // Add to diagnostics
        self.diagnostics.push(DiagnosticData {
            code,
            severity,
            message: message.clone(),
            file_path,
            line,
        });

        // Add to rules if not already present
        let rule_id = format!("{:?}", code);
        if !self.rules.contains_key(&rule_id) {
            self.rules.insert(
                rule_id,
                RuleData {
                    code,
                    severity,
                    description: get_rule_description(code),
                },
            );
        }
    }

    pub fn generate_sarif(&self) -> SarifLog {
        let mut sarif = SarifLog::new();
        
        // Get cargo-deny version
        let version = env!("CARGO_PKG_VERSION");
        
        // Create rules from collected diagnostics
        let mut rules: Vec<Rule> = Vec::new();
        for (rule_id, rule_data) in &self.rules {
            rules.push(Rule {
                id: rule_id.clone(),
                name: rule_id.clone(),
                short_description: TextContent {
                    text: rule_data.description.clone(),
                },
                full_description: TextContent {
                    text: rule_data.description.clone(),
                },
                default_configuration: DefaultConfiguration {
                    level: severity_to_sarif_level(rule_data.severity),
                },
                help: Help {
                    text: format!("For more information, see cargo-deny documentation"),
                    markdown: format!("[cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/)"),
                },
                properties: RuleProperties {
                    tags: get_rule_tags(rule_data.code),
                    precision: "high".to_string(),
                    problem_severity: severity_to_sarif_level(rule_data.severity),
                },
            });
        }

        // Create results from diagnostics
        let mut results: Vec<SarifResult> = Vec::new();
        for diag in &self.diagnostics {
            let rule_id = format!("{:?}", diag.code);
            let mut fingerprints = BTreeMap::new();
            fingerprints.insert(
                "cargo-deny/fingerprint".to_string(),
                format!("{}:{}:{}", rule_id, diag.file_path, diag.line),
            );

            results.push(SarifResult {
                rule_id: rule_id.clone(),
                message: Message {
                    text: diag.message.clone(),
                },
                level: severity_to_sarif_level(diag.severity),
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: diag.file_path.clone(),
                        },
                        region: Region {
                            start_line: diag.line,
                        },
                    },
                }],
                partial_fingerprints: fingerprints,
            });
        }

        // Create run
        let run = Run {
            tool: Tool {
                driver: Driver {
                    name: "cargo-deny".to_string(),
                    version: version.to_string(),
                    semantic_version: version.to_string(),
                    rules,
                },
            },
            results,
        };

        sarif.runs.push(run);
        sarif
    }
}

fn severity_to_sarif_level(severity: Severity) -> String {
    match severity {
        Severity::Error | Severity::Bug => "error",
        Severity::Warning => "warning",
        Severity::Note | Severity::Help => "note",
    }
    .to_string()
}

fn get_rule_description(code: DiagnosticCode) -> String {
    match code {
        DiagnosticCode::Advisory(_) => "Security advisory or vulnerability detected".to_string(),
        DiagnosticCode::License(_) => "License compliance issue detected".to_string(),
        DiagnosticCode::Bans(_) => "Banned or duplicate dependency detected".to_string(),
        DiagnosticCode::Source(_) => "Crate source issue detected".to_string(),
        DiagnosticCode::General(_) => "General cargo-deny check issue".to_string(),
    }
}

fn get_rule_tags(code: DiagnosticCode) -> Vec<String> {
    match code {
        DiagnosticCode::Advisory(_) => vec!["security".to_string(), "vulnerability".to_string()],
        DiagnosticCode::License(_) => vec!["license".to_string(), "compliance".to_string()],
        DiagnosticCode::Bans(_) => vec!["dependencies".to_string(), "supply-chain".to_string()],
        DiagnosticCode::Source(_) => vec!["sources".to_string(), "supply-chain".to_string()],
        DiagnosticCode::General(_) => vec!["cargo-deny".to_string()],
    }
}