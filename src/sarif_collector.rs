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

#[allow(clippy::derivable_impls)]
impl Default for SarifCollector {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: HashMap::new(),
        }
    }
}

impl SarifCollector {
    pub fn add_diagnostic(
        &mut self,
        code: DiagnosticCode,
        severity: Severity,
        message: String,
        file_path: String,
        line: u32,
    ) {
        // Filter out note and help severities - SARIF should only contain actionable issues
        if matches!(severity, Severity::Note | Severity::Help) {
            return;
        }
        
        // Add to diagnostics
        self.diagnostics.push(DiagnosticData {
            code,
            severity,
            message: message.clone(),
            file_path,
            line,
        });

        // Add to rules if not already present
        let rule_id = format_rule_id(code);
        self.rules.entry(rule_id).or_insert(RuleData {
            code,
            severity,
            description: get_rule_description(code).to_string(),
        });
    }

    pub fn add_diagnostic_with_code(
        &mut self,
        code_str: String,
        severity: Severity,
        message: String,
        file_path: String,
        line: u32,
    ) {
        // Parse the diagnostic code from the string
        let diagnostic_code = parse_diagnostic_code(&code_str);
        self.add_diagnostic(diagnostic_code, severity, message, file_path, line);
    }

    pub fn generate_sarif(&self) -> SarifLog {
        let mut sarif = SarifLog::default();

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
                    text: "For more information, see cargo-deny documentation".to_owned(),
                    markdown:
                        "[cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/)"
                            .to_owned(),
                },
                properties: RuleProperties {
                    tags: get_rule_tags(rule_data.code)
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect(),
                    precision: "high".to_string(),
                    problem_severity: severity_to_sarif_level(rule_data.severity),
                },
            });
        }

        // Create results from diagnostics
        let mut results: Vec<SarifResult> = Vec::new();
        for diag in &self.diagnostics {
            let rule_id = format_rule_id(diag.code);
            let mut fingerprints = BTreeMap::new();
            
            // Create a unique fingerprint including package context when available
            let fingerprint_value = if let Some(package) = extract_package_from_message(&diag.message) {
                // Include package identifier for better uniqueness
                format!("{}:{}:{}:{}", package, rule_id, diag.file_path, diag.line)
            } else if diag.file_path.contains('/') {
                // If we have a path with potential package info, use it
                format!("{}:{}:{}", diag.file_path, rule_id, diag.line)
            } else {
                // Fallback to basic format
                format!("{}:{}:{}", rule_id, diag.file_path, diag.line)
            };
            
            fingerprints.insert(
                "cargo-deny/fingerprint".to_string(),
                fingerprint_value,
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

fn format_rule_id(code: DiagnosticCode) -> String {
    use std::str::FromStr;
    
    match code {
        DiagnosticCode::Advisory(c) => {
            // Use shorter prefix as Jake suggested
            let code_str = c.to_string();
            format!("a:{}", code_str)
        }
        DiagnosticCode::License(c) => {
            let code_str = c.to_string();
            format!("l:{}", code_str)
        }
        DiagnosticCode::Bans(c) => {
            let code_str = c.to_string();
            format!("b:{}", code_str)
        }
        DiagnosticCode::Source(c) => {
            let code_str = c.to_string();
            format!("s:{}", code_str)
        }
        DiagnosticCode::General(c) => {
            let code_str = c.to_string();
            format!("g:{}", code_str)
        }
    }
}

fn get_rule_description(code: DiagnosticCode) -> &'static str {
    match code {
        DiagnosticCode::Advisory(_) => "Security advisory or vulnerability detected",
        DiagnosticCode::License(_) => "License compliance issue detected",
        DiagnosticCode::Bans(_) => "Banned or duplicate dependency detected",
        DiagnosticCode::Source(_) => "Crate source issue detected",
        DiagnosticCode::General(_) => "General cargo-deny check issue",
    }
}

fn get_rule_tags(code: DiagnosticCode) -> Vec<&'static str> {
    match code {
        DiagnosticCode::Advisory(_) => vec!["security", "vulnerability"],
        DiagnosticCode::License(_) => vec!["license", "compliance"],
        DiagnosticCode::Bans(_) => vec!["dependencies", "supply-chain"],
        DiagnosticCode::Source(_) => vec!["sources", "supply-chain"],
        DiagnosticCode::General(_) => vec!["cargo-deny"],
    }
}

/// Extract package identifier from diagnostic message if present
fn extract_package_from_message(message: &str) -> Option<String> {
    // Look for patterns like:
    // - "crate 'package_name = version'"
    // - "crate 'package_name@version'"
    // - "Package 'package_name'"
    // - "'package_name v1.2.3'"
    
    // Try to find crate name in single quotes
    if let Some(start) = message.find('\'') {
        if let Some(end) = message[start + 1..].find('\'') {
            let crate_info = &message[start + 1..start + 1 + end];
            // Clean up the crate info to create a stable identifier
            // Handle formats like "package = 0.1.0" or "package@0.1.0" or "package v0.1.0"
            let cleaned = crate_info
                .replace(" = ", "-")
                .replace('@', "-")
                .replace(" v", "-")
                .replace(' ', "-");
            return Some(cleaned);
        }
    }
    
    None
}

fn parse_diagnostic_code(code_str: &str) -> DiagnosticCode {
    use std::str::FromStr;

    // Try to parse as an advisory code
    if let Ok(code) = crate::advisories::Code::from_str(code_str) {
        return DiagnosticCode::Advisory(code);
    }

    // Try to parse as a license code
    if let Ok(code) = crate::licenses::Code::from_str(code_str) {
        return DiagnosticCode::License(code);
    }

    // Try to parse as a bans code
    if let Ok(code) = crate::bans::Code::from_str(code_str) {
        return DiagnosticCode::Bans(code);
    }

    // Try to parse as a sources code
    if let Ok(code) = crate::sources::Code::from_str(code_str) {
        return DiagnosticCode::Source(code);
    }

    // Try to parse as a general code
    if let Ok(code) = crate::diag::general::Code::from_str(code_str) {
        return DiagnosticCode::General(code);
    }

    // If we can't parse the exact code, fall back to a reasonable default
    // based on the code string content
    let code_lower = code_str.to_lowercase();
    if code_lower.starts_with("advisory")
        || code_lower.contains("vulnerability")
        || code_lower.contains("yanked")
        || code_lower.contains("unmaintained")
    {
        DiagnosticCode::Advisory(crate::advisories::Code::Vulnerability)
    } else if code_lower.starts_with("license") || code_lower.contains("unlicensed") {
        DiagnosticCode::License(crate::licenses::Code::Unlicensed)
    } else if code_lower.starts_with("ban") || code_lower.contains("banned") {
        DiagnosticCode::Bans(crate::bans::Code::Banned)
    } else if code_lower.starts_with("source") {
        DiagnosticCode::Source(crate::sources::Code::SourceNotAllowed)
    } else {
        DiagnosticCode::General(crate::diag::general::Code::Deprecated)
    }
}
