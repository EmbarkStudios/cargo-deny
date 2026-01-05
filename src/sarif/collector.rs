use crate::diag::Extra;
use crate::sarif::model::{
    ArtifactLocation, DefaultConfiguration, Driver, Help, Location, Message, PhysicalLocation,
    Region, Result as SarifResult, Rule, RuleProperties, Run, SarifLog, TextContent, Tool,
};
use crate::{
    Kid,
    diag::{self, DiagnosticCode, Pack, Severity},
};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Collects diagnostics and converts them to SARIF format
pub struct SarifCollector {
    diagnostics: Vec<DiagnosticData>,
    rules: BTreeMap<DiagnosticCode, RuleData>,
    workspace_root: String,
}

struct DiagnosticData {
    code: DiagnosticCode,
    severity: Severity,
    krates: smallvec::SmallVec<[Kid; 2]>,
    message: Message,
    locations: Vec<Location>,
    extra: Option<diag::Extra>,
}

struct RuleData {
    code: DiagnosticCode,
    severity: Severity,
    description: &'static str,
}

impl SarifCollector {
    pub fn new(workspace_root: impl Into<String>) -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: BTreeMap::new(),
            workspace_root: workspace_root.into(),
        }
    }

    pub fn add_diagnostics(&mut self, pack: Pack, files: &crate::diag::Files) {
        for diag in pack {
            let Some(code) = diag.code else {
                return;
            };

            // Filter out note and help severities - SARIF should only contain actionable issues
            if matches!(diag.diag.severity, Severity::Note | Severity::Help) {
                return;
            }

            let locations = diag
                .diag
                .labels
                .iter()
                .filter_map(|label| files.sarif_location(label).ok())
                .collect();

            let message = match &diag.extra {
                None => Message::text(diag.diag.message),
                Some(diag::Extra::Advisory(advisory)) => {
                    let mut md = String::new();

                    let meta = &advisory.metadata;

                    md.push_str("# ");
                    if let Some(url) = &meta.url {
                        write!(&mut md, "[{}]({url})", meta.id).unwrap();
                    } else {
                        md.push_str(meta.id.as_str());
                    }

                    md.push('\n');
                    md.push_str(&meta.title);
                    md.push('\n');

                    md.push_str("## Description\n");
                    md.push_str(&meta.description);
                    md.push_str("\n\n");

                    if !advisory.versions.unaffected().is_empty() {
                        md.push_str("## Unaffected\n");
                        for un in advisory.versions.unaffected() {
                            writeln!(&mut md, "- `{un}`").unwrap();
                        }
                        md.push('\n');
                    }

                    if !advisory.versions.patched().is_empty() {
                        md.push_str("## Patched\n");
                        for un in advisory.versions.patched() {
                            writeln!(&mut md, "- `{un}`").unwrap();
                        }
                        md.push('\n');
                    }

                    if let Some(affected) = &advisory.affected {
                        md.push_str("## Affected\n");
                        if !affected.functions.is_empty() {
                            md.push_str("| Functions | Versions |\n|---|---|\n");
                            for (path, reqs) in &affected.functions {
                                write!(&mut md, "|`{path}`|").unwrap();

                                for (i, req) in reqs.iter().enumerate() {
                                    if i > 0 {
                                        md.push_str(", ");
                                    }

                                    write!(&mut md, "`{req}`").unwrap();
                                }

                                md.push_str("|\n");
                            }

                            md.push('\n');
                        }

                        if !affected.arch.is_empty() {
                            md.push_str("### Arches\n");
                            for arch in &affected.arch {
                                md.push_str("- ");
                                md.push_str(arch.as_str());
                                md.push('\n');
                            }
                            md.push('\n');
                        }

                        if !affected.os.is_empty() {
                            md.push_str("### Operating Systems\n");
                            for os in &affected.os {
                                md.push_str("- ");
                                md.push_str(os.as_str());
                                md.push('\n');
                            }
                            md.push('\n');
                        }
                    }

                    Message {
                        text: meta.title.clone(),
                        markdown: Some(md),
                    }
                }
            };

            // Add to diagnostics
            self.diagnostics.push(DiagnosticData {
                code,
                krates: diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect(),
                severity: diag.diag.severity,
                message,
                locations,
                extra: diag.extra,
            });

            // Add to rules if not already present
            self.rules.entry(code).or_insert(RuleData {
                code,
                severity: diag.diag.severity,
                description: code.description(),
            });
        }
    }

    pub fn generate_sarif(self) -> SarifLog {
        // Create rules from collected diagnostics
        let rules = self
            .rules
            .into_iter()
            .map(|(id, rule_data)| Rule {
                name: id.qualified_str(),
                id: id.qualified_str(),
                short_description: TextContent {
                    text: rule_data.description.to_owned(),
                },
                full_description: TextContent {
                    text: String::new(),
                },
                default_configuration: DefaultConfiguration {
                    level: severity_to_sarif_level(rule_data.severity).to_owned(),
                },
                help: Help(id),
                properties: RuleProperties {
                    tags: get_rule_tags(rule_data.code),
                    precision: "high",
                    problem_severity: severity_to_sarif_level(rule_data.severity),
                },
            })
            .collect();

        // Create results from diagnostics
        let results: Vec<SarifResult> = self
            .diagnostics
            .into_iter()
            .map(|diag| {
                let mut fingerprints = BTreeMap::new();
                let rule_id = diag.code.qualified_str();
                fingerprints.insert("cargo-deny/id".into(), rule_id.clone());

                match diag.extra {
                    Some(Extra::Advisory(advisory)) => {
                        fingerprints.insert(
                            "cargo-deny/advisory-id".into(),
                            advisory.metadata.id.to_string(),
                        );
                    }
                    None => {}
                }

                if !diag.krates.is_empty() {
                    for (i, kid) in diag.krates.into_iter().enumerate() {
                        let mut fp = String::new();

                        // Avoid including this in the fingerprint as in most projects
                        // this will be almost every crate and would just be noise
                        if !kid.source().ends_with(tame_index::CRATES_IO_INDEX) {
                            fp.push_str(kid.source());
                            fp.push('#');
                        }

                        fp.push_str(kid.name());
                        fp.push('@');
                        fp.push_str(kid.version());

                        if i > 0 {
                            fingerprints.insert(format!("cargo-deny/krate{i}"), fp);
                        } else {
                            fingerprints.insert("cargo-deny/krate".into(), fp);
                        }
                    }
                } else {
                    for (i, loc) in diag.locations.iter().enumerate() {
                        let mut fp = String::new();

                        fp.push_str(&loc.physical_location.artifact_location.uri);
                        fp.push(':');
                        write!(
                            &mut fp,
                            "{}..{}",
                            loc.physical_location.region.byte_offset,
                            loc.physical_location.region.byte_offset
                                + loc.physical_location.region.byte_length
                        )
                        .unwrap();

                        if i > 0 {
                            fingerprints.insert(format!("cargo-deny/loc{i}"), fp);
                        } else {
                            fingerprints.insert("cargo-deny/loc".into(), fp);
                        }
                    }
                }

                // GitHub Code Scanning requires at least one location per result.
                // If no locations were found (e.g., for dependency advisories that only
                // reference Cargo.lock which is filtered out), add a fallback location
                // pointing to the workspace Cargo.toml since that's where dependencies are declared.
                let locations = if diag.locations.is_empty() {
                    let fallback_uri = if self.workspace_root.is_empty() {
                        "Cargo.toml".to_string()
                    } else {
                        format!("{}/Cargo.toml", self.workspace_root)
                    };
                    vec![Location {
                        physical_location: PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: fallback_uri,
                            },
                            region: Region {
                                start_line: 1,
                                byte_offset: 0,
                                byte_length: 0,
                                snippet: None,
                                message: None,
                            },
                        },
                    }]
                } else {
                    diag.locations
                };

                SarifResult {
                    rule_id,
                    message: diag.message,
                    level: severity_to_sarif_level(diag.severity),
                    locations,
                    partial_fingerprints: fingerprints,
                }
            })
            .collect();

        SarifLog {
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        rules,
                        version: None,
                    },
                },
                results,
            }],
        }
    }
}

#[inline]
fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error | Severity::Bug => "error",
        Severity::Warning => "warning",
        Severity::Note | Severity::Help => "note",
    }
}

#[inline]
fn get_rule_tags(code: DiagnosticCode) -> &'static [&'static str] {
    match code {
        DiagnosticCode::Advisory(_) => &["security", "vulnerability"],
        DiagnosticCode::License(_) => &["license", "compliance"],
        DiagnosticCode::Bans(_) => &["dependencies", "supply-chain"],
        DiagnosticCode::Source(_) => &["sources", "supply-chain"],
        DiagnosticCode::General(_) => &["cargo-deny"],
    }
}
