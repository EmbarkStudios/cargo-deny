use cargo_deny::{
    diag::{DiagnosticCode, Severity},
    sarif::SarifLog,
    sarif_collector::SarifCollector,
};

#[test]
fn test_sarif_structure() {
    let sarif = SarifLog::default();

    assert_eq!(
        sarif.schema,
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(sarif.version, "2.1.0");
    assert!(sarif.runs.is_empty());
}

#[test]
fn test_sarif_collector() {
    let mut collector = SarifCollector::default();

    // Add a test diagnostic
    collector.add_diagnostic(
        DiagnosticCode::Advisory(cargo_deny::advisories::Code::Vulnerability),
        Severity::Error,
        "Test vulnerability found".to_string(),
        "test.rs".to_string(),
        42,
    );

    let sarif = collector.generate_sarif();

    // Verify structure
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);

    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "cargo-deny");
    assert_eq!(run.tool.driver.version, env!("CARGO_PKG_VERSION"));

    // Verify we have rules
    assert_eq!(run.tool.driver.rules.len(), 1);
    let rule = &run.tool.driver.rules[0];
    assert_eq!(rule.id, "Advisory(Vulnerability)");
    assert_eq!(rule.name, "Advisory(Vulnerability)");
    assert!(rule.short_description.text.contains("Security"));

    // Verify we have results
    assert_eq!(run.results.len(), 1);
    let result = &run.results[0];
    assert_eq!(result.rule_id, "Advisory(Vulnerability)");
    assert_eq!(result.message.text, "Test vulnerability found");
    assert_eq!(result.level, "error");

    // Verify location
    assert_eq!(result.locations.len(), 1);
    let location = &result.locations[0];
    assert_eq!(location.physical_location.artifact_location.uri, "test.rs");
    assert_eq!(location.physical_location.region.start_line, 42);
}

#[test]
fn test_sarif_multiple_diagnostics() {
    let mut collector = SarifCollector::default();

    // Add multiple diagnostics of different types
    collector.add_diagnostic(
        DiagnosticCode::Advisory(cargo_deny::advisories::Code::Vulnerability),
        Severity::Error,
        "Vulnerability 1".to_string(),
        "lib.rs".to_string(),
        10,
    );

    collector.add_diagnostic(
        DiagnosticCode::License(cargo_deny::licenses::Code::Unlicensed),
        Severity::Warning,
        "Missing license".to_string(),
        "main.rs".to_string(),
        20,
    );

    collector.add_diagnostic(
        DiagnosticCode::Bans(cargo_deny::bans::Code::Banned),
        Severity::Error,
        "Banned crate".to_string(),
        "Cargo.toml".to_string(),
        30,
    );

    let sarif = collector.generate_sarif();

    // Should have 3 different rules
    assert_eq!(sarif.runs[0].tool.driver.rules.len(), 3);

    // Should have 3 results
    assert_eq!(sarif.runs[0].results.len(), 3);

    // Verify each result has correct severity
    let results = &sarif.runs[0].results;
    assert!(
        results
            .iter()
            .any(|r| r.message.text == "Vulnerability 1" && r.level == "error")
    );
    assert!(
        results
            .iter()
            .any(|r| r.message.text == "Missing license" && r.level == "warning")
    );
    assert!(
        results
            .iter()
            .any(|r| r.message.text == "Banned crate" && r.level == "error")
    );
}

#[test]
fn test_sarif_json_serialization() {
    let mut collector = SarifCollector::default();

    collector.add_diagnostic(
        DiagnosticCode::Advisory(cargo_deny::advisories::Code::Notice),
        Severity::Note,
        "Notice".to_string(),
        "test.rs".to_string(),
        1,
    );

    let sarif = collector.generate_sarif();

    // Should be serializable to JSON
    let json = serde_json::to_string(&sarif).expect("Should serialize to JSON");
    assert!(json.contains("\"$schema\""));
    assert!(json.contains("\"version\":\"2.1.0\""));
    assert!(json.contains("cargo-deny"));

    // Should be deserializable back
    let parsed: SarifLog = serde_json::from_str(&json).expect("Should deserialize from JSON");
    assert_eq!(parsed.version, sarif.version);
    assert_eq!(parsed.runs.len(), sarif.runs.len());
}

#[test]
fn test_sarif_empty_diagnostics() {
    // Edge case: no diagnostics collected
    let collector = SarifCollector::default();
    let sarif = collector.generate_sarif();

    // Should still produce valid SARIF structure
    assert_eq!(
        sarif.schema,
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);

    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "cargo-deny");
    assert_eq!(run.tool.driver.version, env!("CARGO_PKG_VERSION"));

    // Should have no rules and no results
    assert!(run.tool.driver.rules.is_empty());
    assert!(run.results.is_empty());

    // Should be serializable to valid JSON
    let json = serde_json::to_string(&sarif).expect("Should serialize to JSON");
    assert!(json.contains("\"$schema\""));
    assert!(json.contains("\"version\":\"2.1.0\""));
    assert!(json.contains("\"results\":[]"));
    assert!(json.contains("\"rules\":[]"));
}
