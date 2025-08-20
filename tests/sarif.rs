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
    assert_eq!(rule.id, "a:vulnerability");
    assert_eq!(rule.name, "a:vulnerability");
    assert!(rule.short_description.text.contains("Security"));

    // Verify we have results
    assert_eq!(run.results.len(), 1);
    let result = &run.results[0];
    assert_eq!(result.rule_id, "a:vulnerability");
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

    // Use Warning severity instead of Note (which is now filtered)
    collector.add_diagnostic(
        DiagnosticCode::Advisory(cargo_deny::advisories::Code::Notice),
        Severity::Warning,
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

#[test]
fn test_sarif_rule_id_format() {
    // Test that rule IDs use proper format like "license:rejected" not "License(Rejected)"
    let mut collector = SarifCollector::default();
    
    collector.add_diagnostic(
        DiagnosticCode::License(cargo_deny::licenses::Code::Rejected),
        Severity::Error,
        "License rejected".to_string(),
        "Cargo.toml".to_string(),
        10,
    );
    
    let sarif = collector.generate_sarif();
    let json = serde_json::to_string(&sarif).expect("Should serialize to JSON");
    
    // Should use clean format, not Debug format
    assert!(!json.contains("License(Rejected)"), "Should not use Debug format for rule IDs");
    assert!(json.contains("\"l:rejected\""), 
            "Should use short format like 'l:rejected'");
}

#[test]
fn test_sarif_excludes_note_severity() {
    // Test that note-level diagnostics are excluded from SARIF
    let mut collector = SarifCollector::default();
    
    // Add a note (should be excluded)
    collector.add_diagnostic(
        DiagnosticCode::Bans(cargo_deny::bans::Code::SkippedByRoot),
        Severity::Note,
        "Skipped by root".to_string(),
        "deny.toml".to_string(),
        35,
    );
    
    // Add a warning (should be included)
    collector.add_diagnostic(
        DiagnosticCode::License(cargo_deny::licenses::Code::Unlicensed),
        Severity::Warning,
        "Missing license".to_string(),
        "Cargo.toml".to_string(),
        20,
    );
    
    let sarif = collector.generate_sarif();
    
    // Should only have the warning, not the note
    assert_eq!(sarif.runs[0].results.len(), 1, "Should exclude note-level diagnostics");
    assert_eq!(sarif.runs[0].results[0].level, "warning");
}

#[test]
fn test_sarif_fingerprint_includes_package_context() {
    // Test that fingerprints include package information for uniqueness
    let mut collector = SarifCollector::default();
    
    // Simulate adding a diagnostic with package context
    // Note: This test assumes we'll add a method to include package info
    collector.add_diagnostic(
        DiagnosticCode::License(cargo_deny::licenses::Code::Rejected),
        Severity::Error,
        "Package 'openssl v0.10.64' uses rejected license".to_string(),
        "openssl-0.10.64/Cargo.toml".to_string(),
        15,
    );
    
    let sarif = collector.generate_sarif();
    let result = &sarif.runs[0].results[0];
    
    // Fingerprint should include enough context to be unique per package
    let fingerprint = result.partial_fingerprints.get("cargo-deny/fingerprint")
        .expect("Should have fingerprint");
    
    // Should not be a simple format that would be identical for all packages
    assert!(!fingerprint.starts_with("l:rejected:"),
            "Fingerprint should include package context before rule ID");
    
    // Should include some package-specific information extracted from message
    assert!(fingerprint.contains("openssl") || fingerprint.contains("0.10.64"),
            "Fingerprint should include package-specific information");
}
