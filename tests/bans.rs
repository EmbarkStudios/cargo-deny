use cargo_deny::bans::{self, cfg};

#[macro_use]
mod utils;

// Covers issue https://github.com/EmbarkStudios/cargo-deny/issues/184
#[test]
fn cyclic_dependencies_do_not_cause_infinite_loop() {
    utils::gather_diagnostics::<cfg::Config, _, _>(
        utils::get_test_data_krates("cyclic_dependencies").unwrap(),
        "cyclic_dependencies_do_not_cause_infinite_loop",
        None,
        Some(std::time::Duration::from_millis(10000)),
        |ctx, tx| {
            bans::check(ctx, None, tx);
        },
    )
    .unwrap();
}

#[test]
fn allow_wrappers() {
    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        utils::get_test_data_krates("allow_wrappers/maincrate").unwrap(),
        "allow_wrappers",
        Some(
            r#"
[[deny]]
name = "dangerous-dep"
wrappers = ["safe-wrapper"]
"#,
        ),
        None,
        |ctx, tx| {
            bans::check(ctx, None, tx);
        },
    )
    .unwrap();

    let diag = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/severity", "help"))
        .unwrap();

    assert_field_eq!(
        diag,
        "/fields/message",
        "banned crate dangerous-dep = 0.1.0 allowed by direct dependency from safe-wrapper = 0.1.0"
    );
    assert_field_eq!(diag, "/fields/labels/0/message", "ban exception");
    assert_field_eq!(diag, "/fields/labels/0/span", "\"safe-wrapper\"");
}

#[test]
fn disallows_denied() {
    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        utils::get_test_data_krates("allow_wrappers/maincrate").unwrap(),
        "disallows_denied",
        Some(
            r#"
[[deny]]
name = "dangerous-dep"
"#,
        ),
        None,
        |ctx, tx| {
            bans::check(ctx, None, tx);
        },
    )
    .unwrap();

    let diag = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/severity", "error"))
        .unwrap();

    assert_field_eq!(
        diag,
        "/fields/message",
        "detected banned crate dangerous-dep = 0.1.0"
    );
    assert_field_eq!(diag, "/fields/labels/0/message", "matching ban entry");
    assert_field_eq!(diag, "/fields/labels/0/span", "\"dangerous-dep\"");
}

#[test]
fn deny_wildcards() {
    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        utils::get_test_data_krates("wildcards/maincrate").unwrap(),
        "deny_wildcards",
        Some("wildcards = 'deny'"),
        Some(std::time::Duration::from_millis(10000)),
        |ctx, tx| {
            bans::check(ctx, None, tx);
        },
    )
    .unwrap();

    let expected = ["wildcards-test-crate", "wildcards-test-dep"];

    for exp in &expected {
        assert!(
            diags.iter().any(|v| {
                field_eq!(v, "/fields/severity", "error")
                    && field_eq!(
                        v,
                        "/fields/message",
                        format!("found 1 wildcard dependency for crate '{}'", exp)
                    )
            }),
            "unable to find error diagnostic for '{}'",
            exp
        );
    }
}
