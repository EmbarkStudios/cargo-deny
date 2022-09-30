use cargo_deny::{
    assert_field_eq,
    bans::{self, cfg},
    field_eq,
    test_utils::{self as tu, KrateGather},
};

/// Covers issue <https://github.com/EmbarkStudios/cargo-deny/issues/184>
#[test]
fn cyclic_dependencies_do_not_cause_infinite_loop() {
    tu::gather_diagnostics::<cfg::Config, _, _>(
        KrateGather::new("cyclic_dependencies"),
        "cyclic_dependencies_do_not_cause_infinite_loop",
        None,
        None,
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();
}

#[test]
fn allow_wrappers() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        KrateGather::new("allow_wrappers/maincrate"),
        "allow_wrappers",
        Some(
            r#"
[[deny]]
name = "dangerous-dep"
wrappers = ["safe-wrapper"]
"#,
        ),
        None,
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
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
        "banned crate 'dangerous-dep = 0.1.0' allowed by wrapper 'safe-wrapper = 0.1.0'"
    );
    assert_field_eq!(diag, "/fields/labels/0/message", "banned here");
    assert_field_eq!(diag, "/fields/labels/0/span", "dangerous-dep");
    assert_field_eq!(diag, "/fields/labels/1/message", "allowed wrapper");
    assert_field_eq!(diag, "/fields/labels/1/span", "safe-wrapper");
}

#[test]
fn disallows_denied() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        KrateGather::new("allow_wrappers/maincrate"),
        "disallows_denied",
        Some(
            r#"
[[deny]]
name = "dangerous-dep"
"#,
        ),
        None,
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
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
        "crate 'dangerous-dep = 0.1.0' is explicitly banned"
    );
    assert_field_eq!(diag, "/fields/labels/0/message", "banned here");
    assert_field_eq!(diag, "/fields/labels/0/span", "dangerous-dep");
}

#[test]
fn deny_wildcards() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        KrateGather::new("wildcards/maincrate"),
        "deny_wildcards",
        Some("wildcards = 'deny'"),
        None,
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
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
                        format!("found 1 wildcard dependency for crate '{exp}'")
                    )
            }),
            "unable to find error diagnostic for '{exp}'"
        );
    }
}

/// Ensures that multiple versions are always deterministically sorted by
/// version number
/// See <https://github.com/EmbarkStudios/cargo-deny/issues/384>
#[test]
fn deterministic_duplicate_ordering() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        KrateGather::new("duplicates"),
        "deterministic_duplicate_ordering",
        Some("multiple-versions = 'deny'"),
        None,
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_snapshot!(tu::to_snapshot(diags));
}
