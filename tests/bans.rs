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
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
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
    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        utils::get_test_data_krates("wildcards/maincrate").unwrap(),
        "deny_wildcards",
        Some("wildcards = 'deny'"),
        Some(std::time::Duration::from_millis(10000)),
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
                        format!("found 1 wildcard dependency for crate '{}'", exp)
                    )
            }),
            "unable to find error diagnostic for '{}'",
            exp
        );
    }
}

#[test]
fn deterministic_duplicate_ordering() {
    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        utils::get_test_data_krates("duplicates").unwrap(),
        "deterministic_duplicate_ordering",
        Some("multiple-versions = 'deny'"),
        Some(std::time::Duration::from_millis(10000)),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    let duplicates = [
        ("block-buffer", &["0.7.3", "0.10.2"]),
        ("digest", &["0.8.1", "0.10.3"]),
        ("generic-array", &["0.12.4", "0.14.5"]),
    ];

    for dup in &duplicates {
        assert!(
            diags.iter().any(|v| {
                if !field_eq!(v, "/fields/severity", "error")
                    || !field_eq!(
                        v,
                        "/fields/message",
                        format!("found 2 duplicate entries for crate '{}'", dup.0)
                    )
                {
                    return false;
                }

                for (i, version) in dup.1.iter().enumerate() {
                    if !field_eq!(v, &format!("/fields/graphs/{}/version", i), version) {
                        return false;
                    }
                }

                true
            }),
            "unable to find error diagnostic for duplicate '{}'",
            dup.0
        );
    }
}
