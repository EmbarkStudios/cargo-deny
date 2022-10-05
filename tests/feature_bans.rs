use cargo_deny::{
    bans::{self, cfg},
    test_utils::{self as tu, KrateGather},
};

/// Ensures that you can ban features in your own workspace. `simple` is brought
/// in via the default features
#[test]
fn bans_workspace_features() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather::new("features-galore"),
        "bans_workspace_features",
        Some("features = [{ name = 'features-galore', deny = ['simple'] }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_json_snapshot!(diags);
}

/// Ensures non-workspace features are banned
#[test]
fn bans_external_features() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather {
            name: "features-galore",
            features: &["zlib", "ssh"],
            no_default_features: true,
            ..Default::default()
        },
        "bans_external_features",
        Some("features = [{ name = 'libssh2-sys', deny = ['zlib-ng-compat'] }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_json_snapshot!(diags);
}

/// Ensures non-workspace features can be allowed
#[test]
fn allows_external_features() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather {
            name: "features-galore",
            features: &["zlib", "ssh"],
            no_default_features: true,
            ..Default::default()
        },
        "allows_external_features",
        Some("features = [{ name = 'libssh2-sys', allow = ['zlib-ng-compat'] }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_json_snapshot!(diags);
}

/// Ensures workspace features fail if not all are allowed
#[test]
fn fails_if_not_all_features_allowed() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather {
            name: "features-galore",
            features: &["zlib", "ssh"],
            no_default_features: true,
            ..Default::default()
        },
        "bans_external_features",
        Some("features = [{ name = 'features-galore', allow = ['ssh'] }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_json_snapshot!(diags);
}

/// Ensures features banned in a crate with multiple versions are all found
#[test]
fn bans_features_from_multiple_versions() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather::new("features-galore"),
        "bans_features_from_multiple_versions",
        Some("multiple-versions = 'allow'\nfeatures = [{ name = 'windows-sys', deny = ['Win32_System_LibraryLoader'] }]"),
        Some(&["x86_64-pc-windows-msvc"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_json_snapshot!(diags);
}

/// Ensures exact works
#[test]
fn exact_features() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather::new("features-galore"),
        "bans_features_from_multiple_versions",
        Some("multiple-versions = 'allow'\nfeatures = [{ name = 'windows-sys', exact = true, allow = ['Win32_System_LibraryLoader'] }]"),
        Some(&["x86_64-pc-windows-msvc"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_json_snapshot!(diags);
}

/// Ensures weak dependencies are properly pruned from the graph
/// See <https://github.com/EmbarkStudios/krates/issues/41> for more
#[test]
fn weak_dependencies_pruned() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather {
            name: "features-galore",
            features: &["zlib"],
            no_default_features: true,
            ..Default::default()
        },
        "weak_dependencies_pruned",
        Some("deny = [{ name = 'libssh2-sys' }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    assert!(diags.is_empty());
}

/// Ensures the `workspace_default_features` cfg works as expected
#[test]
fn workspace_default_features() {
    let kg = KrateGather {
        name: "features-galore",
        no_default_features: false,
        ..Default::default()
    };

    {
        let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        kg.clone(),
            "workspace_default_features_gets_overriden",
            Some("workspace-default-features = 'warn'\nfeatures = [{ name = 'features-galore', deny = ['default'] }]"),
            Some(&["x86_64-unknown-linux-gnu"]),
            |ctx, cs, tx| {
                bans::check(ctx, None, cs, tx);
            },
        )
        .unwrap();

        insta::assert_json_snapshot!(diags);
    }

    {
        let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
            kg.clone(),
            "workspace_default_features_denies",
            Some("workspace-default-features = 'deny'\n"),
            Some(&["x86_64-unknown-linux-gnu"]),
            |ctx, cs, tx| {
                bans::check(ctx, None, cs, tx);
            },
        )
        .unwrap();

        insta::assert_json_snapshot!(diags);
    }

    {
        let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        kg,
            "workspace_default_features_deny_default",
            Some("workspace-default-features = 'deny'\nfeatures = [{ name = 'features-galore', allow = ['default'] }]"),
            Some(&["x86_64-unknown-linux-gnu"]),
            |ctx, cs, tx| {
                bans::check(ctx, None, cs, tx);
            },
        )
        .unwrap();

        insta::assert_json_snapshot!(diags);
    }
}

/// Ensures the `external_default_features` cfg works as expected
#[test]
fn external_default_features() {
    let kg = KrateGather {
        name: "features-galore",
        no_default_features: true,
        ..Default::default()
    };

    {
        let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        kg.clone(),
            "external_default_features_gets_overriden",
            Some("external-default-features = 'allow'\nfeatures = [{ name = 'bitflags', deny = ['default'] }]"),
            Some(&["x86_64-unknown-linux-gnu"]),
            |ctx, cs, tx| {
                bans::check(ctx, None, cs, tx);
            },
        )
        .unwrap();

        insta::assert_json_snapshot!(diags);
    }

    {
        let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
            kg.clone(),
            "external_default_features_denies",
            Some("external-default-features = 'deny'\n"),
            Some(&["x86_64-unknown-linux-gnu"]),
            |ctx, cs, tx| {
                bans::check(ctx, None, cs, tx);
            },
        )
        .unwrap();

        insta::assert_json_snapshot!(diags);
    }

    {
        let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        kg,
            "external_default_features_deny_default",
            Some("external-default-features = 'deny'\nfeatures = [{ name = 'bitflags', allow = ['default'] }]"),
            Some(&["x86_64-unknown-linux-gnu"]),
            |ctx, cs, tx| {
                bans::check(ctx, None, cs, tx);
            },
        )
        .unwrap();

        insta::assert_json_snapshot!(diags);
    }
}
