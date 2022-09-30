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
        Some("deny = [{ name = 'features-galore', features.deny = ['simple'] }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_snapshot!(tu::to_snapshot(diags));
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
        Some("deny = [{ name = 'libssh2-sys', features.deny = ['zlib-ng-compat'] }]"),
        Some(&["x86_64-unknown-linux-gnu"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_snapshot!(tu::to_snapshot(diags));
}

/// Ensures features banned in a crate with multiple versions are all found
#[test]
fn bans_features_from_multiple_versions() {
    let diags = tu::gather_diagnostics::<cfg::Config, _, _, _>(
        KrateGather::new("features-galore"),
        "bans_features_from_multiple_versions",
        Some("multiple-versions = 'allow'\ndeny = [{ name = 'windows-sys', features.deny = ['Win32_System_LibraryLoader'] }]"),
        Some(&["x86_64-pc-windows-msvc"]),
        |ctx, cs, tx| {
            bans::check(ctx, None, cs, tx);
        },
    )
    .unwrap();

    insta::assert_snapshot!(tu::to_snapshot(diags));
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
