#![cfg(no)]
use cargo_deny::{func_name, test_utils::*};

/// Ensures that you can ban features in your own workspace. `simple` is brought
/// in via the default features
#[test]
fn bans_workspace_features() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new("features = [{ name = 'features-galore', deny = ['simple'] }]"),
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures non-workspace features are banned
#[test]
fn bans_external_features() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            features: &["zlib", "ssh"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new("features = [{ name = 'libssh2-sys', deny = ['zlib-ng-compat'] }]"),
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures non-workspace features can be allowed
#[test]
fn allows_external_features() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            features: &["zlib", "ssh"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new("features = [{ name = 'libssh2-sys', allow = ['zlib-ng-compat'] }]"),
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures workspace features fail if not all are allowed
#[test]
fn fails_if_not_all_features_allowed() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            features: &["zlib", "ssh"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "features = [{ name = 'features-galore', allow = ['ssh'] }]",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures features banned in a crate with multiple versions are all found
#[test]
fn bans_features_from_multiple_versions() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            targets: &["x86_64-pc-windows-msvc"],
            ..Default::default()
        },
        "multiple-versions = 'allow'\nfeatures = [{ name = 'windows-sys', deny = ['Win32_System_LibraryLoader'] }]",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures exact works
#[test]
fn exact_features() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            targets: &["x86_64-pc-windows-msvc"],
            ..Default::default()
        },
        "multiple-versions = 'allow'\nfeatures = [{ name = 'windows-sys', exact = true, allow = ['Win32_System_LibraryLoader'] }]",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures weak dependencies are properly pruned from the graph
/// See <https://github.com/EmbarkStudios/krates/issues/41> for more
#[test]
fn weak_dependencies_pruned() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            features: &["zlib"],
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "deny = [{ name = 'libssh2-sys' }]",
    );

    assert!(diags.is_empty());
}

#[test]
fn workspace_default_features_denies() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            no_default_features: false,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "workspace-default-features = 'deny'",
    );

    insta::assert_json_snapshot!(diags);
}

#[test]
fn workspace_default_features_warns_and_denies() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            no_default_features: false,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "workspace-default-features = 'warn'\nfeatures = [{ name = 'features-galore', deny = ['default'] }]",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that a workspace default ban can be overriden by a crate specific allow = 'default'
#[test]
fn workspace_default_features_allow_override() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            no_default_features: false,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "workspace-default-features = 'deny'\nfeatures = [{ name = 'features-galore', allow = ['default'] }]",
    );

    insta::assert_json_snapshot!(diags);
}

#[test]
fn external_default_features_denies() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "external-default-features = 'deny'",
    );

    insta::assert_json_snapshot!(diags);
}

#[test]
fn external_default_features_warns_and_denies() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "external-default-features = 'warn'\nfeatures = [{ name = 'bitflags', deny = ['default'] }]",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that a workspace default ban can be overriden by a crate specific allow = 'default'
#[test]
fn external_default_features_allow_override() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features-galore",
            no_default_features: false,
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        "external-default-features = 'deny'\nfeatures = [{ name = 'bitflags', allow = ['default'] }]",
    );

    insta::assert_json_snapshot!(diags);
}
