use cargo_deny::{func_name, test_utils::*};

/// Covers issue <https://github.com/EmbarkStudios/cargo-deny/issues/184>
#[test]
fn cyclic_dependencies_do_not_cause_infinite_loop() {
    gather_bans(
        func_name!(),
        KrateGather::new("cyclic_dependencies"),
        Config::default(),
    );
}

/// Validates a crate that is otherwise denied can be allowed by a wrapper
#[test]
fn allow_wrappers() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("allow_wrappers/maincrate"),
        r#"
[[deny]]
name = "dangerous-dep"
reason = "we need to update 'safe-wrapper' to not use this"
wrappers = ["safe-wrapper"]
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Validates a wrapper that doesn't exist emits a warning
#[test]
fn warns_on_unused_wrappers() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("allow_wrappers/maincrate"),
        r#"
[[deny]]
name = "dangerous-dep"
wrappers = ["safe-wrapper", "other-crate"]
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Validates just a plain deny emits an error
#[test]
fn disallows_denied() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("allow_wrappers/maincrate"),
        "deny = ['dangerous-dep']",
    );

    insta::assert_json_snapshot!(diags);
}

/// Validates a crate is denied even if it has wrappers if
#[test]
fn disallows_denied_with_wrapper() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("allow_wrappers/maincrate"),
        r#"
[[deny]]
name = "dangerous-dep"
reason = "we shouldn't use it but it is used transitively"
use-instead = "a-better-krate"
wrappers = ["other-crate"]
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Validates that wildcard '*' dependencies can be detected and banned
#[test]
fn deny_wildcards() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("wildcards/maincrate"),
        "wildcards = 'deny'",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that wildcard dependencies are still banned when
/// allow-wildcard-paths is set to true but the package is public.
#[test]
fn allow_path_wildcards_public_package() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("wildcards/allow-paths-public"),
        r"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that wildcard paths are allowed for private packages
#[test]
fn allow_path_wildcards_private_package() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("wildcards/allow-paths-private"),
        r"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that individual workspace crates can be ignored
#[test]
fn ignores_unpublished_crates() {
    let project_dir = camino::Utf8PathBuf::from("./tests/test_data/workspace");

    let mut cmd = krates::Cmd::new();
    cmd.current_dir(project_dir.clone());

    let mut kb = krates::Builder::new();
    kb.ignore_kind(krates::DepKind::Build, krates::Scope::All);
    kb.include_workspace_crates([project_dir.join("crates/member-two/Cargo.toml")]);
    let krates = kb
        .build(cmd, krates::NoneFilter)
        .expect("failed to build crate graph");

    let diags = gather_diagnostics::<cargo_deny::bans::cfg::Config, _, _>(
        &krates,
        func_name!(),
        // If either the workspace `root` or `member-one` crates are pulled in,
        // they will emit diagnostics that won't be emitted by just including member-two
        r"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
"
        .into(),
        |ctx, tx| {
            cargo_deny::bans::check(ctx, None, tx);
        },
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that dependencies with wildcard and git are allowed for private packages
#[test]
fn allow_git_wildcards_private_package() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("wildcards/allow-git"),
        r"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that multiple versions are always deterministically sorted by
/// version number
/// See <https://github.com/EmbarkStudios/cargo-deny/issues/384>
#[test]
fn deterministic_duplicate_ordering() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("duplicates"),
        r"
multiple-versions = 'deny'
multiple-versions-include-dev = true
",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that dev dependencies are ignored
#[test]
fn ignores_dev() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("duplicates"),
        r#"
multiple-versions = 'deny'
skip = [
    "block-buffer@0.7.3"
]
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures duplicate graphs match expectations
#[test]
fn duplicate_graphs() {
    use cargo_deny::bans;

    let krates = KrateGather::new("duplicates").gather();
    let cfg = r"
multiple-versions = 'deny'
multiple-versions-include-dev = true
"
    .into();

    let dup_graphs = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));

    let duped_graphs = dup_graphs.clone();
    gather_diagnostics::<bans::cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
        bans::check(
            ctx,
            Some(Box::new(move |dg| {
                duped_graphs.lock().push(dg);
                Ok(())
            })),
            tx,
        );
    });

    insta::assert_debug_snapshot!(dup_graphs.lock());
}

/// Ensures that we can allow duplicates generally, but deny them for specific
/// crates
#[test]
fn deny_multiple_versions_for_specific_krates() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("duplicates"),
        r"
multiple-versions = 'allow'
multiple-versions-include-dev = true
deny = [
    { name = 'block-buffer', deny-multiple-versions = true },
    { name = 'generic-array', deny-multiple-versions = true },
]
",
    );

    insta::assert_json_snapshot!(diags);
}

// Ensures that dependencies brought in by target specific features are banned
#[test]
fn deny_target_specific_dependencies() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features",
            no_default_features: true,
            ..Default::default()
        },
        r"
deny = [
    'serde'
]
",
    );

    insta::assert_json_snapshot!(diags);

    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features",
            no_default_features: true,
            targets: &["x86_64-windows-pc-msvc"],
            ..Default::default()
        },
        r"
deny = [
    'serde'
]
",
    );

    insta::assert_json_snapshot!(diags);

    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "features",
            no_default_features: true,
            targets: &["x86_64-windows-pc-msvc", "aarch64-linux-android"],
            ..Default::default()
        },
        r"
deny = [
    'serde'
]
",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that duplicate workspace items are found and linted
#[test]
fn deny_duplicate_workspace_items() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "workspace",
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"],
            ..Default::default()
        },
        r"
multiple-versions = 'allow'

[workspace-dependencies]
include-path-dependencies = true
unused = 'warn'
",
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures skips generate warnings if they aren't needed
#[test]
fn unused_skips_generate_warnings() {
    let diags = gather_bans(
        func_name!(),
        KrateGather {
            name: "workspace",
            no_default_features: true,
            targets: &["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"],
            ..Default::default()
        },
        r"
multiple-versions = 'deny'
skip = [
    # This actually has 3 versions, skip the two lower ones
    'spdx:<0.10.0',
    # This crate, but not exact version, is in the graph
    'smallvec@1.0.0',
    # This crate is in the graph, but there is only one version
    'serde_json',
]
",
    );

    insta::assert_json_snapshot!(diags);
}
