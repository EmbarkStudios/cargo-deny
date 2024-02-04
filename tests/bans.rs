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

#[test]
fn allow_wrappers() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("allow_wrappers/maincrate"),
        r#"
[[deny]]
name = "dangerous-dep"
wrappers = ["safe-wrapper"]
"#,
    );

    insta::assert_json_snapshot!(diags);
}

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

#[test]
fn disallows_denied() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("allow_wrappers/maincrate"),
        "deny = [{name = 'dangerous-dep'}]",
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
        r#"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that wildcard paths are allowed for private packages
#[test]
fn allow_path_wildcards_private_package() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("wildcards/allow-paths-private"),
        r#"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that dependencies with wildcard and git are allowed for private packages
#[test]
fn allow_git_wildcards_private_package() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("wildcards/allow-git"),
        r#"
multiple-versions = 'allow'
wildcards = 'deny'
allow-wildcard-paths = true
"#,
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
        r#"
multiple-versions = 'deny'
multiple-versions-include-dev = true
"#,
    );

    insta::assert_json_snapshot!(diags);
}

/// Ensures that dev dependendencies are ignored
#[test]
fn ignores_dev() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("duplicates"),
        r#"
multiple-versions = 'deny'
skip = [
    { name = 'block-buffer', version = "=0.7.3" },
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
    let cfg = r#"
multiple-versions = 'deny'
multiple-versions-include-dev = true
"#
    .into();

    let dup_graphs = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));

    let duped_graphs = dup_graphs.clone();
    gather_diagnostics::<bans::cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, cs, tx| {
        bans::check(
            ctx,
            Some(Box::new(move |dg| {
                duped_graphs.lock().push(dg);
                Ok(())
            })),
            cs,
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
        r#"
multiple-versions = 'allow'
multiple-versions-include-dev = true
deny = [
    { name = 'block-buffer', deny-multiple-versions = true },
    { name = 'generic-array', deny-multiple-versions = true },
]
"#,
    );

    insta::assert_json_snapshot!(diags);
}
