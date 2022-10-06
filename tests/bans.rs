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

/// Ensures that multiple versions are always deterministically sorted by
/// version number
/// See <https://github.com/EmbarkStudios/cargo-deny/issues/384>
#[test]
fn deterministic_duplicate_ordering() {
    let diags = gather_bans(
        func_name!(),
        KrateGather::new("duplicates"),
        "multiple-versions = 'deny'",
    );

    insta::assert_json_snapshot!(diags);
}
