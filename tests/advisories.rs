use cargo_deny::{
    advisories::{self, cfg},
    field_eq, func_name,
    test_utils::{self as tu},
    Krates,
};

struct TestCtx {
    dbs: advisories::DbSet,
    krates: Krates,
}

fn load() -> TestCtx {
    static ONCE: parking_lot::Once = parking_lot::Once::new();

    ONCE.call_once(|| {
        let mut cargo = std::process::Command::new("cargo");
        cargo.args([
            "fetch",
            "--manifest-path",
            "examples/06_advisories/Cargo.toml",
        ]);
        assert!(
            cargo.status().expect("failed to run cargo fetch").success(),
            "failed to fetch crates"
        );
    });

    let md: krates::cm::Metadata = serde_json::from_str(
        &std::fs::read_to_string("tests/test_data/advisories/06_advisories.json").unwrap(),
    )
    .unwrap();

    let krates: Krates = krates::Builder::new()
        .build_with_metadata(md, krates::NoneFilter)
        .unwrap();

    let db = {
        advisories::DbSet::load(
            Some("tests/advisory-db"),
            vec![],
            advisories::Fetch::Disallow,
        )
        .unwrap()
    };

    TestCtx { dbs: db, krates }
}

fn iter_notes(diag: &serde_json::Value) -> Option<impl Iterator<Item = &str>> {
    diag.pointer("/fields/notes")
        .and_then(|notes| notes.as_array())
        .map(|array| array.iter().filter_map(|s| s.as_str()))
}

fn find_by_code<'a>(
    diags: &'a [serde_json::Value],
    code: &'_ str,
) -> Option<&'a serde_json::Value> {
    diags.iter().find(|v| match iter_notes(v) {
        Some(mut notes) => notes.any(|note| note.contains(code)),
        None => false,
    })
}

#[test]
fn detects_vulnerabilities() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("vulnerability = 'deny'");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, &dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    let diag = find_by_code(&diags, "RUSTSEC-2019-0001").unwrap();

    insta::assert_json_snapshot!(diag);
}

#[test]
fn detects_unmaintained() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("unmaintained = 'warn'");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, &dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    let unmaintained_diag = find_by_code(&diags, "RUSTSEC-2016-0004").unwrap();
    insta::assert_json_snapshot!(unmaintained_diag);
}

#[test]
fn detects_unsound() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("unsound = 'warn'");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, &dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    let unsound_diag = find_by_code(&diags, "RUSTSEC-2019-0036").unwrap();
    insta::assert_json_snapshot!(unsound_diag);
}

#[test]
fn downgrades_lint_levels() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new(
        "unmaintained = 'warn'\nignore = ['RUSTSEC-2016-0004', 'RUSTSEC-2019-0001']",
    );

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, &dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    let downgraded = [
        find_by_code(&diags, "RUSTSEC-2016-0004").unwrap(),
        find_by_code(&diags, "RUSTSEC-2019-0001").unwrap(),
    ];

    insta::assert_json_snapshot!(downgraded);
}

fn verify_yanked(name: &str, dbs: &advisories::DbSet, krates: &Krates) {
    let cfg = tu::Config::new("yanked = 'deny'\nunmaintained = 'allow'\nvulnerability = 'allow'");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    let diags: Vec<_> = diags
        .into_iter()
        .filter(|v| field_eq!(v, "/fields/message", "detected yanked crate"))
        .collect();

    insta::assert_json_snapshot!(name, diags);
}

#[test]
fn detects_yanked() {
    let TestCtx { dbs, krates } = load();
    verify_yanked("detects_yanked", &dbs, &krates);
}

#[test]
fn detects_yanked_sparse() {
    let dbs = {
        advisories::DbSet::load(
            Some("tests/advisory-db"),
            vec![],
            advisories::Fetch::Disallow,
        )
        .unwrap()
    };

    let mut mdc = krates::Cmd::new();
    mdc.manifest_path("examples/06_advisories/Cargo.toml");

    let cmd: krates::cm::MetadataCommand = mdc.into();

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let registry_root = home::cargo_home()
        .unwrap()
        .join("registry/index/github.com-1ecc6299db9ec823");
    std::fs::remove_dir_all(registry_root).expect("failed to nuke registry");
    verify_yanked("detects_yanked_sparse", &dbs, &krates);
}

/// Again, screwing around on disk, don't run this test unless you really want to
#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn warns_on_index_failures() {
    let dbs = {
        advisories::DbSet::load(
            Some("tests/advisory-db"),
            vec![],
            advisories::Fetch::Disallow,
        )
        .unwrap()
    };

    let mut mdc = krates::Cmd::new();
    mdc.manifest_path("examples/06_advisories/Cargo.toml");

    let cmd: krates::cm::MetadataCommand = mdc.into();
    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::new("yanked = 'deny'\ncrates-io-git-fallback = false\nunmaintained = 'allow'\nvulnerability = 'allow'");
    let registry_root = home::cargo_home().unwrap().join("registry/index");
    std::fs::remove_dir_all(registry_root).expect("failed to nuke registry");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, &dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    // This is the number of crates sourced to crates.io
    assert_eq!(
        diags
            .into_iter()
            .filter(|v| { field_eq!(v, "/fields/message", "unable to check for yanked crates") })
            .count(),
        193
    );
}

#[test]
fn warns_on_ignored_and_withdrawn() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new(
        "yanked = 'deny'\nunmaintained = 'deny'\nvulnerability = 'deny'\nignore = ['RUSTSEC-2020-0053']",
    );

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, _, tx| {
            advisories::check(ctx, &dbs, Option::<advisories::NoneReporter>::None, tx);
        });

    insta::assert_json_snapshot!(diags
        .iter()
        .find(|diag| field_eq!(diag, "/fields/code", "advisory-not-detected"))
        .unwrap());
}
