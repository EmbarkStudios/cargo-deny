use cargo_deny::{
    advisories::{self, cfg},
    Krates,
};
#[macro_use]
mod utils;

struct TestCtx {
    dbs: advisories::DatabaseCollection,
    lock: advisories::Lockfile,
    krates: Krates,
}

fn load() -> TestCtx {
    let md: krates::cm::Metadata = serde_json::from_str(
        &std::fs::read_to_string("tests/test_data/advisories/06_advisories.json").unwrap(),
    )
    .unwrap();

    let krates: Krates = krates::Builder::new()
        .build_with_metadata(md, krates::NoneFilter)
        .unwrap();

    let lock = advisories::load_lockfile(&std::path::Path::new(
        "tests/test_data/advisories/06_Cargo.lock",
    ))
    .unwrap();

    let db = {
        let tmp = tempfile::tempdir().unwrap();
        advisories::load_dbs(
            vec![],
            vec![tmp.path().to_owned()],
            advisories::Fetch::Allow,
        )
        .unwrap()
    };

    TestCtx {
        dbs: db,
        lock,
        krates,
    }
}

#[test]
#[ignore]
fn detects_vulnerabilities() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = "vulnerability = 'deny'";

    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        krates,
        "detects_vulnerabilities",
        Some(cfg),
        None,
        |ctx, tx| {
            advisories::check(ctx, &dbs, lock, tx);
        },
    )
    .unwrap();

    let vuln_diag = diags
        .iter()
        .find(|v| v.pointer("/fields/code") == Some(&serde_json::json!("RUSTSEC-2019-0001")))
        .unwrap();

    assert_field_eq!(vuln_diag, "/fields/severity", "error");
    assert_field_eq!(
        vuln_diag,
        "/fields/message",
        "Uncontrolled recursion leads to abort in HTML serialization"
    );
    assert_field_eq!(
        vuln_diag,
        "/fields/labels/0/message",
        "security vulnerability detected"
    );
}

#[test]
#[ignore]
fn detects_unmaintained() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = "unmaintained = 'warn'";

    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        krates,
        "detects_unmaintained",
        Some(cfg),
        None,
        |ctx, tx| {
            advisories::check(ctx, &dbs, lock, tx);
        },
    )
    .unwrap();

    let unmaintained_diag = diags
        .iter()
        .find(|v| v.pointer("/fields/code") == Some(&serde_json::json!("RUSTSEC-2016-0004")))
        .unwrap();

    assert_field_eq!(unmaintained_diag, "/fields/severity", "warning");
    assert_field_eq!(
        unmaintained_diag,
        "/fields/message",
        "libusb is unmaintained; use rusb instead"
    );
    assert_field_eq!(
        unmaintained_diag,
        "/fields/labels/0/message",
        "unmaintained advisory detected"
    );
}

#[test]
#[ignore]
fn downgrades_lint_levels() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = "unmaintained = 'warn'
    ignore = ['RUSTSEC-2016-0004', 'RUSTSEC-2019-0001']";

    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        krates,
        "downgrades_lint_levels",
        Some(cfg),
        None,
        |ctx, tx| {
            advisories::check(ctx, &dbs, lock, tx);
        },
    )
    .unwrap();

    assert_field_eq!(
        diags
            .iter()
            .find(|v| field_eq!(v, "/fields/code", "RUSTSEC-2016-0004"))
            .unwrap(),
        "/fields/severity",
        "help"
    );

    assert_field_eq!(
        diags
            .iter()
            .find(|v| field_eq!(v, "/fields/code", "RUSTSEC-2019-0001"))
            .unwrap(),
        "/fields/severity",
        "help"
    );
}

#[test]
#[ignore]
fn detects_yanked() {
    // Force fetch the index just in case
    rustsec::registry::Index::fetch().unwrap();

    let TestCtx { dbs, lock, krates } = load();

    let cfg = "yanked = 'deny'
    unmaintained = 'allow'
    vulnerability = 'allow'
    ";

    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        krates,
        "detects_yanked",
        Some(cfg),
        None,
        |ctx, tx| {
            advisories::check(ctx, &dbs, lock, tx);
        },
    )
    .unwrap();

    let yanked = [
        "quote 1.0.2 registry+https://github.com/rust-lang/crates.io-index",
        "spdx 0.3.1 registry+https://github.com/rust-lang/crates.io-index",
    ];

    for yanked in &yanked {
        assert!(
            diags.iter().any(|v| {
                field_eq!(v, "/fields/severity", "error")
                    && field_eq!(v, "/fields/message", "detected yanked crate")
                    && field_eq!(v, "/fields/labels/0/span", yanked)
            }),
            "failed to find yanked diagnostic for '{}'",
            yanked
        );
    }
}
