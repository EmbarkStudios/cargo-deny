use cargo_deny::{
    advisories::{self, cfg},
    Krates,
};
#[macro_use]
mod utils;

struct TestCtx {
    dbs: advisories::DbSet,
    lock: advisories::PrunedLockfile,
    krates: Krates,
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
        advisories::DbSet::load(Some(tmp), vec![], advisories::Fetch::Allow).unwrap()
    };

    let lockfile = advisories::PrunedLockfile::prune(lock, &krates);

    TestCtx {
        dbs: db,
        lock: lockfile,
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
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    )
    .unwrap();

    let vuln_diag = find_by_code(&diags, "RUSTSEC-2019-0001").unwrap();

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
fn skips_prereleases() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = "vulnerability = 'deny'";

    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        krates,
        "skips_prereleases",
        Some(cfg),
        None,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    )
    .unwrap();

    let vuln_diag = find_by_code(&diags, "RUSTSEC-2018-0007").unwrap();

    assert_field_eq!(vuln_diag, "/fields/severity", "warning");
    assert_field_eq!(
        vuln_diag,
        "/fields/message",
        "advisory for a crate with a pre-release was skipped as it matched a patch"
    );
    assert_field_eq!(vuln_diag, "/fields/labels/0/message", "pre-release crate");

    assert!(iter_notes(vuln_diag)
        .expect("expected notes on diag")
        .any(|s| s == "Satisfied version requirement: >=0.5.0-alpha.3"));
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
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    )
    .unwrap();

    let unmaintained_diag = find_by_code(&diags, "RUSTSEC-2016-0004").unwrap();

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
fn detects_unsound() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = "unsound = 'warn'";

    let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
        krates,
        "detects_unsound",
        Some(cfg),
        None,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    )
    .unwrap();

    let unsound_diag = find_by_code(&diags, "RUSTSEC-2019-0036").unwrap();

    assert_field_eq!(unsound_diag, "/fields/severity", "warning");
    assert_field_eq!(
        unsound_diag,
        "/fields/message",
        "Type confusion if __private_get_type_id__ is overriden"
    );
    assert_field_eq!(
        unsound_diag,
        "/fields/labels/0/message",
        "unsound advisory detected"
    );
    assert_field_eq!(
        unsound_diag,
        "/fields/labels/0/span",
        "failure 0.1.8 registry+https://github.com/rust-lang/crates.io-index"
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
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    )
    .unwrap();

    assert_field_eq!(
        find_by_code(&diags, "RUSTSEC-2016-0004").unwrap(),
        "/fields/severity",
        "help"
    );

    assert_field_eq!(
        find_by_code(&diags, "RUSTSEC-2019-0001").unwrap(),
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
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    )
    .unwrap();

    let yanked = ["spdx 0.3.1 registry+https://github.com/rust-lang/crates.io-index"];

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
