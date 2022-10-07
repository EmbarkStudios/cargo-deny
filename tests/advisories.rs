use cargo_deny::{
    advisories::{self, cfg},
    field_eq,
    test_utils::{self as tu},
    Krates,
};

struct TestCtx {
    dbs: advisories::DbSet,
    lock: advisories::PrunedLockfile,
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

    let lock = advisories::load_lockfile(krates::Utf8Path::new(
        "tests/test_data/advisories/06_Cargo.lock",
    ))
    .unwrap();

    let db = {
        advisories::DbSet::load(
            Some("tests/advisory-db"),
            vec![],
            advisories::Fetch::Disallow,
        )
        .unwrap()
    };

    let lockfile = advisories::PrunedLockfile::prune(lock, &krates);

    TestCtx {
        dbs: db,
        lock: lockfile,
        krates,
    }
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
    let TestCtx { dbs, lock, krates } = load();

    let cfg = tu::Config::new("vulnerability = 'deny'");

    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        &krates,
        "detects_vulnerabilities",
        cfg,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    );

    let diag = find_by_code(&diags, "RUSTSEC-2019-0001").unwrap();

    insta::assert_json_snapshot!(diag);
}

// #[test]
// #[ignore]
// fn detects_prereleases() {
//     let TestCtx { dbs, lock, krates } = load();

//     let cfg = "vulnerability = 'deny'";

//     let diags = utils::gather_diagnostics::<cfg::Config, _, _>(
//         krates,
//         "detects_prereleases",
//         Some(cfg),
//         None,
//         |ctx, _, tx| {
//             advisories::check(
//                 ctx,
//                 &dbs,
//                 lock,
//                 Option::<advisories::NoneReporter>::None,
//                 tx,
//             );
//         },
//     )
//     .unwrap();

//     println!("{:#?}", diags);

//     let vuln_diag = find_by_code(&diags, "RUSTSEC-2020-0069").unwrap();

//     assert_field_eq!(vuln_diag, "/fields/severity", "error");
//     assert_field_eq!(
//         vuln_diag,
//         "/fields/message",
//         "advisory for a crate with a pre-release was skipped as it matched a patch"
//     );
//     assert_field_eq!(vuln_diag, "/fields/labels/0/message", "pre-release crate");

//     assert!(iter_notes(vuln_diag)
//         .expect("expected notes on diag")
//         .any(|s| s == "Satisfied version requirement: >=0.5.0-alpha.3"));
// }

#[test]
fn detects_unmaintained() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = tu::Config::new("unmaintained = 'warn'");

    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        &krates,
        "detects_unmaintained",
        cfg,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    );

    let unmaintained_diag = find_by_code(&diags, "RUSTSEC-2016-0004").unwrap();
    insta::assert_json_snapshot!(unmaintained_diag);
}

#[test]
fn detects_unsound() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = tu::Config::new("unsound = 'warn'");

    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        &krates,
        "detects_unsound",
        cfg,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    );

    let unsound_diag = find_by_code(&diags, "RUSTSEC-2019-0036").unwrap();
    insta::assert_json_snapshot!(unsound_diag);
}

#[test]
fn downgrades_lint_levels() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = tu::Config::new(
        "unmaintained = 'warn'\nignore = ['RUSTSEC-2016-0004', 'RUSTSEC-2019-0001']",
    );

    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        &krates,
        "downgrades_lint_levels",
        cfg,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    );

    let downgraded = [
        find_by_code(&diags, "RUSTSEC-2016-0004").unwrap(),
        find_by_code(&diags, "RUSTSEC-2019-0001").unwrap(),
    ];

    insta::assert_json_snapshot!(downgraded);
}

#[test]
fn detects_yanked() {
    // This crate has been yanked for ages so no need to do a refresh of the registry
    // {
    //     let mut index = crates_index::Index::new_cargo_default().unwrap();
    //     index.update().unwrap();
    // }

    let TestCtx { dbs, lock, krates } = load();

    let cfg = tu::Config::new("yanked = 'deny'\nunmaintained = 'allow'\nvulnerability = 'allow'");

    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        &krates,
        "detects_yanked",
        cfg,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    );

    let yanked = ["spdx 0.3.1 registry+https://github.com/rust-lang/crates.io-index"];

    for yanked in &yanked {
        assert!(
            diags.iter().any(|v| {
                field_eq!(v, "/fields/severity", "error")
                    && field_eq!(v, "/fields/message", "detected yanked crate")
                    && field_eq!(v, "/fields/labels/0/span", yanked)
            }),
            "failed to find yanked diagnostic for '{yanked}'"
        );
    }
}

#[test]
fn warns_on_ignored_and_withdrawn() {
    let TestCtx { dbs, lock, krates } = load();

    let cfg = tu::Config::new(
        "yanked = 'deny'\nunmaintained = 'deny'\nvulnerability = 'deny'\nignore = ['RUSTSEC-2020-0053']",
    );

    let diags = tu::gather_diagnostics::<cfg::Config, _, _>(
        &krates,
        "warns_on_ignored_and_withdrawn",
        cfg,
        |ctx, _, tx| {
            advisories::check(
                ctx,
                &dbs,
                lock,
                Option::<advisories::NoneReporter>::None,
                tx,
            );
        },
    );

    insta::assert_json_snapshot!(diags
        .iter()
        .find(|diag| field_eq!(diag, "/fields/code", "advisory_not_detected"))
        .unwrap());
}
