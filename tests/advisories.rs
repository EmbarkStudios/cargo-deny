use cargo_deny::{
    Krates,
    advisories::{self, cfg},
    field_eq, func_name,
    test_utils::{self as tu},
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
            "tests/advisory-db".into(),
            vec![],
            advisories::Fetch::Disallow(time::Duration::days(10000)),
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

fn find_by_code<'a>(diags: &'a [serde_json::Value], code: &str) -> Option<&'a serde_json::Value> {
    diags.iter().find(|v| match iter_notes(v) {
        Some(mut notes) => notes.any(|note| note.contains(code)),
        None => false,
    })
}

/// Validates we emit diagnostics when a vulnerability advisory is detected
#[test]
fn detects_vulnerabilities() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                None,
                tx,
            );
        });

    let diag = find_by_code(&diags, "RUSTSEC-2019-0001").unwrap();

    insta::assert_json_snapshot!(diag);
}

/// Validates we emit diagnostics when an unmaintained advisory is detected
#[test]
fn detects_unmaintained() {
    let TestCtx { dbs, krates } = load();

    fn unmaintained_advisories(v: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        v.into_iter()
            .filter(|diag| {
                diag.pointer("/fields/code").and_then(|code| code.as_str()) == Some("unmaintained")
            })
            .collect()
    }

    {
        let cfg = tu::Config::new("");

        let diags =
            tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
                advisories::check(
                    ctx,
                    &dbs,
                    Option::<advisories::NoneReporter>::None,
                    None,
                    tx,
                );
            });

        insta::assert_json_snapshot!(unmaintained_advisories(diags));
    }

    {
        let cfg = tu::Config::new("unmaintained = 'workspace'");

        let diags =
            tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
                advisories::check(
                    ctx,
                    &dbs,
                    Option::<advisories::NoneReporter>::None,
                    None,
                    tx,
                );
            });

        insta::assert_json_snapshot!(unmaintained_advisories(diags));
    }

    {
        let cfg = tu::Config::new("unmaintained = 'transitive'");

        let diags =
            tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
                advisories::check(
                    ctx,
                    &dbs,
                    Option::<advisories::NoneReporter>::None,
                    None,
                    tx,
                );
            });

        insta::assert_json_snapshot!(unmaintained_advisories(diags));
    }

    {
        let cfg = tu::Config::new("unmaintained = 'none'");

        let diags =
            tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
                advisories::check(
                    ctx,
                    &dbs,
                    Option::<advisories::NoneReporter>::None,
                    None,
                    tx,
                );
            });

        insta::assert_json_snapshot!(unmaintained_advisories(diags));
    }
}

/// Validates we emit diagnostics when an unsound advisory is detected
#[test]
fn detects_unsound() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                None,
                tx,
            );
        });

    let unsound_diag = find_by_code(&diags, "RUSTSEC-2019-0036").unwrap();
    insta::assert_json_snapshot!(unsound_diag);
}

/// Validates that advisories that are ignored still have diagnostics emitted for
/// them, but with 'note' severity
#[test]
fn downgrades_lint_levels() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new(
        r#"
ignore = [
    "RUSTSEC-2016-0004",
    { id = "RUSTSEC-2019-0001", reason = "this is a test" },
]
"#,
    );

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                None,
                tx,
            );
        });

    let downgraded = [
        find_by_code(&diags, "RUSTSEC-2016-0004").unwrap(),
        find_by_code(&diags, "RUSTSEC-2019-0001").unwrap(),
    ];

    insta::assert_json_snapshot!(downgraded);

    let ignored: Vec<_> = diags
        .into_iter()
        .filter(|v| {
            v.pointer("/fields/code")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s == "advisory-ignored")
        })
        .collect();

    insta::assert_json_snapshot!(ignored);
}

/// Validates we can detect yanked crates from sparse, git, and
/// non crates.io registries
#[test]
fn detects_yanked() {
    // This crate has really light dependencies that _should_ still exercise
    // the yank checking without taking more than a couple of seconds to download
    // even though we always do it in a fresh temporary directory
    let td = temp_dir();
    let cargo_home = td.path();

    let mut cmd = krates::Cmd::new();

    // Note we need to set the current directory as cargo has a bug/design flaw
    // where .cargo/config.toml is only searched from the current working directory
    // not the location of the root manifest. which is....really annoying
    cmd.current_dir("examples/12_yank_check")
        .lock_opts(krates::LockOptions {
            frozen: false,
            locked: true,
            offline: false,
        });

    let mut cmd: krates::cm::MetadataCommand = cmd.into();
    cmd.env("CARGO_HOME", cargo_home);

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let indices = advisories::Indices::load(&krates, cargo_home.to_owned().try_into().unwrap());
    let dbs = advisories::DbSet { dbs: Vec::new() };

    {
        let cfg = tu::Config::new("yanked = 'deny'");

        let indices = advisories::Indices {
            indices: Vec::new(),
            cache: indices.cache.clone(),
        };

        let diags =
            tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
                advisories::check(
                    ctx,
                    &dbs,
                    Option::<advisories::NoneReporter>::None,
                    Some(indices),
                    tx,
                );
            });

        let diags: Vec<_> = diags
            .into_iter()
            .filter(|v| {
                v.pointer("/fields/message")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| v.starts_with("detected yanked crate"))
            })
            .collect();

        insta::assert_json_snapshot!(diags);
    }

    {
        let cfg = tu::Config::new(
            r#"
yanked = "deny"
ignore = [
    # This crate is in the graph, but we're ignoring it
    { crate = "spdx@0.3.1", reason = "a new version has not been released yet" },
    # This crate is not in the graph, so we should get a warning about it
    "boop",
]
"#,
        );

        let diags =
            tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
                advisories::check(
                    ctx,
                    &dbs,
                    Option::<advisories::NoneReporter>::None,
                    Some(indices),
                    tx,
                );
            });

        let diags: Vec<_> = diags
            .into_iter()
            .filter(|v| {
                v.pointer("/fields/message")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| {
                        v.starts_with("detected yanked crate") || v.starts_with("yanked crate")
                    })
            })
            .collect();

        insta::assert_json_snapshot!(diags);
    }
}

/// Validates that if we fail to load 1 or more indices, all the crates sourced
/// to that index will emit an diagnostic that they can't be checked
#[test]
fn warns_on_index_failures() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("yanked = 'deny'");

    let source = cargo_deny::Source::crates_io(false);

    let mut cache = std::collections::BTreeMap::new();

    for krate in krates.krates() {
        cache.insert(
            (krate.name.as_str(), &source),
            advisories::Entry::Error("this path is valid but we pretend it is non-utf8".into()),
        );
    }

    let indices = advisories::Indices {
        indices: vec![(
            &source,
            Err(tame_index::Error::NonUtf8Path(
                "this path is valid but we pretend it is non-utf8".into(),
            )),
        )],
        cache,
    };

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                Some(indices),
                tx,
            );
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

/// Validates that we emit a warning if a crate in the graph _does_ match an
/// advisory, however that advisory has been withdrawn <https://github.com/rustsec/advisory-db/pull/942>
#[test]
fn warns_on_ignored_and_withdrawn() {
    let TestCtx { dbs, krates } = load();

    let cfg = tu::Config::new("yanked = 'deny'\nignore = ['RUSTSEC-2020-0053']");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                None,
                tx,
            );
        });

    insta::assert_json_snapshot!(
        diags
            .iter()
            .find(|diag| field_eq!(diag, "/fields/code", "advisory-not-detected"))
            .unwrap()
    );
}

#[inline]
fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

#[inline]
fn to_path(td: &tempfile::TempDir) -> Option<&cargo_deny::Path> {
    Some(cargo_deny::Path::from_path(td.path()).unwrap())
}

/// Validates that stale advisory databases result in an error
#[test]
fn fails_on_stale_advisory_database() {
    assert!(
        advisories::DbSet::load(
            "tests/advisory-db".into(),
            vec![],
            advisories::Fetch::Disallow(time::Duration::seconds(0)),
        )
        .unwrap_err()
        .to_string()
        .contains("repository is stale")
    );
}

use advisories::Fetch;

const TEST_DB_URL: &str = "https://github.com/EmbarkStudios/test-advisory-db";
const TEST_DB_PATH: &str = "tests/advisory-db/test-advisory-db-c27873b782cceedc";
const GIT_PATH: &str = "test-advisory-db-c27873b782cceedc/.git";
const GIT_SUB_PATH: &str = ".git/modules/tests/advisory-db/test-advisory-db-c27873b782cceedc";

/// Expected HEAD without fetch
const EXPECTED_ONE: &str = "1f44d565d81692a44b8c7af8a80f587e19757f8c";
const EXPECTED_ONE_ID: &str = "BOOP-2023-0001";
const EXPECTED_ONE_DATE: &str = "2023-06-30";
/// Expected remote HEAD for <https://github.com/EmbarkStudios/test-advisory-db>
const EXPECTED_TWO: &str = "c84d73b086cc762f6a2b8ed794d47171a52781a3";
const EXPECTED_TWO_ID: &str = "BOOP-2023-0002";
const EXPECTED_TWO_DATE: &str = "2023-07-10";

fn do_open(td: &tempfile::TempDir, f: Fetch) -> advisories::AdvisoryDb {
    let mut db_set = advisories::DbSet::load(
        to_path(td).unwrap().to_owned(),
        vec![TEST_DB_URL.parse().unwrap()],
        f,
    )
    .unwrap();

    db_set.dbs.pop().unwrap()
}

fn validate(adb: &advisories::AdvisoryDb, rev: &str, ids: &[(&str, &str)]) {
    let repo = gix::open(&adb.path).expect("failed to open repo");
    assert_eq!(repo.head_commit().unwrap().id.to_hex().to_string(), rev);

    for (id, date) in ids {
        let adv = adb.db.get(&id.parse().unwrap()).expect("unable to find id");
        assert_eq!(adv.date().as_str(), *date);
    }

    assert!(
        (time::OffsetDateTime::now_utc() - adb.fetch_time) < std::time::Duration::from_secs(60)
    );
}

/// Validates we can clone an advisory database with gix
#[test]
fn clones_with_gix() {
    let td = temp_dir();
    let db = do_open(&td, Fetch::Allow);

    validate(
        &db,
        EXPECTED_TWO,
        &[
            (EXPECTED_ONE_ID, EXPECTED_ONE_DATE),
            (EXPECTED_TWO_ID, EXPECTED_TWO_DATE),
        ],
    );
}

/// Validates we can clone an advisory database with git
#[test]
fn clones_with_git() {
    let td = temp_dir();
    let db = do_open(&td, Fetch::AllowWithGitCli);

    validate(
        &db,
        EXPECTED_TWO,
        &[
            (EXPECTED_ONE_ID, EXPECTED_ONE_DATE),
            (EXPECTED_TWO_ID, EXPECTED_TWO_DATE),
        ],
    );
}

fn validate_fetch(fetch: Fetch) {
    let td = temp_dir();

    fs_extra::copy_items(
        &[TEST_DB_PATH],
        td.path(),
        &fs_extra::dir::CopyOptions::default(),
    )
    .expect("failed to copy");

    let git_path = td.path().join(GIT_PATH);
    std::fs::remove_file(&git_path).expect("unable to remove .git file");

    fs_extra::copy_items(
        &[GIT_SUB_PATH],
        &git_path,
        &fs_extra::dir::CopyOptions {
            copy_inside: true,
            ..Default::default()
        },
    )
    .expect("failed to copy");

    // We need to overwrite the config file in the git directory, otherwise
    // mutations will actually affect the working tree rather than the actual
    // temp location we've copied the submodule into
    std::fs::write(
        git_path.join("config"),
        r#"
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = https://github.com/EmbarkStudios/test-advisory-db
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
"#,
    )
    .expect("failed to write config");

    let db = do_open(&td, Fetch::Disallow(time::Duration::days(10000)));
    validate(&db, EXPECTED_ONE, &[(EXPECTED_ONE_ID, EXPECTED_ONE_DATE)]);

    let db = do_open(&td, fetch);
    validate(
        &db,
        EXPECTED_TWO,
        &[
            (EXPECTED_ONE_ID, EXPECTED_ONE_DATE),
            (EXPECTED_TWO_ID, EXPECTED_TWO_DATE),
        ],
    );
}

/// Validates we can fetch advisory db updates with gix
#[test]
fn fetches_with_gix() {
    #[allow(clippy::disallowed_macros)]
    if std::env::var_os("CI").is_some() && cfg!(target_os = "macos") {
        println!("consistently times out, so tired");
        return;
    }

    validate_fetch(Fetch::Allow);
}

/// Validates we can fetch advisory db updates with git
#[test]
fn fetches_with_git() {
    #[allow(clippy::disallowed_macros)]
    if std::env::var_os("CI").is_some() && cfg!(target_os = "macos") {
        println!("consistently times out, so tired");
        return;
    }

    validate_fetch(Fetch::AllowWithGitCli);
}

/// Validates that we can detect source replacement and can still perform yank
/// checking
#[test]
fn crates_io_source_replacement() {
    use rayon::prelude::*;

    // Create a local registry in a temp dir that we use a source replacement
    // for crates.io
    let lrd = temp_dir();
    {
        use tame_index::{external::reqwest, index::local};

        let sparse = tame_index::index::RemoteSparseIndex::new(
            tame_index::SparseIndex::new(tame_index::IndexLocation::new(
                tame_index::IndexUrl::CratesIoSparse,
            ))
            .unwrap(),
            reqwest::blocking::Client::new(),
        );

        // Use a separate even more temporary cargo home for the gathering of the
        // crates we want to write to the temp local registry, so that we don't
        // pollute the cargo home used in the actual test
        let temp_cargo_home = temp_dir();

        let mut cmd = krates::Cmd::new();

        // Note we need to set the current directory as cargo has a bug/design flaw
        // where .cargo/config.toml is only searched from the current working directory
        // not the location of the root manifest. which is....really annoying
        cmd.current_dir("examples/12_yank_check")
            .lock_opts(krates::LockOptions {
                frozen: false,
                locked: true,
                offline: false,
            });

        let mut cmd: krates::cm::MetadataCommand = cmd.into();
        cmd.env("CARGO_HOME", temp_cargo_home.path());

        let krates: Krates = krates::Builder::new()
            .build(cmd, krates::NoneFilter)
            .unwrap();

        struct IndexPkg {
            ik: tame_index::IndexKrate,
            version: semver::Version,
        }

        let lock = &tame_index::utils::flock::FileLock::unlocked();

        let index_krates: Vec<_> = krates
            .krates()
            .filter_map(|k| {
                if k.source.as_ref().is_none_or(|s| !s.is_crates_io()) {
                    return None;
                }
                Some(IndexPkg {
                    ik: sparse
                        .cached_krate(k.name.as_str().try_into().unwrap(), lock)
                        .unwrap()
                        .unwrap(),
                    version: k.version.clone(),
                })
            })
            .collect();

        let client =
            local::builder::Client::build(reqwest::blocking::ClientBuilder::new()).unwrap();

        let lrb = local::LocalRegistryBuilder::create(to_path(&lrd).unwrap().to_owned()).unwrap();
        let config = sparse.index.index_config().unwrap();

        index_krates.into_par_iter().for_each(|ip| {
            let iv = ip
                .ik
                .versions
                .iter()
                .find(|iv| iv.version.parse::<cargo_deny::Version>().unwrap() == ip.version)
                .unwrap();
            let vk = local::ValidKrate::download(&client, &config, iv).unwrap();

            lrb.insert(&ip.ik, &[vk]).unwrap();
        });

        let _lr = lrb.finalize(true).unwrap();
    }

    // Copy the package to a new temp dir so that we can mutate the config.toml
    // to use our new local registry
    let pkg_dir = temp_dir();
    {
        fs_extra::copy_items(
            &["examples/12_yank_check"],
            pkg_dir.path(),
            &Default::default(),
        )
        .expect("failed to copy");

        let config_path = pkg_dir.path().join("12_yank_check/.cargo/config.toml");
        let mut cfg =
            std::fs::read_to_string(&config_path).expect("failed to read .cargo/config.toml");

        cfg.push_str("\n[source.temp-local-registry]\n");
        use std::fmt::Write;
        writeln!(&mut cfg, "local-registry = \"{}\"", to_path(&lrd).unwrap()).unwrap();

        cfg.push_str("\n[source.crates-io]\n");
        cfg.push_str("replace-with = \"temp-local-registry\"");

        std::fs::write(config_path, cfg).expect("failed to write .cargo/config.toml");
    }

    // This crate has really light dependencies that _should_ still exercise
    // the yank checking without taking more than a couple of seconds to download
    // even though we always do it in a fresh temporary directory
    let td = temp_dir();
    let cargo_home = td.path();

    let mut cmd = krates::Cmd::new();

    // Note we need to set the current directory as cargo has a bug/design flaw
    // where .cargo/config.toml is only searched from the current working directory
    // not the location of the root manifest. which is....really annoying
    cmd.current_dir(pkg_dir.path().join("12_yank_check"))
        .lock_opts(krates::LockOptions {
            frozen: false,
            locked: true,
            offline: false,
        });

    let mut cmd: krates::cm::MetadataCommand = cmd.into();
    cmd.env("CARGO_HOME", cargo_home);

    let cargo_home: camino::Utf8PathBuf = cargo_home.to_owned().try_into().unwrap();

    let mut kb = krates::Builder::new();
    cargo_deny::krates_with_index(
        &mut kb,
        Some(to_path(&pkg_dir).unwrap().join("12_yank_check")),
        Some(cargo_home.clone()),
    )
    .unwrap();

    let krates: Krates = kb.build(cmd, krates::NoneFilter).unwrap();

    let indices = advisories::Indices::load(&krates, cargo_home.clone());

    let cfg = tu::Config::new("yanked = 'deny'");

    let dbs = advisories::DbSet { dbs: Vec::new() };

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                Some(indices),
                tx,
            );
        });

    let diags: Vec<_> = diags
        .into_iter()
        .filter(|v| {
            v.pointer("/fields/message")
                .and_then(|v| v.as_str())
                .is_some_and(|v| v.starts_with("detected yanked crate"))
        })
        .collect();

    insta::assert_json_snapshot!(diags);

    // Now that we've verified we can perform the yank checks against valid indices, go
    // in and corrupt/remove the index entries and perform the check again to ensure we
    // give good error messages to the user

    {
        let index = tame_index::index::ComboIndexCache::new(
            tame_index::IndexLocation::new(
                tame_index::IndexUrl::crates_io(
                    Some(to_path(&pkg_dir).unwrap().join("12_yank_check")),
                    Some(&cargo_home),
                    None,
                )
                .unwrap(),
            )
            .with_root(Some(cargo_home.clone())),
        )
        .unwrap();

        // Nuke spdx entirely
        let spath = index.cache_path("spdx".try_into().unwrap());
        std::fs::remove_file(spath).unwrap();

        // Note we also need to nuke the spdx crate file otherwise the local registry
        // validation will fail, we don't care about this, we are screwing it up on purpose
        std::fs::remove_file(lrd.path().join("spdx-0.3.1.crate")).unwrap();

        // Remove the specific version of smallvec pinned by the lockfile
        {
            let spath = index.cache_path("smallvec".try_into().unwrap());
            let json = std::fs::read_to_string(&spath).unwrap();

            let mut file = std::fs::File::create(spath).unwrap();
            for line in json.lines() {
                use std::io::Write as _;
                if line.contains(r#","vers":"1.6.1","#) {
                    continue;
                }
                assert_eq!(
                    file.write_vectored(&[
                        std::io::IoSlice::new(line.as_bytes()),
                        std::io::IoSlice::new(b"\n"),
                    ])
                    .unwrap(),
                    line.len() + 1
                );
            }

            std::fs::remove_file(lrd.path().join("smallvec-1.6.1.crate")).unwrap();
        }
    }

    // Change the version of the cache entry to a too old version that tame-index doesn't support
    {
        let index = tame_index::index::ComboIndexCache::new(
            tame_index::IndexLocation::new(
                "https://github.com/EmbarkStudios/cargo-test-index".into(),
            )
            .with_root(Some(cargo_home.clone())),
        )
        .unwrap();

        let spath = index.cache_path("crate-two".try_into().unwrap());
        let mut sc = std::fs::read(&spath).unwrap();
        sc[0] = tame_index::index::cache::CURRENT_CACHE_VERSION /* 3 */ - 2;
        std::fs::write(spath, sc).unwrap();
    }

    // Corrupt the entry by making the etag string invalid utf8
    {
        let index = tame_index::index::ComboIndexCache::new(
            tame_index::IndexLocation::new(
                "sparse+https://cargo.cloudsmith.io/embark/deny/".into(),
            )
            .with_root(Some(cargo_home.clone())),
        )
        .unwrap();

        let spath = index.cache_path("crate-one".try_into().unwrap());
        let mut sc = std::fs::read(&spath).unwrap();
        sc[11] = 0xc0;
        sc[12] = 0x80;
        std::fs::write(spath, sc).unwrap();
    }

    let indices = advisories::Indices::load(&krates, cargo_home.clone());

    let cfg = tu::Config::new("yanked = 'deny'");

    let diags =
        tu::gather_diagnostics::<cfg::Config, _, _>(&krates, func_name!(), cfg, |ctx, tx| {
            advisories::check(
                ctx,
                &dbs,
                Option::<advisories::NoneReporter>::None,
                Some(indices),
                tx,
            );
        });

    let diags: Vec<_> = diags
        .into_iter()
        .filter_map(|v| {
            v.pointer("/fields/notes/0")
                .and_then(|v| v.as_str())
                .map(|n| {
                    (
                        v.pointer("/fields/graphs/0/Krate/name")
                            .and_then(|v| v.as_str())
                            .unwrap()
                            .to_owned(),
                        n.replace(cargo_home.as_str(), "$TEMP_LOCAL"),
                    )
                })
        })
        .collect();

    insta::assert_json_snapshot!(diags);
}
