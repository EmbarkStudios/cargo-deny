use cargo_deny::{Krates, test_utils as tu};

fn gather_sarif<VC, R>(ctx: tu::GatherCtx<'_, VC>, runner: R) -> serde_json::Value
where
    VC: Send,
    R: FnOnce(cargo_deny::CheckCtx<'_, VC>, cargo_deny::diag::PackChannel) + Send,
{
    let (tx, rx) = crossbeam::channel::unbounded();

    let (_, sarif) = rayon::join(
        || {
            let cctx = cargo_deny::CheckCtx {
                krates: ctx.krates,
                krate_spans: &ctx.spans,
                cfg: ctx.valid_cfg,
                serialize_extra: true,
                colorize: false,
                log_level: log::LevelFilter::Info,
                files: &ctx.files,
            };
            runner(cctx, tx);
        },
        || {
            let mut sarif = cargo_deny::sarif::SarifCollector::default();

            let default = if std::env::var_os("CI").is_some() {
                60
            } else {
                30
            };

            let timeout = std::env::var("CARGO_DENY_TEST_TIMEOUT_SECS")
                .ok()
                .and_then(|ts| ts.parse().ok())
                .unwrap_or(default);
            let timeout = std::time::Duration::from_secs(timeout);

            let trx = crossbeam::channel::after(timeout);
            loop {
                crossbeam::select! {
                    recv(rx) -> msg => {
                        if let Ok(pack) = msg {
                            sarif.add_diagnostics(pack, &ctx.files);
                        } else {
                            // Yay, the sender was dropped (i.e. check was finished)
                            break;
                        }
                    }
                    recv(trx) -> _ => {
                        anyhow::bail!("Timed out after {timeout:?}");
                    }
                }
            }

            Ok(sarif.generate_sarif())
        },
    );

    let mut sl = sarif.expect("failed to gather Sarif results");

    let root = cargo_deny::PathBuf::try_from(std::env::current_dir().unwrap()).unwrap();

    // I can't tell if insta's redaction matchers actually support nested structures
    // so rather than try and fail, just redact manually
    for res in &mut sl.runs[0].results {
        for loc in &mut res.locations {
            loc.physical_location.artifact_location.uri = loc
                .physical_location
                .artifact_location
                .uri
                .replace(root.as_str(), "{CWD}");
        }

        for fp in res.partial_fingerprints.values_mut() {
            if fp.contains("file://") {
                *fp = fp.replace(root.as_str(), "{CWD}");
            }
        }
    }

    // Use a single version in tests so we don't have to bump snapshots every time
    // we bump versions
    sl.runs[0].tool.driver.version = Some(semver::Version::new(9, 9, 9));

    serde_json::to_value(sl).expect("failed to serialize Sarif results")
}

#[test]
fn sarif_advisories() {
    use cargo_deny::advisories;

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

    let cfg = tu::Config::new("");

    let ctx = tu::setup::<advisories::cfg::Config, _>(&krates, cargo_deny::func_name!(), cfg);
    let s = gather_sarif(ctx, |ctx, sink| {
        advisories::check(
            ctx,
            &db,
            Option::<advisories::NoneReporter>::None,
            None,
            sink,
        );
    });

    insta::assert_json_snapshot!(s);
}

#[test]
fn sarif_licenses() {
    use cargo_deny::licenses;

    let mut cmd = krates::Cmd::new();
    cmd.manifest_path("examples/04_gnu_licenses/Cargo.toml");

    let krates: Krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::new("allow = ['GPL-2.0-or-later']");
    let mut ctx = tu::setup::<licenses::cfg::Config, _>(&krates, cargo_deny::func_name!(), cfg);
    let gatherer = licenses::Gatherer::default()
        .with_store(std::sync::Arc::new(
            licenses::LicenseStore::from_cache().unwrap(),
        ))
        .with_confidence_threshold(0.8);

    let summary = gatherer.gather(ctx.krates, &mut ctx.files, Some(&ctx.valid_cfg));

    let s = gather_sarif(ctx, |ctx, sink| licenses::check(ctx, summary, sink.into()));

    insta::assert_json_snapshot!(s);
}

#[test]
fn sarif_bans() {
    use cargo_deny::bans;

    let mut cmd = krates::Cmd::new();
    cmd.features(["zlib", "ssh"].into_iter().map(String::from))
        .lock_opts(krates::LockOptions {
            locked: true,
            frozen: false,
            offline: false,
        })
        .manifest_path("tests/test_data/features-galore/Cargo.toml");

    let krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::new(
        "
multiple-versions = 'deny'
deny = ['vcpkg']
features = [
    { name = 'features-galore', deny = ['simple'] },
    { name = 'libssh2-sys', deny = ['zlib-ng-compat'] },
    { name = 'features-galore', allow = ['ssh'] },
]
",
    );
    let ctx = tu::setup::<bans::cfg::Config, _>(&krates, cargo_deny::func_name!(), cfg);

    let s = gather_sarif(ctx, |ctx, sink| bans::check(ctx, None, sink));

    insta::assert_json_snapshot!(s);
}

#[test]
fn sarif_sources() {
    use cargo_deny::sources;

    let mut cmd = krates::Cmd::new();
    cmd.lock_opts(krates::LockOptions {
        locked: true,
        frozen: false,
        offline: false,
    })
    .manifest_path("tests/test_data/sources/Cargo.toml");

    let krates = krates::Builder::new()
        .build(cmd, krates::NoneFilter)
        .unwrap();

    let cfg = tu::Config::new(
        "unknown-git = 'deny'
allow-git = [
    'https://bitbucket.org/marshallpierce/line-wrap-rs',
]
[allow-org]
github = ['EmbarkStudios', 'bizzlepop']
",
    );
    let ctx = tu::setup::<sources::cfg::Config, _>(&krates, cargo_deny::func_name!(), cfg);

    let s = gather_sarif(ctx, sources::check);

    insta::assert_json_snapshot!(s);
}
