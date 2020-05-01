use anyhow::{ensure, Error};
use cargo_deny::{
    advisories::{self, cfg},
    diag, Krates,
};
use krates::cm::Metadata;
use std::sync::RwLock;

struct Ctx {
    krates: Krates,
    spans: (diag::KrateSpans, codespan::FileId),
    db: advisories::Database,
    lock: advisories::Lockfile,
    files: RwLock<codespan::Files<String>>,
}

fn load() -> Ctx {
    let md: Metadata =
        serde_json::from_str(&std::fs::read_to_string("tests/06_advisories.json").unwrap())
            .unwrap();

    let krates: Krates = krates::Builder::new()
        .build_with_metadata(md, krates::NoneFilter)
        .unwrap();

    let spans = diag::KrateSpans::new(&krates);
    //let lock = advisories::generate_lockfile(&krates);
    let lock = advisories::load_lockfile(&std::path::Path::new("tests/06_Cargo.lock")).unwrap();

    let db = {
        let tmp = tempfile::tempdir().unwrap();
        advisories::load_db(None, Some(tmp.path().to_owned()), advisories::Fetch::Allow).unwrap()
    };

    let mut files = codespan::Files::new();
    let spans = (spans.0, files.add("Cargo.lock", spans.1));

    Ctx {
        krates,
        spans,
        lock,
        db,
        files: RwLock::new(files),
    }
}

fn load_cfg(ctx: &Ctx, test_name: &str, cfg_str: String) -> Result<cfg::ValidConfig, Error> {
    let cfg: advisories::cfg::Config = toml::from_str(&cfg_str)?;

    let cfg_id = ctx
        .files
        .write()
        .unwrap()
        .add(test_name.to_owned(), cfg_str);

    cfg.validate(cfg_id)
        .map_err(|_| anyhow::anyhow!("failed to load {}", test_name))
}

#[test]
#[ignore]
fn detects_vulnerabilities() {
    let (tx, rx) = crossbeam::channel::unbounded();
    let ctx = load();

    let cfg = load_cfg(
        &ctx,
        "detects_vulnerabilities",
        "vulnerability = \"deny\"".into(),
    )
    .unwrap();

    let (_, vuln_res) = rayon::join(
        || {
            let ctx2 = cargo_deny::CheckCtx {
                cfg,
                krates: &ctx.krates,
                krate_spans: &ctx.spans.0,
                spans_id: ctx.spans.1,
            };

            advisories::check(ctx2, &ctx.db, ctx.lock, tx);
        },
        || {
            let mut res = Err(anyhow::anyhow!("failed to receive unmaintained"));

            for msg in rx {
                for diag in msg.into_iter() {
                    let diag = diag.diag;
                    if diag.code == Some("RUSTSEC-2019-0001".to_owned()) {
                        ensure!(
                            diag.severity == diag::Severity::Error,
                            dbg!(dbg!(diag.severity) == diag::Severity::Error)
                        );
                        ensure!(
                            diag.message == "Uncontrolled recursion leads to abort in HTML serialization",
                            dbg!(dbg!(diag.message) == "Uncontrolled recursion leads to abort in HTML serialization")
                        );
                        ensure!(
                            diag.labels[0].message == "security vulnerability detected",
                            dbg!(
                                dbg!(&diag.labels[0].message) == "security vulnerability detected"
                            )
                        );

                        res = Ok(());
                    }
                }
            }

            res
        },
    );

    vuln_res.unwrap()
}

#[test]
#[ignore]
fn detects_unmaintained() {
    let (tx, rx) = crossbeam::channel::unbounded();

    let ctx = load();
    let cfg = load_cfg(
        &ctx,
        "detects_unmaintained",
        "unmaintained = \"warn\"".into(),
    )
    .unwrap();

    let (_, unmaintained_res) = rayon::join(
        || {
            let ctx2 = cargo_deny::CheckCtx {
                cfg,
                krates: &ctx.krates,
                krate_spans: &ctx.spans.0,
                spans_id: ctx.spans.1,
            };

            advisories::check(ctx2, &ctx.db, ctx.lock, tx);
        },
        || {
            let mut res = Err(anyhow::anyhow!("failed to receive unmaintained"));

            for msg in rx {
                for diag in msg.into_iter() {
                    let diag = diag.diag;
                    if diag.code == Some("RUSTSEC-2016-0004".to_owned()) {
                        ensure!(
                            diag.severity == diag::Severity::Warning,
                            dbg!(dbg!(diag.severity) == diag::Severity::Warning)
                        );
                        ensure!(
                            diag.message == "libusb is unmaintained; use rusb instead",
                            dbg!(dbg!(diag.message) == "libusb is unmaintained; use rusb instead")
                        );
                        ensure!(
                            diag.labels[0].message == "unmaintained advisory detected",
                            dbg!(dbg!(&diag.labels[0].message) == "unmaintained advisory detected")
                        );

                        res = Ok(());
                    }
                }
            }

            res
        },
    );

    unmaintained_res.unwrap()
}

#[test]
#[ignore]
fn downgrades() {
    let (tx, rx) = crossbeam::channel::unbounded();

    let ctx = load();
    let cfg = load_cfg(
        &ctx,
        "downgrades",
        "unmaintained = \"warn\"\nignore = [\"RUSTSEC-2016-0004\",\"RUSTSEC-2019-0001\"]".into(),
    )
    .unwrap();

    let (_, down_res) = rayon::join(
        || {
            let ctx2 = cargo_deny::CheckCtx {
                cfg,
                krates: &ctx.krates,
                krate_spans: &ctx.spans.0,
                spans_id: ctx.spans.1,
            };

            advisories::check(ctx2, &ctx.db, ctx.lock, tx);
        },
        || {
            let mut got_ammonia_vuln = false;
            let mut got_libusb_adv = false;

            for msg in rx {
                for diag in msg.into_iter() {
                    let diag = diag.diag;
                    if diag.code == Some("RUSTSEC-2019-0001".to_owned()) {
                        ensure!(
                            diag.severity == diag::Severity::Note,
                            dbg!(dbg!(diag.severity) == diag::Severity::Note)
                        );
                        ensure!(
                            diag.message == "Uncontrolled recursion leads to abort in HTML serialization",
                            dbg!(dbg!(diag.message) == "Uncontrolled recursion leads to abort in HTML serialization")
                        );
                        ensure!(
                            diag.labels[0].message == "security vulnerability detected",
                            dbg!(
                                dbg!(&diag.labels[0].message) == "security vulnerability detected"
                            )
                        );

                        got_ammonia_vuln = true;
                    }

                    if diag.code == Some("RUSTSEC-2016-0004".to_owned()) {
                        ensure!(
                            diag.severity == diag::Severity::Note,
                            dbg!(dbg!(diag.severity) == diag::Severity::Note)
                        );
                        ensure!(
                            diag.message == "libusb is unmaintained; use rusb instead",
                            dbg!(dbg!(diag.message) == "libusb is unmaintained; use rusb instead")
                        );
                        ensure!(
                            diag.labels[0].message == "unmaintained advisory detected",
                            dbg!(dbg!(&diag.labels[0].message) == "unmaintained advisory detected")
                        );

                        got_libusb_adv = true;
                    }
                }
            }

            ensure!(
                got_ammonia_vuln && got_libusb_adv,
                dbg!(dbg!(got_ammonia_vuln) && dbg!(got_libusb_adv))
            );
            Ok(())
        },
    );

    down_res.unwrap()
}

#[test]
#[ignore]
fn detects_yanked() {
    // Force fetch the index just in case
    rustsec::registry::Index::fetch().unwrap();

    let (tx, rx) = crossbeam::channel::unbounded();
    let ctx = load();

    let cfg = load_cfg(&ctx, "detects_yanked", "yanked = \"deny\"".into()).unwrap();

    let (_, yanked_res) = rayon::join(
        || {
            let ctx2 = cargo_deny::CheckCtx {
                cfg,
                krates: &ctx.krates,
                krate_spans: &ctx.spans.0,
                spans_id: ctx.spans.1,
            };

            advisories::check(ctx2, &ctx.db, ctx.lock, tx);
        },
        || {
            let mut res = Err(anyhow::anyhow!("failed to receive yanked"));

            for msg in rx {
                for diag in msg.into_iter() {
                    let diag = diag.diag;

                    if diag.code.is_none() {
                        ensure!(
                            diag.severity == diag::Severity::Error,
                            dbg!(dbg!(diag.severity) == diag::Severity::Error)
                        );

                        ensure!(
                            diag.message == "detected yanked crate",
                            dbg!(dbg!(diag.message) == "detected yanked crate")
                        );

                        ensure!(
                            diag.labels[0].message == "yanked version",
                            dbg!(dbg!(&diag.labels[0].message) == "yanked version")
                        );

                        res = Ok(());
                    }
                }
            }

            res
        },
    );

    yanked_res.unwrap()
}
