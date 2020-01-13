use anyhow::{ensure, Error};
use cargo_deny::{
    advisories::{self, cfg},
    diag, Krates,
};
use krates::cm::Metadata;

struct Ctx {
    krates: Krates,
    spans: (diag::KrateSpans, codespan::FileId),
    db: advisories::Database,
    lock: advisories::Lockfile,
    files: parking_lot::RwLock<codespan::Files<String>>,
}

fn load() -> Ctx {
    let md: Metadata =
        serde_json::from_str(&std::fs::read_to_string("tests/06_advisories.json").unwrap())
            .unwrap();

    let krates: Krates = krates::Builder::new()
        .build_with_metadata(md, krates::NoneFilter)
        .unwrap();

    let spans = diag::KrateSpans::new(&krates);
    let lock = advisories::generate_lockfile(&krates);

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
        files: parking_lot::RwLock::new(files),
    }
}

fn generates_same_lockfile(ctx: &Ctx) -> Result<(), Error> {
    let lockfile =
        advisories::load_lockfile(&std::path::Path::new("examples/06_advisories/Cargo.lock"))?;

    if ctx.lock != lockfile {
        let diff = difference::Changeset::new(
            &format!("{:#?}", ctx.lock),
            &format!("{:#?}", lockfile),
            "\n",
        );

        //        let diff = "by a lot";

        anyhow::bail!("lock files differ\n{}", diff);
    } else {
        Ok(())
    }
}

fn load_cfg(ctx: &Ctx, test_name: &str, cfg_str: String) -> Result<cfg::ValidConfig, Error> {
    let cfg: advisories::cfg::Config = toml::from_str(&cfg_str)?;

    let cfg_id = ctx.files.write().add(test_name.to_owned(), cfg_str);

    cfg.validate(cfg_id)
        .map_err(|_| anyhow::anyhow!("failed to load {}", test_name))
}

fn detects_vulnerabilities(ctx: &Ctx) -> Result<(), Error> {
    let (tx, rx) = crossbeam::channel::unbounded();

    let cfg = load_cfg(
        ctx,
        "detects_vulnerabilities",
        "vulnerability = \"deny\"".into(),
    )?;

    let (_, vuln_res) = rayon::join(
        || {
            advisories::check(
                cfg,
                &ctx.krates,
                (&ctx.spans.0, ctx.spans.1),
                &ctx.db,
                &ctx.lock,
                tx,
            );
        },
        || {
            let mut res = Err(anyhow::anyhow!("failed to receive unmaintained"));

            for msg in rx {
                for diag in msg.diagnostics {
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
                            diag.primary_label.message == "security vulnerability detected",
                            dbg!(
                                dbg!(diag.primary_label.message)
                                    == "security vulnerability detected"
                            )
                        );

                        res = Ok(());
                    }
                }
            }

            res
        },
    );

    vuln_res
}

fn detects_unmaintained(ctx: &Ctx) -> Result<(), Error> {
    let (tx, rx) = crossbeam::channel::unbounded();

    let cfg = load_cfg(
        ctx,
        "detects_unmaintained",
        "unmaintained = \"warn\"".into(),
    )?;

    let (_, vuln_res) = rayon::join(
        || {
            advisories::check(
                cfg,
                &ctx.krates,
                (&ctx.spans.0, ctx.spans.1),
                &ctx.db,
                &ctx.lock,
                tx,
            );
        },
        || {
            let mut res = Err(anyhow::anyhow!("failed to receive unmaintained"));

            for msg in rx {
                for diag in msg.diagnostics {
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
                            diag.primary_label.message == "unmaintained advisory detected",
                            dbg!(
                                dbg!(diag.primary_label.message)
                                    == "unmaintained advisory detected"
                            )
                        );

                        res = Ok(());
                    }
                }
            }

            res
        },
    );

    vuln_res
}

fn downgrades(ctx: &Ctx) -> Result<(), Error> {
    let (tx, rx) = crossbeam::channel::unbounded();

    let cfg = load_cfg(
        ctx,
        "downgrades",
        "unmaintained = \"warn\"\nignore = [\"RUSTSEC-2016-0004\",\"RUSTSEC-2019-0001\"]".into(),
    )?;

    let (_, vuln_res) = rayon::join(
        || {
            advisories::check(
                cfg,
                &ctx.krates,
                (&ctx.spans.0, ctx.spans.1),
                &ctx.db,
                &ctx.lock,
                tx,
            );
        },
        || {
            let mut got_ammonia_vuln = false;
            let mut got_libusb_adv = false;

            for msg in rx {
                for diag in msg.diagnostics {
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
                            diag.primary_label.message == "security vulnerability detected",
                            dbg!(
                                dbg!(diag.primary_label.message)
                                    == "security vulnerability detected"
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
                            diag.primary_label.message == "unmaintained advisory detected",
                            dbg!(
                                dbg!(diag.primary_label.message)
                                    == "unmaintained advisory detected"
                            )
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

    vuln_res
}

#[test]
fn test_advisories() {
    // rustsec's Database is not really amenable to testing atm
    // so we just load it once and reuse it to run tests, bit
    // unfortunate but not a huge deal
    let ctx = load();

    let mut generates_same_lockfile_res =
        Err(anyhow::anyhow!("no result from generates_same_lockfile"));
    let mut detects_vulns_res = Err(anyhow::anyhow!("no result from detects_vulnerabilities"));
    let mut detects_unmaintained_res = Err(anyhow::anyhow!("no result from detects_unmaintained"));
    let mut downgrades_res = Err(anyhow::anyhow!("no result from downgrades"));

    rayon::scope(|s| {
        s.spawn(|_| {
            generates_same_lockfile_res = generates_same_lockfile(&ctx);
        });

        s.spawn(|_| {
            detects_vulns_res = detects_vulnerabilities(&ctx);
        });

        s.spawn(|_| {
            detects_unmaintained_res = detects_unmaintained(&ctx);
        });

        s.spawn(|_| {
            downgrades_res = downgrades(&ctx);
        });
    });

    generates_same_lockfile_res.unwrap();
    detects_vulns_res.unwrap();
    detects_unmaintained_res.unwrap();
}
