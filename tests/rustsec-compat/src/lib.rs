use cargo_deny::advisories::db;

struct Ctx {
    rs: rustsec::database::Database,
    cd: db::AdvisoryDb,
    krates: std::collections::BTreeMap<String, Vec<semver::Version>>,
}

static CTX: std::sync::OnceLock<Ctx> = std::sync::OnceLock::new();

fn ctx() -> &'static Ctx {
    CTX.get_or_init(|| {
        let td = cargo_deny::PathBuf::from_path_buf(std::env::temp_dir()).unwrap();
        let cd = db::AdvisoryDb::load(
            db::DEFAULT_URL.parse().unwrap(),
            td,
            db::Fetch::AllowWithGitCli,
        )
        .expect("(cargo_deny) failed to load db");

        let rs = rustsec::database::Database::open(cd.path.as_std_path())
            .expect("(rustsec) failed to load db");
    })
}

/// Ensures that cargo_deny can deserialize and serialize the exact same as rustsec for all advisories
#[test]
fn advisories_match() {
    let ctx = ctx();
}

/// Ensures that cargo_deny matches rustsec on detecting if the advisory applies to every published version of the crate
#[test]
fn affected_versions() {
    let ctx = ctx();

    for adv in ctx.rs.iter() {}
}
