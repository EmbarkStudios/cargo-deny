use cargo_deny::advisories::db;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

struct Ctx {
    rs: rustsec::database::Database,
    cd: db::AdvisoryDb,
    krates: std::collections::BTreeMap<String, Option<Vec<semver::Version>>>,
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

        let mut krates: std::collections::BTreeMap<String, Option<Vec<semver::Version>>> = rs
            .iter()
            .filter_map(|adv| {
                adv.metadata.collection.and_then(|c| {
                    (c == rustsec::Collection::Crates).then(|| {
                        (
                            adv.metadata.package.as_str().to_owned(),
                            (!adv.metadata.expect_deleted).then_some(Vec::new()),
                        )
                    })
                })
            })
            .collect();

        let client = ureq::Agent::new_with_defaults();
        let sparse = tame_index::index::sparse::SparseIndex::new(
            tame_index::index::IndexLocation::new(tame_index::index::IndexUrl::CratesIoSparse),
        )
        .expect("failed to create sparse index");

        krates.par_iter_mut().for_each(|(k, v)| {
            let Some(v) = v.as_mut() else {
                return;
            };
            let url = sparse.crate_url(tame_index::KrateName::crates_io(k).unwrap());

            match client.get(&url).call() {
                Ok(res) => match tame_index::krate::IndexKrate::from_slice(
                    &res.into_body().read_to_vec().unwrap(),
                ) {
                    Ok(ik) => {
                        for iv in ik.versions {
                            match iv.version.parse() {
                                Ok(vs) => v.push(vs),
                                Err(err) => {
                                    panic!(
                                        "failed to parse version '{}' for crate {k}: {err}",
                                        iv.version
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        panic!("failed to deserialize {k}: {error}");
                    }
                },
                Err(error) => {
                    panic!("failed to retrieve {k}: {error}");
                }
            }
        });

        Ctx { cd, rs, krates }
    })
}

/// Ensures that cargo_deny can deserialize and serialize the exact same as rustsec for all advisories
#[test]
fn advisories_match() {
    let ctx = ctx();

    for adv in ctx.rs.iter() {
        if adv
            .metadata
            .collection
            .is_none_or(|c| c != rustsec::Collection::Crates)
        {
            continue;
        }

        let id = adv.metadata.id.as_str();
        let Some(cd_adv) = ctx.cd.db.advisories.get(id) else {
            panic!("advisory {id} not found in cargo_deny db");
        };

        let advs =
            serde_json::to_string_pretty(&serde_json::to_value(&adv.metadata).unwrap()).unwrap();
        let cd_advs = serde_json::to_string_pretty(&cd_adv.advisory.advisory.to_json()).unwrap();

        if advs == cd_advs {
            continue;
        }

        let diff = similar::TextDiff::from_lines(&advs, &cd_advs);

        for change in diff.iter_all_changes() {
            use similar::ChangeTag::*;
            let sign = match change.tag() {
                Delete => "\x1B[31m-",
                Insert => "\x1B[32m+",
                Equal => " ",
            };
            eprint!("\x1B[0m{sign}{change}\x1B[0m");
        }

        panic!("mismatch for {id}");
    }
}

/// Ensures that cargo_deny matches rustsec on detecting if the advisory applies to every published version of the crate
#[test]
fn affected_versions() {
    let ctx = ctx();

    let mut mismatches = 0;
    for adv in ctx.rs.iter() {
        if adv
            .metadata
            .collection
            .is_none_or(|c| c != rustsec::Collection::Crates)
        {
            continue;
        }

        let id = adv.metadata.id.as_str();

        let Some(cd_adv) = ctx.cd.db.advisories.get(id) else {
            panic!("advisory {id} not found in cargo_deny db");
        };

        let Some(versions) = ctx
            .krates
            .get(adv.metadata.package.as_str())
            .and_then(|v| v.as_ref())
        else {
            continue;
        };

        for vs in versions {
            match (
                adv.versions.is_vulnerable(vs),
                db::find_unaffected_req(&cd_adv.advisory.versions, vs),
            ) {
                (false, None) => eprintln!("\x1B[0m\x1B[31m{vs}\x1B[0m"),
                (true, Some(req)) => eprintln!("\x1B[0m\x1B[32m{vs} => {req}\x1B[0m"),
                _ => continue,
            };

            mismatches += 1;
        }
    }

    if mismatches > 0 {
        panic!("oh no");
    }
}
