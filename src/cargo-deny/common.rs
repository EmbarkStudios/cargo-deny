use std::path::{Path, PathBuf};

pub(crate) fn make_absolute_path(path: PathBuf, context_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        context_dir.join(path)
    }
}

use cargo_deny::licenses::LicenseStore;

pub(crate) fn load_license_store() -> Result<LicenseStore, anyhow::Error> {
    log::info!("loading license store...");
    LicenseStore::from_cache()
}

pub(crate) fn gather_krates(
    context_dir: PathBuf,
    targets: Vec<(String, Vec<String>)>,
) -> Result<cargo_deny::Krates, anyhow::Error> {
    log::info!("gathering crates for {}", context_dir.display());
    let krates_md = cargo_deny::get_krates_metadata(&context_dir)?;

    let mut gb = cargo_deny::graph::GraphBuilder::new();

    for target in targets {
        gb.include_target(target.0, target.1);
    }

    gb.ignore_kind(
        cargo_deny::DepKind::Dev,
        cargo_deny::graph::Unless::IsWorkspace,
    );

    let graph = gb.build_with_metadata(krates_md);

    if let Ok(ref krates) = graph {
        log::info!("gathered {} crates", krates.krates_count());
    }

    graph
}

// pub(crate) fn prune_krates_by_target(
//     krates: &mut cargo_deny::Krates,
//     which: Option<cargo_deny::prune::Prune<'_>>,
// ) -> Result<usize, anyhow::Error> {
//     log::info!("pruning crate graph of {} crates...", krates.krates.len());
//     let pruned = krates.prune(which)?;
//     log::info!("pruned {} crates", pruned);

//     Ok(pruned)
// }
