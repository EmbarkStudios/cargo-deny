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

pub(crate) fn gather_krates(context_dir: PathBuf) -> Result<cargo_deny::Krates, anyhow::Error> {
    log::info!("gathering crates for {}", context_dir.display());

    let krates = cargo_deny::get_all_crates(&context_dir);

    if let Ok(ref krates) = krates {
        log::info!("gathered {} crates", krates.krates.len());
    }

    krates
}
