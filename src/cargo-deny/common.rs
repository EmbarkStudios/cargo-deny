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

    let mut mdc = krates::Cmd::new();

    mdc.all_features();
    mdc.manifest_path(context_dir.join("Cargo.toml"));

    use krates::{Builder, DepKind};

    let mut gb = Builder::new();

    gb.include_targets(targets);
    gb.ignore_kind(DepKind::Dev, krates::Scope::NonWorkspace);

    let graph = gb.build(mdc, |filtered: krates::cm::Package| match filtered.source {
        Some(src) => {
            if src.is_crates_io() {
                log::debug!("filtered {} {}", filtered.name, filtered.version);
            } else {
                log::debug!("filtered {} {} {}", filtered.name, filtered.version, src);
            }
        }
        None => log::debug!("filtered crate {} {}", filtered.name, filtered.version),
    });

    if let Ok(ref krates) = graph {
        log::info!("gathered {} crates", krates.len());
    }

    Ok(graph?)
}

#[derive(serde::Deserialize)]
pub(crate) struct Target {
    pub(crate) triple: cargo_deny::Spanned<String>,
    #[serde(default)]
    pub(crate) features: Vec<String>,
}

use cargo_deny::diag::Diagnostic;

pub(crate) fn load_targets(
    in_targets: Vec<Target>,
    diagnostics: &mut Vec<Diagnostic>,
    id: codespan::FileId,
) -> Vec<(String, Vec<String>)> {
    let mut targets = Vec::with_capacity(in_targets.len());
    for target in in_targets {
        let triple = target.triple.as_ref();

        if krates::cfg_expr::targets::get_target_by_triple(triple).is_none() {
            diagnostics.push(Diagnostic::new_warning(
                format!("unknown target `{}` specified", triple),
                cargo_deny::diag::Label::new(
                    id,
                    target.triple.span().clone(),
                    "the triple won't be evaluated against cfg() sections, just explicit triples",
                ),
            ));
        }

        targets.push((triple.into(), target.features));
    }

    targets
}
