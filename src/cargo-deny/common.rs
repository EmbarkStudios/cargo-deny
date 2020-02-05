use std::path::PathBuf;

use cargo_deny::licenses::LicenseStore;

pub(crate) fn load_license_store() -> Result<LicenseStore, anyhow::Error> {
    log::info!("loading license store...");
    LicenseStore::from_cache()
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

pub struct KrateContext {
    pub manifest_path: PathBuf,
    pub workspace: bool,
    pub exclude: Vec<String>,
    pub targets: Vec<String>,
}

impl KrateContext {
    pub fn get_config_path(&self, config_path: Option<PathBuf>) -> Option<PathBuf> {
        match config_path {
            Some(cp) => {
                if cp.is_absolute() {
                    Some(cp)
                } else {
                    Some(self.manifest_path.parent().unwrap().join(cp))
                }
            }
            None => {
                let mut p = self.manifest_path.parent();

                while let Some(parent) = p {
                    let config_path = parent.join("deny.toml");

                    if config_path.exists() {
                        return Some(config_path);
                    }

                    p = parent.parent();
                }

                None
            }
        }
    }

    pub fn gather_krates(
        self,
        cfg_targets: Vec<(String, Vec<String>)>,
    ) -> Result<cargo_deny::Krates, anyhow::Error> {
        log::info!("gathering crates for {}", self.manifest_path.display());

        let mut mdc = krates::Cmd::new();

        mdc.all_features();
        mdc.manifest_path(self.manifest_path);

        use krates::{Builder, DepKind};

        let mut gb = Builder::new();

        // Use targets passed on the command line first, and fallback to config
        // based targets otherwise
        if !self.targets.is_empty() {
            gb.include_targets(self.targets.into_iter().map(|t| (t, Vec::new())));
        } else if !cfg_targets.is_empty() {
            gb.include_targets(cfg_targets);
        }

        gb.ignore_kind(DepKind::Dev, krates::Scope::NonWorkspace);
        gb.workspace(self.workspace);

        if !self.exclude.is_empty() {
            gb.exclude(
                self.exclude
                    .into_iter()
                    .filter_map(|spec| match spec.parse() {
                        Ok(spec) => Some(spec),
                        Err(e) => {
                            log::warn!("invalid pkg spec '{}': {}", spec, e);
                            None
                        }
                    }),
            );
        }

        let graph = gb.build(mdc, |filtered: krates::cm::Package| match filtered.source {
            Some(src) => {
                if src.is_crates_io() {
                    log::debug!("filtered {} {}", filtered.name, filtered.version);
                } else {
                    log::debug!("filtered {} {} {}", filtered.name, filtered.version, src);
                }
            }
            None => log::debug!("filtered {} {}", filtered.name, filtered.version),
        });

        if let Ok(ref krates) = graph {
            log::info!("gathered {} crates", krates.len());
        }

        Ok(graph?)
    }
}
