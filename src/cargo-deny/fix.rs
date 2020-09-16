use anyhow::{Context, Error};
use cargo_deny::{
    advisories,
    diag::{Diagnostic, Files},
    manifest,
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to <cwd>/deny.toml if not specified
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
    /// Allows crates to be patched with versions which are incompatible with
    /// the current version requirements.
    #[structopt(long)]
    allow_incompatible: bool,
    /// Disable fetching of the advisory database and crates.io index
    ///
    /// By default the advisory database and crates.io index are updated before checking the advisories, if disabled via this flag, an error occurs if the advisory database or crates.io index are not available locally already.
    #[structopt(short, long)]
    disable_fetch: bool,
    /// Prints what would occur, but does not actually modify any files on disk
    #[structopt(long)]
    dry_run: bool,
}

#[derive(serde::Deserialize)]
struct Config {
    advisories: Option<advisories::cfg::Config>,
    #[serde(default)]
    targets: Vec<crate::common::Target>,
}

struct ValidConfig {
    advisories: advisories::cfg::ValidConfig,
    targets: Vec<(krates::Target, Vec<String>)>,
}

impl ValidConfig {
    fn load(
        cfg_path: Option<PathBuf>,
        files: &mut Files,
        log_ctx: crate::common::LogContext,
    ) -> Result<Self, Error> {
        use cargo_deny::UnvalidatedConfig;

        let (cfg_contents, cfg_path) = match cfg_path {
            Some(cfg_path) if cfg_path.exists() => (
                std::fs::read_to_string(&cfg_path).with_context(|| {
                    format!("failed to read config from {}", cfg_path.display())
                })?,
                cfg_path,
            ),
            Some(cfg_path) => {
                log::warn!(
                    "config path '{}' doesn't exist, falling back to default config",
                    cfg_path.display()
                );
                (String::new(), cfg_path)
            }
            None => {
                log::warn!("unable to find a config path, falling back to default config");
                (String::new(), PathBuf::from("deny.default.toml"))
            }
        };

        let cfg: Config = toml::from_str(&cfg_contents).with_context(|| {
            format!("failed to deserialize config from '{}'", cfg_path.display())
        })?;

        log::info!("using config from {}", cfg_path.display());

        let id = files.add(&cfg_path, cfg_contents);

        let print = |diags: Vec<Diagnostic>| {
            if diags.is_empty() {
                return;
            }

            if let Some(printer) = crate::common::DiagPrinter::new(log_ctx, None) {
                let mut lock = printer.lock();
                for diag in diags {
                    lock.print(diag, &files);
                }
            }
        };

        let mut diags = Vec::new();
        let advisories = cfg.advisories.unwrap_or_default().validate(id, &mut diags);
        let targets = crate::common::load_targets(cfg.targets, &mut diags, id);

        let has_errors = diags
            .iter()
            .any(|d| d.severity <= cargo_deny::diag::Severity::Error);
        print(diags);

        if has_errors {
            anyhow::bail!(
                "failed to validate configuration file {}",
                cfg_path.display()
            );
        } else {
            Ok(Self {
                advisories,
                targets,
            })
        }
    }
}

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    let cfg_path = ctx.get_config_path(args.config.clone());

    let mut files = Files::new();
    let ValidConfig {
        advisories,
        targets,
    } = ValidConfig::load(cfg_path, &mut files, log_ctx)?;

    // Parallel all the things
    let mut index = None;
    let mut dbs = None;
    let mut krates = None;
    let mut lockfile = None;

    rayon::scope(|s| {
        if !args.disable_fetch {
            s.spawn(|_| {
                log::info!("fetching crates.io index...");
                index = Some(rustsec::registry::Index::fetch());
                log::info!("fetched crates.io index");
            });
        }

        s.spawn(|_| {
            // This function already logs internally
            dbs = Some(advisories::DbSet::load(
                advisories.db_path,
                advisories.db_urls.into_iter().map(|u| u.take()).collect(),
                if args.disable_fetch {
                    advisories::Fetch::Disallow
                } else {
                    advisories::Fetch::Allow
                },
            ));
        });

        s.spawn(|_| {
            krates = Some(ctx.gather_krates(targets));
            if let Ok(krates) = krates.as_ref().unwrap() {
                lockfile = Some(advisories::load_lockfile(krates.lock_path()));
            }
        });
    });

    if let Some(index) = index {
        index.context("failed to fetch crates.io index")?;
    }

    let dbs = dbs.unwrap().context("failed to load advisory database")?;

    let krates = krates.unwrap().context("failed to gather crate graph")?;
    let lockfile = lockfile.unwrap().context("failed to load lockfile")?;

    let lockfile = advisories::PrunedLockfile::prune(lockfile, &krates);

    let report = advisories::Report::generate(&dbs, &lockfile, false);

    // For now we only care about vulnerabilities, but we can add support for fixing
    // the informational advisories as well, at least the ones that contain information
    // on what crate/version fixes the issue in the advisory
    if report.vulnerabilities.is_empty() {
        log::info!("No vulnerabilities were detected");
    }

    let patch_set = report
        .gather_patches(
            &krates,
            if args.allow_incompatible {
                advisories::fix::Semver::Latest
            } else {
                advisories::fix::Semver::Compatible
            },
        )
        .context("failed to gather patches")?;

    // Print diagnostics
    //println!("{:#?}", patch_set);

    // Apply patches for each unique manifest
    let mut manifests = std::collections::HashMap::new();

    for patch in &patch_set.patches {
        if !manifests.contains_key(&patch.manifest_to_patch.id) {
            manifests.insert(
                patch.manifest_to_patch.id.clone(),
                (&patch.manifest_to_patch, Vec::new()),
            );
        }

        // The patches will be unique per edge so we don't have to worry about
        // duplicates for the same dependency here
        let dep_update = manifest::dep::Dependency::new(patch.crate_to_patch.0.to_owned())
            // We just use the stringified Version as the new requirement for simplicity
            .set_version(patch.crate_to_patch.1.to_string());

        if let Some(kp) = manifests.get_mut(&patch.manifest_to_patch.id) {
            kp.1.push(dep_update);
        }
    }

    let mut num_errors = 0;

    for (krate, patches) in manifests.values() {
        let path = &krate.manifest_path;
        log::info!("Patching '{}'", path.display());

        let manifest_contents = match std::fs::read_to_string(path) {
            Ok(mc) => mc,
            Err(e) => {
                log::error!(
                    "Unable to read manifest '{}' for crate '{} = {}': {}",
                    path.display(),
                    krate.name,
                    krate.version,
                    e
                );
                num_errors += 1;
                continue;
            }
        };

        let mut manifest: manifest::Manifest = match manifest_contents.parse() {
            Ok(man) => man,
            Err(e) => {
                log::error!(
                    "Unable to parse manifest '{}' for crate '{} = {}': {}",
                    path.display(),
                    krate.name,
                    krate.version,
                    e
                );
                num_errors += 1;
                continue;
            }
        };

        match manifest.upgrade(&patches) {
            Ok(_) => {
                let updated_contents = manifest.doc.to_string_in_original_order();

                // If we're doing a dry run, just print what the diff would be
                // if we actually serialized to disk
                if args.dry_run {
                    let cs =
                        difference::Changeset::new(&manifest_contents, &updated_contents, "\n");

                    log::info!("Patch for {} = {}\n{}", krate.name, krate.version, cs);
                } else {
                    match std::fs::write(path, &updated_contents) {
                        Ok(_) => log::info!("Patched {}", path.display()),
                        Err(e) => {
                            log::error!("Failed to update '{}': {}", path.display(), e);
                            num_errors += 1;
                        }
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to apply patch(es) to manifest '{}': {}",
                    path.display(),
                    e
                );
                num_errors += 1;
            }
        }
    }

    if num_errors > 0 {
        anyhow::bail!(
            "Encountered {} errors while attempting to apply patches",
            num_errors
        );
    } else {
        Ok(())
    }
}
