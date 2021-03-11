use anyhow::{Context, Error};
use cargo_deny::{
    advisories,
    diag::{Diagnostic, Files},
};
use std::path::PathBuf;
use structopt::{clap::arg_enum, StructOpt};

arg_enum! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub enum FetchSource {
        Db,
        Index,
        All,
    }
}

#[derive(StructOpt, Debug, Clone)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to <cwd>/deny.toml if not specified
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
    /// The sources to fetch
    #[structopt(
        possible_values = &FetchSource::variants(),
        case_insensitive = true,
    )]
    sources: Vec<FetchSource>,
}

#[derive(serde::Deserialize)]
struct Config {
    advisories: Option<advisories::cfg::Config>,
}

struct ValidConfig {
    advisories: advisories::cfg::ValidConfig,
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
                    lock.print(diag, files);
                }
            }
        };

        let mut diags = Vec::new();
        let advisories = cfg.advisories.unwrap_or_default().validate(id, &mut diags);

        let has_errors = diags
            .iter()
            .any(|d| d.severity >= cargo_deny::diag::Severity::Error);
        print(diags);

        if has_errors {
            anyhow::bail!(
                "failed to validate configuration file {}",
                cfg_path.display()
            );
        } else {
            Ok(Self { advisories })
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
    let cfg = ValidConfig::load(cfg_path, &mut files, log_ctx)?;

    let mut index = None;
    let mut dbs = None;

    rayon::scope(|s| {
        let fetch_index = args.sources.is_empty()
            || args
                .sources
                .iter()
                .any(|w| *w == FetchSource::Index || *w == FetchSource::All);

        if fetch_index {
            s.spawn(|_| {
                log::info!("fetching crates.io index...");
                index = Some(rustsec::registry::Index::fetch());
                log::info!("fetched crates.io index");
            });
        }

        let fetch_db = args.sources.is_empty()
            || args
                .sources
                .iter()
                .any(|w| *w == FetchSource::Db || *w == FetchSource::All);

        if fetch_db {
            s.spawn(|_| {
                // This function already logs internally
                dbs = Some(advisories::DbSet::load(
                    cfg.advisories.db_path,
                    cfg.advisories
                        .db_urls
                        .into_iter()
                        .map(|dburl| dburl.take())
                        .collect(),
                    advisories::Fetch::Allow,
                ))
            });
        }
    });

    if let Some(index) = index {
        index.context("failed to fetch crates.io index")?;
    }

    if let Some(dbs) = dbs {
        dbs.context("failed to fetch database")?;
    }

    Ok(())
}
