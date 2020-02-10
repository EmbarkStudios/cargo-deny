use anyhow::{Context, Error};
use cargo_deny::{advisories, diag::Diagnostic};
use clap::arg_enum;
use std::path::PathBuf;
use structopt::StructOpt;

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
    fn load(cfg_path: Option<PathBuf>, files: &mut codespan::Files<String>) -> Result<Self, Error> {
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

        let id = files.add(cfg_path.to_string_lossy(), cfg_contents);

        let print = |diags: Vec<Diagnostic>| {
            use codespan_reporting::term;

            if diags.is_empty() {
                return;
            }

            let writer =
                term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
            let config = term::Config::default();
            let mut writer = writer.lock();
            for diag in &diags {
                term::emit(&mut writer, &config, &files, &diag).unwrap();
            }
        };

        let advisories = match cfg.advisories.unwrap_or_default().validate(id) {
            Ok(advisories) => advisories,
            Err(diags) => {
                print(diags);

                anyhow::bail!(
                    "failed to validate configuration file {}",
                    cfg_path.display()
                );
            }
        };

        Ok(Self { advisories })
    }
}

pub fn cmd(args: Args, ctx: crate::common::KrateContext) -> Result<(), Error> {
    let cfg_path = ctx.get_config_path(args.config.clone());

    let mut files = codespan::Files::new();
    let cfg = ValidConfig::load(cfg_path, &mut files)?;

    let mut index = None;
    let mut db = None;

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
                db = Some(advisories::load_db(
                    cfg.advisories.db_url.as_ref().map(AsRef::as_ref),
                    cfg.advisories.db_path.as_ref().cloned(),
                    advisories::Fetch::Allow,
                ))
            });
        }
    });

    if let Some(index) = index {
        index.context("failed to fetch crates.io index")?;
    }

    if let Some(db) = db {
        db.context("failed to fetch database")?;
    }

    Ok(())
}
