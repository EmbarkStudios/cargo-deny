use crate::common::ValidConfig;
use anyhow::{Context as _, Error};
use cargo_deny::{PathBuf, advisories, diag::Files};

#[derive(clap::ValueEnum, Debug, PartialEq, Eq, Copy, Clone)]
pub enum FetchSource {
    Db,
    Index,
    All,
}

#[derive(clap::Parser, Debug, Clone)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to <cwd>/deny.toml if not specified
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// The sources to fetch
    #[arg(value_enum)]
    sources: Vec<FetchSource>,
}

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    let cfg_path = krate_ctx.get_config_path(args.config.clone());

    let mut files = Files::new();
    let ValidConfig { advisories, .. } = ValidConfig::load(
        cfg_path,
        krate_ctx.get_local_exceptions_path(),
        &mut files,
        log_ctx,
    )?;

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
                log::info!("fetching crates");
                index = Some(krate_ctx.fetch_krates());
                log::info!("fetched crates");
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
                    advisories.db_path,
                    advisories
                        .db_urls
                        .into_iter()
                        .map(|dburl| dburl.take())
                        .collect(),
                    if advisories.git_fetch_with_cli {
                        advisories::Fetch::AllowWithGitCli
                    } else {
                        advisories::Fetch::Allow
                    },
                ));
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
