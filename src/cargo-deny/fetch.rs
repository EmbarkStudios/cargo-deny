use crate::common::ValidConfig;
use anyhow::{Context as _, Error};
use cargo_deny::{advisories, diag::Files};

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum FetchSource {
    Db,
    Index,
    StdReplacement,
    All,
}

crate::enum_args!(FetchSource : FetchSourceParser => {
    "db" => Db,
    "index" => Index,
    "std-replacement" => StdReplacement,
    "all" => All,
});

pub struct Args {
    sources: Vec<FetchSource>,
}

impl Args {
    pub fn cmd() -> clap::Command {
        clap::Command::new("fetch")
            .about("Fetches remote data")
            .args([clap::Arg::new("SOURCES")
                .help("The sources to fetch.")
                .value_parser(FetchSourceParser)
                .action(clap::ArgAction::Append)])
    }

    pub fn parse(args: &mut clap::ArgMatches) -> Self {
        Self {
            sources: args
                .remove_many("SOURCES")
                .map_or(Default::default(), |v| v.collect()),
        }
    }
}

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    let cfg_path = krate_ctx.get_config_path()?;

    let mut files = Files::new();
    let ValidConfig {
        advisories, graph, ..
    } = ValidConfig::load(
        cfg_path,
        krate_ctx.get_local_exceptions_path(),
        &mut files,
        log_ctx,
    )?;

    let mut index = None;
    let mut dbs = None;
    let mut replacements = None;

    rayon::scope(|s| {
        let fetch_index = args.sources.is_empty()
            || args
                .sources
                .iter()
                .any(|w| *w == FetchSource::Index || *w == FetchSource::All);

        if fetch_index {
            s.spawn(|_| {
                let start = std::time::Instant::now();
                log::info!("fetching crates");
                index = Some(krate_ctx.fetch_krates(&graph.targets));
                log::info!("fetched crates in {:?}", start.elapsed());
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

        let fetch_replacement = args.sources.is_empty()
            || args
                .sources
                .iter()
                .any(|w| *w == FetchSource::StdReplacement || *w == FetchSource::All);

        if fetch_replacement {
            s.spawn(|_| {
                let start = std::time::Instant::now();
                log::info!("fetching std-replacement-data");
                replacements = Some(cargo_deny::bans::replacements::ReplacementCtx::sync());
                log::info!("fetched std-replacement-data in {:?}", start.elapsed());
            });
        }
    });

    if let Some(index) = index {
        index.context("failed to fetch crates.io index")?;
    }

    if let Some(dbs) = dbs {
        dbs.context("failed to fetch database")?;
    }

    if let Some(replacements) = replacements {
        replacements.context("failed to fetch std-replacement-data")?;
    }

    Ok(())
}
