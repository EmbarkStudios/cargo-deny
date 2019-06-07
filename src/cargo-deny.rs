#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use ansi_term::Color;
use cargo_deny::{self, ban, licenses};
use failure::{bail, format_err, Error};
use serde::Deserialize;
use slog::{info, warn};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Copy, Clone, Debug)]
enum MessageFormat {
    Human,
    Json,
}

impl std::str::FromStr for MessageFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(MessageFormat::Json),
            "human" => Ok(MessageFormat::Human),
            s => bail!("unknown message format {}", s),
        }
    }
}

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(flatten)]
    log_level: structopt_flags::LogLevelNoDef,
    #[structopt(long = "message-format", default_value = "human")]
    msg_format: MessageFormat,
    /// The directory used as the context for the deny, if not specified,
    /// the current working directory is used instead. Must contain a Cargo.toml file.
    #[structopt(long = "context", parse(from_os_str))]
    context: Option<PathBuf>,
    /// The path to the config file used to determine which crates are
    /// allowed or denied. Will default to <context>/deny.toml if not specified.
    #[structopt(short = "c", long = "config", parse(from_os_str))]
    config: Option<PathBuf>,
    #[structopt(short = "g", long = "graph", parse(from_os_str))]
    graph: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Config {
    licenses: Option<licenses::Config>,
    bans: Option<ban::Config>,
}

impl Config {
    fn sort(&mut self) {
        if let Some(lcfg) = self.licenses.as_mut() {
            lcfg.sort();
        }

        if let Some(bcfg) = self.bans.as_mut() {
            bcfg.sort();
        }
    }
}

fn real_main() -> Result<(), Error> {
    use slog::Drain;
    use structopt_flags::GetWithDefault;
    let args = Opts::from_args();

    let drain = match args.msg_format {
        MessageFormat::Human => {
            let decorator = slog_term::TermDecorator::new().stderr().build();

            slog_async::Async::new(slog_term::CompactFormat::new(decorator).build().fuse())
                .build()
                .fuse()
        }
        MessageFormat::Json => slog_async::Async::new(
            slog_json::Json::new(std::io::stderr())
                .add_default_keys()
                .set_newlines(true)
                .build()
                .fuse(),
        )
        .build()
        .fuse(),
    };

    let filter_level = match args.log_level.get_with_default(log::LevelFilter::Error) {
        log::LevelFilter::Debug => slog::FilterLevel::Debug,
        log::LevelFilter::Error => slog::FilterLevel::Error,
        log::LevelFilter::Info => slog::FilterLevel::Info,
        log::LevelFilter::Trace => slog::FilterLevel::Trace,
        log::LevelFilter::Warn => slog::FilterLevel::Warning,
        log::LevelFilter::Off => slog::FilterLevel::Off,
    };

    let drain = drain
        .filter(move |r: &'_ slog::Record<'_>| r.level().as_usize() <= filter_level.as_usize())
        .fuse();

    let root_logger = slog::Logger::root(drain, slog::o!());

    let context_dir = args
        .context
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| format_err!("unable to determine context directory"))?;

    if !context_dir.exists() {
        bail!("context {} was not found", context_dir.display());
    }

    if !context_dir.is_dir() {
        bail!("context {} is not a directory", context_dir.display());
    }

    let config = args
        .config
        .or_else(|| Some("deny.toml".to_owned().into()))
        .map(|p| {
            if p.is_absolute() {
                p
            } else {
                context_dir.join(p)
            }
        })
        .ok_or_else(|| format_err!("unable to determine config path"))?;

    let mut cfg = {
        let cfg_contents = std::fs::read_to_string(&config)
            .map_err(|e| format_err!("failed to read config from {}: {}", config.display(), e))?;

        let mut cfg: Config = toml::from_str(&cfg_contents).map_err(|e| {
            format_err!(
                "failed to deserialize config from {}: {}",
                config.display(),
                e
            )
        })?;

        cfg.sort();

        cfg
    };

    let (all_crates, store) = rayon::join(
        || {
            let mut timer = slog_perf::TimeReporter::new_with_level(
                "read-crates",
                root_logger.clone(),
                slog::Level::Debug,
            );

            timer.start_with("read", || {
                cargo_deny::get_all_crates(&context_dir).expect("failed to acquire crates")
            })
        },
        || {
            if cfg.licenses.is_some() {
                let mut timer = slog_perf::TimeReporter::new_with_level(
                    "load-license-store",
                    root_logger.clone(),
                    slog::Level::Debug,
                );

                Some(timer.start_with("load", || {
                    licenses::LicenseStore::from_cache().expect("failed to load license store")
                }))
            } else {
                None
            }
        },
    );

    info!(root_logger, "checking crates"; "count" => all_crates.as_ref().len());

    if let Some(ref mut licenses) = cfg.licenses {
        let ignored = licenses.get_ignore_licenses();

        {
            let mut timer = slog_perf::TimeReporter::new_with_level(
                "check-licenses",
                root_logger.clone(),
                slog::Level::Debug,
            );

            let gatherer =
                licenses::Gatherer::new(root_logger.new(slog::o!("stage" => "license_gather")))
                    .with_store(std::sync::Arc::new(
                        store.expect("we should have a license store"),
                    ))
                    .with_confidence_threshold(licenses.confidence_threshold);

            let summary = timer.start_with("gather", || gatherer.gather(&all_crates, ignored));

            timer.start_with("check", || {
                licenses::check_licenses(
                    root_logger.new(slog::o!("stage" => "license_check")),
                    summary,
                    licenses,
                )
            })?;
        }

    if let Some(ref bans) = cfg.bans {
        let mut timer = slog_perf::TimeReporter::new_with_level(
            "check-bans",
            root_logger.clone(),
            slog::Level::Debug,
        );

        let output_graph = args.graph.map(|pb| {
            let output_dir = pb.join("graph_output");
            let _ = std::fs::remove_dir_all(&output_dir);

            std::fs::create_dir_all(&output_dir).unwrap();

            move |dup_graph: ban::DupGraph| {
                std::fs::write(
                    output_dir.join(format!("{}.dot", dup_graph.duplicate)),
                    dup_graph.graph.as_bytes(),
                )?;

                Ok(())
            }
        });

        timer.start_with("check", || {
            ban::check_bans(
                root_logger.new(slog::o!("stage" => "ban_check")),
                &all_crates,
                bans,
                output_graph,
            )
        })?;

        info!(
            root_logger,
            "{}",
            Color::Green.paint("ban check succeeded!")
        );
    }

    Ok(())
}

fn main() {
    match real_main() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", Color::Red.paint(format!("{}", e)));
            std::process::exit(1);
        }
    }
}
