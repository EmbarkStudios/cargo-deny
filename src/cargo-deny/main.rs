#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use ansi_term::Color;
use cargo_deny::licenses;
use failure::{bail, format_err, Error};
//use slog::{info, warn};
use std::path::PathBuf;
use structopt::StructOpt;

mod check;
mod common;
mod list;

use crate::common::MessageFormat;

#[derive(StructOpt, Debug)]
enum Command {
    #[structopt(name = "list")]
    List(list::Args),
    #[structopt(name = "check")]
    Check(check::Args),
}

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(flatten)]
    log_level: structopt_flags::LogLevelNoDef,
    /// The format for log messages
    #[structopt(long = "message-format", default_value = "human")]
    msg_format: MessageFormat,
    /// The directory used as the context for the deny, if not specified,
    /// the current working directory is used instead. Must contain a Cargo.toml file.
    #[structopt(long = "context", parse(from_os_str))]
    context: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
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

    let filter_level = match args.log_level.get_with_default(log::LevelFilter::Info) {
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
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| format_err!("unable to determine context directory"))?;

    if !context_dir.exists() {
        bail!("context {} was not found", context_dir.display());
    }

    if !context_dir.is_dir() {
        bail!("context {} is not a directory", context_dir.display());
    }

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
            if let Command::Check(ref check) = args.cmd {
                if !check.needs_license_store() {
                    return None;
                }
            }

            let mut timer = slog_perf::TimeReporter::new_with_level(
                "load-license-store",
                root_logger.clone(),
                slog::Level::Debug,
            );

            Some(timer.start_with("load", || {
                licenses::LicenseStore::from_cache().expect("failed to load license store")
            }))
        },
    );

    match args.cmd {
        Command::List(list) => list::cmd(root_logger, list, all_crates, store),
        Command::Check(check) => check::cmd(root_logger, context_dir, check, all_crates, store),
    }
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
