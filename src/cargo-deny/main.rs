#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use anyhow::{bail, Context, Error};
use cargo_deny::licenses;
use std::path::PathBuf;
use structopt::StructOpt;

mod check;
mod common;
mod list;

#[derive(StructOpt, Debug)]
enum Command {
    /// Outputs a listing of all licenses and the crates that use them
    #[structopt(name = "list")]
    List(list::Args),
    /// Checks your dependency graph based on the configuration you specify
    #[structopt(name = "check")]
    Check(check::Args),
}

fn parse_level(s: &str) -> Result<log::LevelFilter, Error> {
    s.parse::<log::LevelFilter>()
        .with_context(|| format!("failed to parse level '{}'", s))
}

#[derive(Debug, StructOpt)]
struct Opts {
    /// The log level for messages, only log messages at or above
    /// the level will be emitted.
    #[structopt(
        short = "L",
        long = "log-level",
        default_value = "warn",
        parse(try_from_str = parse_level),
        long_help = "The log level for messages, only log messages at or above the level will be emitted.

Possible values:
* off
* error
* warn
* info
* debug
* trace"
    )]
    log_level: log::LevelFilter,
    /// The directory used as the context for the deny, if not specified,
    /// the current working directory is used instead. Must contain a Cargo.toml file.
    #[structopt(long = "context", parse(from_os_str))]
    context: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
}

fn setup_logger(level: log::LevelFilter) -> Result<(), fern::InitError> {
    use ansi_term::Color::*;
    use log::Level::*;

    fern::Dispatch::new()
        .level(level)
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{date} [{level}] {message}\x1B[0m",
                date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
                level = match record.level() {
                    Error => Red.paint("ERROR"),
                    Warn => Yellow.paint("WARN"),
                    Info => Green.paint("INFO"),
                    Debug => Blue.paint("DEBUG"),
                    Trace => Purple.paint("TRACE"),
                },
                message = message,
            ));
        })
        .chain(std::io::stderr())
        .apply()?;
    Ok(())
}

fn real_main() -> Result<(), Error> {
    let args =
        Opts::from_iter({
            std::env::args().enumerate().filter_map(|(i, a)| {
                if i == 1 && a == "deny" {
                    None
                } else {
                    Some(a)
                }
            })
        });

    setup_logger(args.log_level)?;

    let context_dir = args
        .context
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .context("unable to determine context directory")?;

    if !context_dir.exists() {
        bail!("context {} was not found", context_dir.display());
    }

    if !context_dir.is_dir() {
        bail!("context {} is not a directory", context_dir.display());
    }

    let (all_crates, store) = rayon::join(
        || {
            log::info!("gathering crates for {}", context_dir.display());
            cargo_deny::get_all_crates(&context_dir)
        },
        || {
            if let Command::Check(ref check) = args.cmd {
                if !check.needs_license_store() {
                    return None;
                }
            }

            log::info!("loading license store");
            Some(licenses::LicenseStore::from_cache())
        },
    );

    let all_crates = all_crates?;

    log::info!("gathered {} crates", all_crates.krates.len());

    let license_store = match store {
        Some(res) => Some(res?),
        None => None,
    };

    match args.cmd {
        Command::List(list) => list::cmd(list, all_crates, license_store),
        Command::Check(check) => check::cmd(
            args.log_level,
            context_dir,
            check,
            all_crates,
            license_store,
        ),
    }
}

fn main() {
    match real_main() {
        Ok(_) => {}
        Err(e) => {
            log::error!("{}", e);
            std::process::exit(1);
        }
    }
}
