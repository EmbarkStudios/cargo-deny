#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use anyhow::{bail, Context, Error};
use std::path::PathBuf;
use structopt::StructOpt;

mod check;
mod common;
mod init;
mod list;

#[derive(StructOpt, Debug)]
enum Command {
    /// Outputs a listing of all licenses and the crates that use them
    #[structopt(name = "list")]
    List(list::Args),
    /// Checks your dependency graph based on the configuration you specify
    #[structopt(name = "check")]
    Check(check::Args),
    /// Initialize an empty deny.toml file in your current crate.
    #[structopt(name = "init")]
    Init(init::Args),
}

fn parse_level(s: &str) -> Result<log::LevelFilter, Error> {
    s.parse::<log::LevelFilter>()
        .with_context(|| format!("failed to parse level '{}'", s))
}

#[derive(StructOpt)]
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
    #[structopt(long, parse(from_os_str))]
    context: Option<PathBuf>,
    #[structopt(short, long)]
    target: Vec<String>,
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

    let log_level = args.log_level;

    setup_logger(log_level)?;

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

    match args.cmd {
        Command::Check(cargs) => check::cmd(log_level, cargs, args.target, context_dir),
        Command::List(largs) => list::cmd(largs, args.target, context_dir),
        Command::Init(iargs) => init::cmd(iargs, context_dir),
    }
}

fn main() {
    match real_main() {
        Ok(_) => {}
        Err(e) => {
            log::error!("{:#}", e);
            std::process::exit(1);
        }
    }
}
