#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use anyhow::{bail, Context, Error};
use std::path::PathBuf;
use structopt::StructOpt;

mod check;
mod common;
mod fetch;
mod init;
mod list;

#[derive(StructOpt, Debug)]
enum Command {
    /// Checks a project's crate graph
    #[structopt(name = "check")]
    Check(check::Args),
    /// Fetches remote data
    #[structopt(name = "fetch")]
    Fetch(fetch::Args),
    /// Creates a cargo-deny config from a template
    #[structopt(name = "init")]
    Init(init::Args),
    /// Outputs a listing of all licenses and the crates that use them
    #[structopt(name = "list")]
    List(list::Args),
}

fn parse_level(s: &str) -> Result<log::LevelFilter, Error> {
    s.parse::<log::LevelFilter>()
        .with_context(|| format!("failed to parse level '{}'", s))
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case", max_term_width = 80)]
pub(crate) struct GraphContext {
    /// The directory used as the root context (deprecated)
    ///
    /// If not specified, the current working directory is used instead. The directory must contain a Cargo.toml file
    #[structopt(long, parse(from_os_str))]
    pub(crate) context: Option<PathBuf>,
    /// The path of a Cargo.toml to use as the context for the operation.
    ///
    /// By default, the Cargo.toml in the current working directory is used.
    #[structopt(long, parse(from_os_str))]
    pub(crate) manifest_path: Option<PathBuf>,
    /// If passed, all workspace packages are used as roots for the crate graph.
    ///
    /// Automatically assumed if the manifest path points to a virtual manifest.
    ///
    /// Normally, if you specify a manifest path that is a member of a workspace, that crate will be the sole root of the crate graph, meaning only other workspace members that are dependencies of that workspace crate will be included in the graph. This overrides that behavior to include all workspace members.
    #[structopt(long)]
    pub(crate) workspace: bool,
    /// One or more crates to exclude from the crate graph that is used.
    ///
    /// NOTE: Unlike cargo, this does not have to be used with the `--workspace` flag.
    #[structopt(long)]
    pub(crate) exclude: Vec<String>,
    /// One or more platforms to filter crates by
    ///
    /// If a dependency is target specific, it will be ignored if it does not match 1 or more of the specified targets. This option overrides the top-level `targets = []` configuration value.
    #[structopt(short, long)]
    pub(crate) target: Vec<String>,
}

/// Lints your project's crate graph
#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case", max_term_width = 80)]
struct Opts {
    /// The log level for messages
    #[structopt(
        short = "L",
        long = "log-level",
        default_value = "warn",
        parse(try_from_str = parse_level),
        long_help = "The log level for messages

Only log messages at or above the level will be emitted.

Possible values:
* off
* error
* warn
* info
* debug
* trace
")]
    log_level: log::LevelFilter,
    #[structopt(flatten)]
    ctx: GraphContext,
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

    let manifest_path = match args.ctx.manifest_path {
        Some(mpath) => mpath,
        None => {
            // For now, use the context path provided by the user, but
            // we've deprected it and it will go away at some point
            let context_dir = args
                .ctx
                .context
                .or_else(|| std::env::current_dir().ok())
                .context("unable to determine current working directory")?;

            if !context_dir.exists() {
                bail!(
                    "current working directory {} was not found",
                    context_dir.display()
                );
            }

            if !context_dir.is_dir() {
                bail!(
                    "current working directory {} is not a directory",
                    context_dir.display()
                );
            }

            let man_path = context_dir.join("Cargo.toml");

            if !man_path.exists() {
                bail!(
                    "the directory {} doesn't contain a Cargo.toml file",
                    context_dir.display()
                );
            }

            man_path
        }
    };

    if manifest_path.file_name() != Some(std::ffi::OsStr::new("Cargo.toml"))
        || !manifest_path.is_file()
    {
        bail!("--manifest-path must point to a Cargo.toml file");
    }

    if !manifest_path.exists() {
        bail!("unable to find cargo manifest {}", manifest_path.display());
    }

    let krate_ctx = common::KrateContext {
        manifest_path,
        workspace: args.ctx.workspace,
        exclude: args.ctx.exclude,
        targets: args.ctx.target,
    };

    match args.cmd {
        Command::Check(cargs) => {
            let show_stats = cargs.show_stats;
            let stats = check::cmd(log_level, cargs, krate_ctx)?;

            let errors = stats.total_errors();

            let mut summary = String::new();

            // If we're using the default or higher log level, just emit
            // a single line, anything else gets a full table
            if show_stats || log_level > log::LevelFilter::Warn {
                get_full_stats(&mut summary, &stats);
            } else if log_level != log::LevelFilter::Off && log_level <= log::LevelFilter::Warn {
                let mut print_stats = |check: &str, stats: Option<&check::Stats>| {
                    use std::fmt::Write;

                    if let Some(stats) = stats {
                        write!(
                            &mut summary,
                            "{} {}, ",
                            check,
                            if stats.errors > 0 {
                                ansi_term::Color::Red.paint("FAILED")
                            } else {
                                ansi_term::Color::Green.paint("ok")
                            }
                        )
                        .unwrap();
                    }
                };

                print_stats("advisories", stats.advisories.as_ref());
                print_stats("bans", stats.bans.as_ref());
                print_stats("licenses", stats.licenses.as_ref());
                print_stats("sources", stats.sources.as_ref());

                // Remove trailing ,
                summary.pop();
                summary.pop();
                summary.push('\n');
            }

            if !summary.is_empty() {
                print!("{}", summary);
            }

            if errors > 0 {
                std::process::exit(1);
            } else {
                Ok(())
            }
        }
        Command::Fetch(fargs) => fetch::cmd(fargs, krate_ctx),
        Command::Init(iargs) => init::cmd(iargs, krate_ctx),
        Command::List(largs) => list::cmd(largs, krate_ctx),
    }
}

fn get_full_stats(summary: &mut String, stats: &check::AllStats) {
    let column = {
        let mut max = 0;
        let mut count = |check: &str, s: Option<&check::Stats>| {
            max = std::cmp::max(
                max,
                s.map_or(0, |s| {
                    let status = if s.errors > 0 {
                        "FAILED".len()
                    } else {
                        "ok".len()
                    };

                    status + check.len()
                }),
            );
        };

        count("advisories", stats.advisories.as_ref());
        count("bans", stats.bans.as_ref());
        count("licenses", stats.licenses.as_ref());
        count("sources", stats.sources.as_ref());

        max + 2 /* spaces */ + 9 /* color escapes */
    };

    let mut print_stats = |check: &str, stats: Option<&check::Stats>| {
        use std::fmt::Write;

        if let Some(stats) = stats {
            writeln!(
                summary,
                "{:>column$}: {} errors, {} warnings, {} notes",
                format!(
                    "{} {}",
                    check,
                    if stats.errors > 0 {
                        ansi_term::Color::Red.paint("FAILED")
                    } else {
                        ansi_term::Color::Green.paint("ok")
                    }
                ),
                ansi_term::Color::Red.paint(format!("{}", stats.errors)),
                ansi_term::Color::Yellow.paint(format!("{}", stats.warnings)),
                ansi_term::Color::Blue.paint(format!("{}", stats.notes + stats.helps)),
                column = column,
            )
            .unwrap();
        }
    };

    print_stats("advisories", stats.advisories.as_ref());
    print_stats("bans", stats.bans.as_ref());
    print_stats("licenses", stats.licenses.as_ref());
    print_stats("sources", stats.sources.as_ref());
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
