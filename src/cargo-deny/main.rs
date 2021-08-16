// BEGIN - Embark standard lints v0.4
// do not change or add/remove here, but one can add exceptions after this section
// for more info see: <https://github.com/EmbarkStudios/rust-ecosystem/issues/59>
#![deny(unsafe_code)]
#![warn(
    clippy::all,
    clippy::await_holding_lock,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::expl_impl_clone_on_copy,
    clippy::explicit_deref_methods,
    clippy::explicit_into_iter_loop,
    clippy::fallible_impl_from,
    clippy::filter_map_next,
    clippy::float_cmp_const,
    clippy::fn_params_excessive_bools,
    clippy::if_let_mutex,
    clippy::implicit_clone,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::invalid_upcast_comparisons,
    clippy::large_types_passed_by_value,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::manual_ok_or,
    clippy::map_err_ignore,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::mut_mut,
    clippy::mutex_integer,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::option_option,
    clippy::path_buf_push_overwrite,
    clippy::ptr_as_ptr,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_functions_in_if_condition,
    clippy::semicolon_if_nothing_returned,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_lit_as_bytes,
    clippy::string_to_string,
    clippy::todo,
    clippy::trait_duplication_in_bounds,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::useless_transmute,
    clippy::verbose_file_reads,
    clippy::zero_sized_map_values,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]
// END - Embark standard lints v0.4
#![allow(clippy::exit)]

use anyhow::{bail, Context, Error};
use std::path::PathBuf;
use structopt::StructOpt;

mod check;
mod common;
mod fetch;
mod fix;
mod init;
mod list;
mod stats;

#[derive(StructOpt, Debug)]
enum Command {
    /// Checks a project's crate graph
    #[structopt(name = "check")]
    Check(check::Args),
    /// Fetches remote data
    #[structopt(name = "fetch")]
    Fetch(fetch::Args),
    /// Attempts to fix security advisories by updating Cargo.toml manifests
    #[structopt(name = "fix")]
    Fix(fix::Args),
    /// Creates a cargo-deny config from a template
    #[structopt(name = "init")]
    Init(init::Args),
    /// Outputs a listing of all licenses and the crates that use them
    #[structopt(name = "list")]
    List(list::Args),
}

#[derive(StructOpt, Copy, Clone, Debug, PartialEq)]
pub enum Format {
    Human,
    Json,
}

impl Format {
    fn variants() -> &'static [&'static str] {
        &["human", "json"]
    }
}

impl std::str::FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_ascii_lowercase();

        Ok(match lower.as_str() {
            "human" => Self::Human,
            "json" => Self::Json,
            _ => bail!("unknown output format '{}' specified", s),
        })
    }
}

#[derive(StructOpt, Copy, Clone, Debug)]
pub enum Color {
    Auto,
    Always,
    Never,
}

impl Color {
    fn variants() -> &'static [&'static str] {
        &["auto", "always", "never"]
    }
}

impl std::str::FromStr for Color {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_ascii_lowercase();

        Ok(match lower.as_str() {
            "auto" => Self::Auto,
            "always" => Self::Always,
            "never" => Self::Never,
            _ => bail!("unknown color option '{}' specified", s),
        })
    }
}

fn parse_level(s: &str) -> Result<log::LevelFilter, Error> {
    s.parse::<log::LevelFilter>()
        .with_context(|| format!("failed to parse level '{}'", s))
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case", max_term_width = 80)]
pub(crate) struct GraphContext {
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
    /// Activate all available features
    #[structopt(long)]
    pub(crate) all_features: bool,
    /// Do not activate the `default` feature
    #[structopt(long)]
    pub(crate) no_default_features: bool,
    /// Space or comma separated list of features to activate
    #[structopt(long, use_delimiter = true)]
    pub(crate) features: Vec<String>,
    /// Require Cargo.lock and cache are up to date
    #[structopt(long)]
    pub(crate) frozen: bool,
    /// Require Cargo.lock is up to date
    #[structopt(long)]
    pub(crate) locked: bool,
    /// Run without accessing the network. If used with the `check` subcommand, this also disables advisory database fetching.
    #[structopt(long)]
    pub(crate) offline: bool,
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
    /// Specify the format of cargo-deny's output
    #[structopt(short, long, default_value = "human", possible_values = Format::variants())]
    format: Format,
    #[structopt(short, long, default_value = "auto", possible_values = Color::variants())]
    color: Color,
    #[structopt(flatten)]
    ctx: GraphContext,
    #[structopt(subcommand)]
    cmd: Command,
}

fn setup_logger(
    level: log::LevelFilter,
    format: Format,
    color: bool,
) -> Result<(), fern::InitError> {
    use ansi_term::Color::{Blue, Green, Purple, Red, Yellow};
    use log::Level::{Debug, Error, Info, Trace, Warn};

    match format {
        Format::Human => {
            if color {
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
            } else {
                fern::Dispatch::new()
                    .level(level)
                    .format(move |out, message, record| {
                        out.finish(format_args!(
                            "{date} [{level}] {message}",
                            date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
                            level = match record.level() {
                                Error => "ERROR",
                                Warn => "WARN",
                                Info => "INFO",
                                Debug => "DEBUG",
                                Trace => "TRACE",
                            },
                            message = message,
                        ));
                    })
                    .chain(std::io::stderr())
                    .apply()?;
            }
        }
        Format::Json => {
            fern::Dispatch::new()
                .level(level)
                .format(move |out, message, record| {
                    out.finish(format_args!(
                        r#"{{"type":"log","fields":{{"timestamp":"{date}","level":"{level}","message":"{message}"}}}}"#,
                        date = chrono::Utc::now().to_rfc3339(),
                        level = match record.level() {
                            Error => "ERROR",
                            Warn => "WARN",
                            Info => "INFO",
                            Debug => "DEBUG",
                            Trace => "TRACE",
                        },
                        message = message,
                    ));
                })
                .chain(std::io::stderr())
                .apply()?;
        }
    }

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

    let color = match args.color {
        Color::Auto => atty::is(atty::Stream::Stderr),
        Color::Always => true,
        Color::Never => false,
    };

    setup_logger(log_level, args.format, color)?;

    let manifest_path = match args.ctx.manifest_path {
        Some(mpath) => mpath,
        None => {
            // For now, use the context path provided by the user, but
            // we've deprected it and it will go away at some point
            let cwd =
                std::env::current_dir().context("unable to determine current working directory")?;

            if !cwd.exists() {
                bail!("current working directory {} was not found", cwd.display());
            }

            if !cwd.is_dir() {
                bail!(
                    "current working directory {} is not a directory",
                    cwd.display()
                );
            }

            let man_path = cwd.join("Cargo.toml");

            if !man_path.exists() {
                bail!(
                    "the directory {} doesn't contain a Cargo.toml file",
                    cwd.display()
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
        no_default_features: args.ctx.no_default_features,
        all_features: args.ctx.all_features,
        features: args.ctx.features,
        frozen: args.ctx.frozen,
        locked: args.ctx.locked,
        offline: args.ctx.offline,
    };

    let log_ctx = crate::common::LogContext {
        color: args.color,
        format: args.format,
        log_level: args.log_level,
    };

    match args.cmd {
        Command::Check(mut cargs) => {
            let show_stats = cargs.show_stats;

            if args.ctx.offline {
                log::info!("network access disabled via --offline flag, disabling advisory database fetching");
                cargs.disable_fetch = true;
            }

            let stats = check::cmd(log_ctx, cargs, krate_ctx)?;

            let errors = stats.total_errors();

            stats::print_stats(stats, show_stats, log_level, args.format, args.color);

            if errors > 0 {
                std::process::exit(1);
            } else {
                Ok(())
            }
        }
        Command::Fetch(fargs) => fetch::cmd(log_ctx, fargs, krate_ctx),
        Command::Fix(fargs) => fix::cmd(log_ctx, fargs, krate_ctx),
        Command::Init(iargs) => init::cmd(iargs, krate_ctx),
        Command::List(largs) => list::cmd(log_ctx, largs, krate_ctx),
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
