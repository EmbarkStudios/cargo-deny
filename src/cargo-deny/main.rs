#![allow(clippy::exit)]

use anyhow::{Context as _, Error};
use cargo_deny::PathBuf;
use clap::{Parser, Subcommand, ValueEnum};

mod check;
mod common;
mod fetch;
mod init;
mod list;
mod stats;

#[derive(Subcommand, Debug)]
enum Command {
    /// Checks a project's crate graph
    #[command(name = "check")]
    Check(check::Args),
    /// Fetches remote data
    #[command(name = "fetch")]
    Fetch(fetch::Args),
    /// Creates a cargo-deny config from a template
    #[command(name = "init")]
    Init(init::Args),
    /// Outputs a listing of all licenses and the crates that use them
    #[command(name = "list")]
    List(list::Args),
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Sarif,
}

#[derive(ValueEnum, Copy, Clone, Debug)]
pub enum Color {
    Auto,
    Always,
    Never,
}

fn parse_level(s: &str) -> Result<log::LevelFilter, Error> {
    s.parse::<log::LevelFilter>()
        .with_context(|| format!("failed to parse level '{s}'"))
}

#[derive(Parser)]
#[command(rename_all = "kebab-case")]
pub(crate) struct GraphContext {
    /// The path of a Cargo.toml to use as the context for the operation.
    ///
    /// By default, the Cargo.toml in the current working directory is used.
    #[arg(long)]
    pub(crate) manifest_path: Option<PathBuf>,
    /// If passed, all workspace packages are used as roots for the crate graph.
    ///
    /// Automatically assumed if the manifest path points to a virtual manifest.
    ///
    /// Normally, if you specify a manifest path that is a member of a workspace, that crate will be the sole root of the crate graph, meaning only other workspace members that are dependencies of that workspace crate will be included in the graph. This overrides that behavior to include all workspace members.
    #[arg(long)]
    pub(crate) workspace: bool,
    /// One or more crates to exclude from the crate graph that is used.
    ///
    /// NOTE: Unlike cargo, this does not have to be used with the `--workspace` flag.
    #[arg(long)]
    pub(crate) exclude: Vec<String>,
    /// One or more platforms to filter crates by
    ///
    /// If a dependency is target specific, it will be ignored if it does not match 1 or more of the specified targets. This option overrides the top-level `targets = []` configuration value.
    #[arg(short, long)]
    pub(crate) target: Vec<String>,
    /// Activate all available features
    #[arg(long)]
    pub(crate) all_features: bool,
    /// Do not activate the `default` feature
    #[arg(long)]
    pub(crate) no_default_features: bool,
    /// Space or comma separated list of features to activate
    #[arg(long, value_delimiter = ',')]
    pub(crate) features: Vec<String>,
    /// Equivalent to specifying both `--locked` and `--offline`
    #[arg(long)]
    pub(crate) frozen: bool,
    /// Run without accessing the network.
    ///
    /// If used with the `check` subcommand, this disables advisory database
    /// fetching
    #[arg(long)]
    pub(crate) offline: bool,
    /// Assert that `Cargo.lock` will remain unchanged
    #[arg(long)]
    pub(crate) locked: bool,
    /// If set, the crates.io git index is initialized for use in fetching crate information, otherwise it is enabled
    /// only if using a cargo < 1.70.0 without the sparse protocol enabled
    #[arg(long)]
    pub(crate) allow_git_index: bool,
    /// If set, excludes all dev-dependencies, not just ones for non-workspace crates
    #[arg(long)]
    pub(crate) exclude_dev: bool,
    /// If set, exclude unpublished workspace members from graph roots.
    ///
    /// Workspace members are considered unpublished if they they are explicitly marked with `publish = false`.
    /// Note that the excluded workspace members are still used for the initial dependency resolution by cargo,
    /// which might affect the exact version of used dependencies.
    #[arg(long)]
    pub(crate) exclude_unpublished: bool,
}

/// Lints your project's crate graph
#[derive(Parser)]
#[command(author, version, about, long_about = None, rename_all = "kebab-case", max_term_width = 80)]
struct Opts {
    /// The log level for messages
    #[arg(
        short = 'L',
        long = "log-level",
        default_value = "warn",
        value_parser = parse_level,
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
    #[arg(short, long, default_value = "human", value_enum)]
    format: Format,
    #[arg(
        short,
        long,
        default_value = "auto",
        value_enum,
        env = "CARGO_TERM_COLOR"
    )]
    color: Color,
    #[clap(flatten)]
    ctx: GraphContext,
    #[clap(subcommand)]
    cmd: Command,
}

fn setup_logger(
    level: log::LevelFilter,
    format: Format,
    color: bool,
) -> Result<(), fern::InitError> {
    use log::Level::{Debug, Error, Info, Trace, Warn};
    use nu_ansi_term::Color::{Blue, Green, Purple, Red, Yellow};

    let now = time::OffsetDateTime::now_utc();

    match format {
        Format::Human => {
            const HUMAN: &[time::format_description::FormatItem<'static>] =
                time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

            if color {
                fern::Dispatch::new()
                    .level(level)
                    .format(move |out, message, record| {
                        out.finish(format_args!(
                            "{date} [{level}] {message}\x1B[0m",
                            date = now.format(&HUMAN).unwrap(),
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
                            date = now.format(&HUMAN).unwrap(),
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
                        "{}",
                        serde_json::json! {{
                            "type": "log",
                            "fields": {
                                "timestamp": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
                                "level": match record.level() {
                                    Error => "ERROR",
                                    Warn => "WARN",
                                    Info => "INFO",
                                    Debug => "DEBUG",
                                    Trace => "TRACE",
                                },
                                "message": message,
                            }
                        }}
                    ));
                })
                .chain(std::io::stderr())
                .apply()?;
        }
        Format::Sarif => {
            // For SARIF output, suppress regular logs to stderr to avoid mixing with SARIF JSON
            // Only output actual errors that would prevent SARIF generation
            fern::Dispatch::new()
                .level(log::LevelFilter::Error)
                .format(move |out, message, _record| {
                    out.finish(format_args!("{message}"));
                })
                .chain(std::io::stderr())
                .apply()?;
        }
    }

    Ok(())
}

fn real_main() -> Result<(), Error> {
    let args = Opts::parse_from({
        std::env::args()
            .enumerate()
            .filter_map(|(i, a)| if i == 1 && a == "deny" { None } else { Some(a) })
    });

    let log_level = args.log_level;

    let color = crate::common::should_colorize(args.color, std::io::stderr());

    setup_logger(log_level, args.format, color)?;

    let manifest_path = if let Some(mpath) = args.ctx.manifest_path {
        mpath
    } else {
        // For now, use the context path provided by the user, but
        // we've deprecated it and it will go away at some point
        let cwd =
            std::env::current_dir().context("unable to determine current working directory")?;

        anyhow::ensure!(
            cwd.exists(),
            "current working directory {} was not found",
            cwd.display()
        );

        anyhow::ensure!(
            cwd.is_dir(),
            "current working directory {} is not a directory",
            cwd.display()
        );

        let man_path = cwd.join("Cargo.toml");

        anyhow::ensure!(
            man_path.exists(),
            "the directory {} doesn't contain a Cargo.toml file",
            cwd.display()
        );

        man_path.try_into().context("non-utf8 path")?
    };

    anyhow::ensure!(
        manifest_path.file_name() == Some("Cargo.toml") && manifest_path.is_file(),
        "--manifest-path must point to a Cargo.toml file"
    );

    anyhow::ensure!(
        manifest_path.exists(),
        "unable to find cargo manifest {manifest_path}"
    );

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
        exclude_dev: args.ctx.exclude_dev,
        exclude_unpublished: args.ctx.exclude_unpublished,
    };

    let log_ctx = crate::common::LogContext {
        color: args.color,
        format: args.format,
        log_level: args.log_level,
    };

    // Allow gix to hook the signal handler so that it can properly release lockfiles
    // if the user aborts or we crash
    #[allow(unsafe_code)]
    // SAFETY: The code in the callback must be async signal safe, but we don't
    // have any code in there because the callback is not actually invoked since
    // we send a grace_count of 0, the callback is only invoked if grace_count > 0
    let _dereg = unsafe {
        gix::interrupt::init_handler(0, || {
            //const BUF: &[u8] = b"gix interrupt handler triggered, terminating process...\n";
            //libc::write(libc::STDERR_FILENO, BUF.as_ptr().cast(), BUF.len());
        })
        .context("failed to initialize gix's interrupt handler")?
    };

    match args.cmd {
        Command::Check(mut cargs) => {
            let show_stats = cargs.show_stats;

            if args.ctx.offline {
                log::info!(
                    "network access disabled via --offline flag, disabling advisory database fetching"
                );
                cargs.disable_fetch = true;
            }

            let stats = check::cmd(log_ctx, cargs, krate_ctx)?;

            if let Some(exit_code) =
                stats::print_stats(stats, show_stats, log_level, args.format, args.color)
            {
                std::process::exit(exit_code);
            }

            Ok(())
        }
        Command::Fetch(fargs) => fetch::cmd(log_ctx, fargs, krate_ctx),
        Command::Init(iargs) => init::cmd(iargs, krate_ctx),
        Command::List(largs) => list::cmd(log_ctx, largs, krate_ctx),
    }
}

fn main() {
    match real_main() {
        Ok(_) => {}
        Err(e) => {
            log::error!("{e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod test {
    use clap::ColorChoice;
    use clap::Command;

    fn snapshot_test_cli_command(app: Command, cmd_name: String) {
        let mut app = app
            // we do not want ASCII colors in our snapshot test output
            .color(ColorChoice::Never)
            // override versions to not have to update test when changing versions
            .version("0.0.0")
            .long_version("0.0.0");

        // don't show current env vars as that will make snapshot test output diff depending on environment run in
        let arg_names = app
            .get_arguments()
            .filter_map(|a| {
                let id = a.get_id();

                if id != "version" && id != "help" {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for arg_name in arg_names {
            app = app.mut_arg(arg_name, |arg| arg.hide_env_values(true));
        }

        // get the long help text for the command
        let mut buffer = Vec::new();
        app.write_long_help(&mut buffer).unwrap();
        let content = std::str::from_utf8(&buffer).unwrap();

        let snapshot = insta::_macro_support::SnapshotValue::FileText {
            name: Some(cmd_name.as_str().into()),
            content,
        };

        // use internal `insta` function instead of the macro so we can pass in the
        // right module information from the crate and to gather up the errors instead of panicking directly on failures
        #[allow(clippy::disallowed_types)]
        insta::_macro_support::assert_snapshot(
            snapshot,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            "cli-cmd",
            module_path!(),
            file!(),
            line!(),
            "help_text",
        )
        .unwrap();

        // recursively test all subcommands
        for app in app.get_subcommands() {
            if app.get_name() == "help" {
                continue;
            }

            snapshot_test_cli_command(app.clone(), format!("{cmd_name}-{}", app.get_name()));
        }
    }

    #[test]
    fn cli_snapshot() {
        use clap::CommandFactory;

        insta::with_settings!({
            snapshot_path => "../../tests/snapshots",
        }, {
            snapshot_test_cli_command(
                super::Opts::command().name("cargo_deny"),
                "cargo_deny".to_owned(),
            );
        });
    }
}
