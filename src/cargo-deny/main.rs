#![allow(clippy::exit)]

use anyhow::{Context as _, Error};
use cargo_deny::PathBuf;
use clap::{Arg, ArgMatches, Command};

mod check;
mod common;
mod fetch;
mod init;
mod list;
mod stats;

use crate::common::PathParser;

enum Subcommand {
    Check(check::Args),
    Fetch(fetch::Args),
    Init(init::Args),
    List(list::Args),
}

impl Subcommand {
    fn fill(cmd: Command) -> Command {
        cmd.subcommand(check::Args::cmd())
            .subcommand(fetch::Args::cmd())
            .subcommand(init::Args::cmd())
            .subcommand(list::Args::cmd())
            .subcommand_required(true)
    }
}

crate::enum_args!(log::LevelFilter : LevelParser => {
    "off" => Off,
    "error" => Error,
    "warn" => Warn,
    "info" => Info,
    "debug" => Debug,
    "trace" => Trace,
});

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Sarif,
}

crate::enum_args!(Format : FormatParser => {
    "human" => Human,
    "json" => Json,
    "sarif" => Sarif,
});

#[derive(Copy, Clone, Debug)]
pub enum Color {
    Auto,
    Always,
    Never,
}

crate::enum_args!(Color : ColorParser => {
    "auto" => Auto,
    "always" => Always,
    "never" => Never,
});

#[derive(Clone)]
struct TargetParser;

impl clap::builder::TypedValueParser for TargetParser {
    type Value = &'static str;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let Some(v) = value.to_str() else {
            return Err(clap_err!(InvalidUtf8, cmd));
        };

        cfg_expr::targets::get_builtin_target_by_triple(v)
            .ok_or_else(|| clap_err_invalid_value!(v, arg, cmd))
            .map(|t| t.triple.0.as_ref())
    }

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        // We _could_ list all of the builtin target triples here, but that's maybe a bit much...
        None
    }
}

pub(crate) struct GraphContext {
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) metadata_path: Option<PathBuf>,
    pub(crate) config: Option<PathBuf>,
    pub(crate) workspace: bool,
    pub(crate) exclude: Vec<String>,
    pub(crate) target: Vec<&'static str>,
    pub(crate) all_features: bool,
    pub(crate) no_default_features: bool,
    pub(crate) features: Vec<String>,
    pub(crate) frozen: bool,
    pub(crate) offline: bool,
    pub(crate) locked: bool,
    pub(crate) exclude_dev: bool,
    pub(crate) exclude_unpublished: bool,
}

impl GraphContext {
    fn fill(cmd: Command) -> Command {
        cmd.args([
            Arg::new("MANIFEST_PATH").long("manifest-path").help("The path of a Cargo.toml to use as the context for the operation.").long_help("The path of a Cargo.toml to use as the context for the operation.\n\nBy default, the Cargo.toml in the current working directory is used.").value_parser(PathParser).value_hint(clap::ValueHint::FilePath),
            Arg::new("METADATA_PATH").long("metadata-path").help("Path to cargo metadata json.").long_help("Path to cargo metadata json.\n\nBy default we use `cargo metadata` to generate the metadata json, but you can override that behaviour by providing the path to the output of `cargo metadata`.").value_parser(PathParser).value_hint(clap::ValueHint::FilePath),
            Arg::new("CONFIG_PATH").long("config").help("Path to the config to use.").long_help("Path to the config to use.\n\nDefaults to <cwd>/deny.toml if not specified.").value_parser(PathParser).value_hint(clap::ValueHint::FilePath),
            Arg::new("workspace").long("workspace").help("If passed, all workspace packages are used as roots for the crate graph.").long_help("If passed, all workspace packages are used as roots for the crate graph.\n\nAutomatically assumed if the manifest path points to a virtual manifest.\n\nNormally, if you specify a manifest path that is a member of a workspace, that crate will be the sole root of the crate graph, meaning only other workspace members that are dependencies of that workspace crate will be included in the graph. This overrides that behavior to include all workspace members.").action(clap::ArgAction::SetTrue),
            Arg::new("exclude").long("exclude").help("One or more crates to exclude from the crate graph.").long_help("One or more crates to exclude from the crate graph.\n\nNOTE: Unlike cargo, this does not have to be used with the `--workspace` flag.").value_name("CRATE").action(clap::ArgAction::Append),
            Arg::new("target").short('t').long("target").help("One or more platforms to filter crates by.").long_help("One or more platforms to filter crates by.\n\nIf a dependency is target specific, it will be ignored if it does not match 1 or more of the specified targets. This option overrides the top-level `targets = []` configuration value.").value_parser(TargetParser).value_name("CFG"),
            Arg::new("all-features").long("all-features").help("Activate all available features.").action(clap::ArgAction::SetTrue),
            Arg::new("no-default-features").long("no-default-features").help("Do not activate the `default` feature.").action(clap::ArgAction::SetTrue),
            Arg::new("FEATURES").long("features").help("List of features to activate").value_delimiter(',').action(clap::ArgAction::Append),
            Arg::new("frozen").long("frozen").help("Equivalent to specifying both `--locked` and `--offline`.").action(clap::ArgAction::SetTrue),
            Arg::new("offline").long("offline").help("Run without accessing the network.").long_help("Run without accessing the network.\n\nDisables fetching crates, advisory databases, and std-replacement-data").action(clap::ArgAction::SetTrue),
            Arg::new("locked").long("locked").help("Assert that `Cargo.lock` will remain unchanged.").action(clap::ArgAction::SetTrue),
            Arg::new("exclude-dev").long("exclude-dev").help("Exclude dev-dependencies for workspace crates.").action(clap::ArgAction::SetTrue),
            Arg::new("exclude-unpublished").long("exclude-unpublished").help("Exclude unpublished workspace members from graph roots.").long_help(
                "Exclude unpublished workspace members from graph roots.\n\nWorkspace members are considered unpublished if they they are explicitly marked with `publish = false`.\n\nNote that the excluded workspace members are still used for the initial dependency resolution by cargo, which might affect the exact version of used dependencies.").action(clap::ArgAction::SetTrue),
        ])
    }

    fn parse(args: &mut ArgMatches) -> Self {
        let manifest_path = args.remove_one("MANIFEST_PATH");
        let metadata_path = args.remove_one("METADATA_PATH");
        let config = args.remove_one("CONFIG_PATH");
        let workspace = args.get_flag("workspace");
        let exclude = args
            .remove_many("exclude")
            .map_or(Default::default(), |v| v.collect());
        let target = args
            .remove_many("target")
            .map_or(Default::default(), |v| v.collect());
        let all_features = args.get_flag("all-features");
        let no_default_features = args.get_flag("no-default-features");
        let features = args
            .remove_many("FEATURES")
            .map_or(Default::default(), |v| v.collect());
        let frozen = args.get_flag("frozen");
        let offline = frozen || args.get_flag("offline");
        let locked = frozen || args.get_flag("locked");
        let exclude_dev = args.get_flag("exclude-dev");
        let exclude_unpublished = args.get_flag("exclude-unpublished");

        Self {
            manifest_path,
            metadata_path,
            config,
            workspace,
            exclude,
            target,
            all_features,
            no_default_features,
            features,
            frozen,
            offline,
            locked,
            exclude_dev,
            exclude_unpublished,
        }
    }
}

struct Args {
    log_level: log::LevelFilter,
    format: Format,
    color: Color,
    ctx: GraphContext,
    cmd: Subcommand,
}

impl Args {
    fn command() -> Command {
        let cmd = clap::Command::new("cargo-deny")
            .version(env!("CARGO_PKG_VERSION"))
            .author(env!("CARGO_PKG_AUTHORS"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .help_expected(true)
            .args([
                Arg::new("LOG_LEVEL").short('L').long("log-level").default_value("warn").value_parser(LevelParser).help("The log level for messages.").long_help("The log level for messages.\n\nOnly messages at or above the level will be emitted"),
                Arg::new("FORMAT").short('f').long("format").default_value("human").value_parser(FormatParser).help("The output format."),
                Arg::new("COLOR").short('c').long("color").default_value("auto").value_parser(ColorParser).env("CARGO_TERM_COLOR").help("Controls output coloring."),
            ]);

        let cmd = GraphContext::fill(cmd);
        Subcommand::fill(cmd)
    }

    fn parse(args: &mut ArgMatches) -> Self {
        let log_level = *args.get_one("LOG_LEVEL").unwrap();
        let format = *args.get_one("FORMAT").unwrap();
        let color = *args.get_one("COLOR").unwrap();

        let ctx = GraphContext::parse(args);
        let (name, mut args) = args.remove_subcommand().unwrap();
        let cmd = match name.as_str() {
            "check" => Subcommand::Check(check::Args::parse(&mut args)),
            "fetch" => Subcommand::Fetch(fetch::Args::parse(&mut args)),
            "list" => Subcommand::List(list::Args::parse(&mut args)),
            "init" => Subcommand::Init(init::Args::parse(&mut args)),
            _ => unreachable!(),
        };

        Self {
            log_level,
            format,
            color,
            ctx,
            cmd,
        }
    }
}

fn setup_logger(
    level: log::LevelFilter,
    format: Format,
    color: bool,
) -> Result<(), fern::InitError> {
    use log::Level::{Debug, Error, Info, Trace, Warn};
    use nu_ansi_term::Color::{Blue, Green, Purple, Red, Yellow};

    match format {
        Format::Human => {
            struct Human(jiff::Zoned);

            impl std::fmt::Display for Human {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(
                        f,
                        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        self.0.year(),
                        self.0.month(),
                        self.0.day(),
                        self.0.hour(),
                        self.0.minute(),
                        self.0.second()
                    )
                }
            }

            let now = Human(jiff::Zoned::now());

            if color {
                fern::Dispatch::new()
                    .level(level)
                    .format(move |out, message, record| {
                        out.finish(format_args!(
                            "{date} [{level}] {message}\x1B[0m",
                            date = now,
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
                            date = now,
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
                                "timestamp": jiff::Timestamp::now().to_string(),
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
    let cmd = Args::command();
    let mut args = cmd.get_matches_from(
        std::env::args()
            .enumerate()
            .filter_map(|(i, a)| if i == 1 && a == "deny" { None } else { Some(a) }),
    );

    let args = Args::parse(&mut args);

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
        metadata_path: args.ctx.metadata_path,
        config_path: args.ctx.config,
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

    match args.cmd {
        Subcommand::Check(cargs) => {
            let show_stats = cargs.show_stats;
            let stats = check::cmd(log_ctx, cargs, krate_ctx)?;

            if let Some(exit_code) =
                stats::print_stats(stats, show_stats, log_level, args.format, args.color)
            {
                std::process::exit(exit_code);
            }

            Ok(())
        }
        Subcommand::Fetch(fargs) => fetch::cmd(log_ctx, fargs, krate_ctx),
        Subcommand::Init(iargs) => init::cmd(iargs, krate_ctx),
        Subcommand::List(largs) => list::cmd(log_ctx, largs, krate_ctx),
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
        insta::with_settings!({
            snapshot_path => "../../tests/snapshots",
        }, {
            snapshot_test_cli_command(
                super::Args::command().name("cargo_deny"),
                "cargo_deny".to_owned(),
            );
        });
    }
}
