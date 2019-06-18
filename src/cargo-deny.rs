#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use ansi_term::Color;
use cargo_deny::{self, ban, licenses};
use failure::{bail, format_err, Error};
use serde::Deserialize;
use slog::{info, warn};
use std::path::PathBuf;
use structopt::StructOpt;

mod list;

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

#[derive(Copy, Clone, Debug)]
enum ColorWhen {
    Always,
    Never,
    Auto,
}

impl std::str::FromStr for ColorWhen {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let c = match s {
            "auto" => ColorWhen::Auto,
            "always" => ColorWhen::Always,
            "never" => ColorWhen::Never,
            s => bail!("unknown coloring flag '{}'", s),
        };

        Ok(c)
    }
}

#[derive(StructOpt, Debug)]
struct ListArgs {
    /// The confidence threshold required for license files
    /// to be positively identified
    #[structopt(short, long, default_value = "0.8")]
    threshold: f32,
    /// The format of the output
    #[structopt(short, long, default_value = "human")]
    format: MessageFormat,
    /// Output coloring: 'auto', 'always', or 'never'
    #[structopt(long, default_value = "auto")]
    color: ColorWhen,

}

#[derive(StructOpt, Debug, PartialEq)]
enum WhichCheck {
    License,
    Ban,
    All,
}

impl std::str::FromStr for WhichCheck {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let check = match s {
            "all" => WhichCheck::All,
            "license" => WhichCheck::License,
            "ban" => WhichCheck::Ban,
            other => bail!("unknown check '{}'", other),
        };

        Ok(check)
    }
}

#[derive(StructOpt, Debug)]
struct CheckArgs {
    /// The path to the config file used to determine which crates are
    /// allowed or denied. Will default to <context>/deny.toml if not specified.
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
    #[structopt(short, long, parse(from_os_str))]
    graph: Option<PathBuf>,
    /// The check(s) to perform
    #[structopt(default_value = "all")]
    which: WhichCheck,
}

#[derive(StructOpt, Debug)]
enum Command {
    #[structopt(name = "list")]
    List(ListArgs),
    #[structopt(name = "check")]
    Check(CheckArgs),
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
                if check.which == WhichCheck::Ban {
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
        Command::List(list) => list_cmd(root_logger, list, all_crates, store),
        Command::Check(check) => check_cmd(root_logger, context_dir, check, all_crates, store),
    }
}

fn list_cmd(
    log: slog::Logger,
    args: ListArgs,
    crates: cargo_deny::Crates,
    store: Option<licenses::LicenseStore>,
) -> Result<(), Error> {
    use cargo_deny::binary_search;
    use licenses::{Note, Summary};
    use std::{
        cmp::Ordering,
        collections::{BTreeMap, HashMap},
        fmt::{self, Write},
    };
    let gatherer = licenses::Gatherer::new(log.new(slog::o!("stage" => "license_gather")))
        .with_store(std::sync::Arc::new(
            store.expect("we should have a license store"),
        ))
        .with_confidence_threshold(args.threshold);

    let summary = gatherer.gather(crates.as_ref(), HashMap::new());

    #[derive(PartialEq, Eq, Ord)]
    enum Key<'a> {
        License(&'a str),
        Exception(&'a str),
        Unlicensed,
    }

    impl<'a> fmt::Display for Key<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let s = match self {
                Key::License(l) => l,
                Key::Exception(e) => e,
                Key::Unlicensed => "Unlicensed",
            };

            write!(f, "{}", s)
        }
    }

    impl<'a> serde::Serialize for Key<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                Key::License(l) => s.serialize_str(l),
                Key::Exception(e) => s.serialize_str(e),
                Key::Unlicensed => s.serialize_str("Unlicensed"),
            }
        }
    }

    impl<'a> std::cmp::PartialOrd for Key<'a> {
        fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
            match (self, o) {
                (Key::License(a), Key::License(b)) => a.partial_cmp(b),
                (Key::Exception(a), Key::Exception(b)) => a.partial_cmp(b),
                (Key::License(_), _) => Some(Ordering::Less),
                (_, Key::License(_)) => Some(Ordering::Greater),
                (Key::Unlicensed, Key::Unlicensed) => Some(Ordering::Equal),
                (Key::Unlicensed, _) => Some(Ordering::Greater),
                (_, Key::Unlicensed) => Some(Ordering::Less),
            }
        }
    }

    let mut license_map: BTreeMap<Key<'_>, Vec<String>> = BTreeMap::new();

    for crate_note in summary.notes() {
        for note in &crate_note.notes {
            match note {
                Note::License { name, .. } => {
                    let license_name = Summary::resolve_id(*name);

                    let key = Key::License(license_name);
                    match license_map.get_mut(&key) {
                        Some(v) => {
                            if let Err(i) = binary_search(v, crate_note.name) {
                                v.insert(i, crate_note.name.to_owned());
                            }
                        }
                        None => {
                            license_map.insert(key, vec![crate_note.name.to_owned()]);
                        }
                    }
                }
                Note::Unlicensed => match license_map.get_mut(&Key::Unlicensed) {
                    Some(v) => {
                        if let Err(i) = binary_search(v, crate_note.name) {
                            v.insert(i, crate_note.name.to_owned());
                        }

                    }
                    None => {
                        license_map.insert(Key::Unlicensed, vec![crate_note.name.to_owned()]);
                    }
                },
                Note::Exception(exc) => {
                    let key = Key::Exception(exc);
                    match license_map.get_mut(&key) {
                        Some(v) => {
                            if let Err(i) = binary_search(v, crate_note.name) {
                                v.insert(i, crate_note.name.to_owned());
                            }

                        }
                        None => {
                            license_map.insert(key, vec![crate_note.name.to_owned()]);
                        }
                    }
                }
                Note::Unknown { name, source } => {
                    warn!(
                        log,
                        "detected an unknown license";
                        "crate" => crate_note,
                        "src" => source,
                    );

                    let key = Key::License(name);
                    match license_map.get_mut(&key) {
                        Some(v) => {
                            if let Err(i) = binary_search(v, crate_note.name) {
                                v.insert(i, crate_note.name.to_owned());
                            }
                        }
                        None => {
                            license_map.insert(key, vec![crate_note.name.to_owned()]);
                        }
                    }
                }
                Note::LowConfidence { score, source } => {
                    warn!(
                        log,
                        "unable to determine license with high confidence";
                        "crate" => crate_note,
                        "score" => score,
                        "src" => source,
                    );
                }
                Note::UnreadableLicense { path, err } => {
                    warn!(
                        log,
                        "license file is unreadable";
                        "crate" => crate_note,
                        "path" => path.display(),
                        "err" => err.to_string(), // io::Error makes slog sad
                    );
                }
                Note::Ignored(_) => unreachable!(),
            }
        }
    }

    // Drop the stderr log so all of its output is written first
    drop(log);

    match args.format {
        MessageFormat::Human => {
            let mut output = String::with_capacity(4 * 1024);
            let color = match args.color {
                ColorWhen::Always => true,
                ColorWhen::Never => false,
                ColorWhen::Auto => atty::is(atty::Stream::Stdout),
            };

            for (k, v) in license_map {
                if color {
                    write!(
                        output,
                        "{}",
                        match k {
                            Key::License(l) => Color::Cyan.paint(l),
                            Key::Exception(e) => Color::Purple.paint(e),
                            Key::Unlicensed => Color::Red.paint("Unlicensed"),
                        }
                    )?;

                    write!(
                        output,
                        " ({}): ",
                        Color::White.bold().paint(v.len().to_string())
                    )?;
                } else {
                    write!(output, "{} ({}): ", k, v.len())?;
                }

                for (i, crate_name) in v.iter().enumerate() {
                    if i != 0 {
                        write!(output, ", {}", crate_name)?;
                    } else {
                        write!(output, "{}", crate_name)?;
                    }
                }

                writeln!(output)?;
            }

            std::io::Write::write_all(&mut std::io::stdout(), output.as_bytes())?;
        }
        MessageFormat::Json => {
            serde_json::to_writer(std::io::stdout(), &license_map)?;
        }
    }

    Ok(())
}

fn check_cmd(
    log: slog::Logger,
    context_dir: PathBuf,
    args: CheckArgs,
    crates: cargo_deny::Crates,
    store: Option<licenses::LicenseStore>,
) -> Result<(), Error> {
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

    info!(log, "checking crates"; "count" => crates.as_ref().len());

    if args.which == WhichCheck::All || args.which == WhichCheck::License {
        if let Some(ref mut licenses) = cfg.licenses {
            let ignored = licenses.get_ignore_licenses();

            {
                let mut timer = slog_perf::TimeReporter::new_with_level(
                    "check-licenses",
                    log.clone(),
                    slog::Level::Debug,
                );

                let gatherer =
                    licenses::Gatherer::new(log.new(slog::o!("stage" => "license_gather")))
                        .with_store(std::sync::Arc::new(
                            store.expect("we should have a license store"),
                        ))
                        .with_confidence_threshold(licenses.confidence_threshold);

                let summary =
                    timer.start_with("gather", || gatherer.gather(crates.as_ref(), ignored));

                timer.start_with("check", || {
                    licenses::check_licenses(
                        log.new(slog::o!("stage" => "license_check")),
                        summary,
                        licenses,
                    )
                })?;
            }

            info!(log, "{}", Color::Green.paint("license check succeeded!"));
        }
    }

    if args.which == WhichCheck::All || args.which == WhichCheck::Ban {
        if let Some(ref bans) = cfg.bans {
            let mut timer = slog_perf::TimeReporter::new_with_level(
                "check-bans",
                log.clone(),
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
                    log.new(slog::o!("stage" => "ban_check")),
                    &crates,
                    bans,
                    output_graph,
                )
            })?;

            info!(log, "{}", Color::Green.paint("ban check succeeded!"));
        }
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
