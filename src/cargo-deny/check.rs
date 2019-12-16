use anyhow::{Context, Error};
use cargo_deny::{advisories, bans, licenses};
use clap::arg_enum;
use codespan_reporting::diagnostic::Diagnostic;
use log::error;
use serde::Deserialize;
use std::path::PathBuf;
use structopt::StructOpt;

use crate::common::make_absolute_path;

arg_enum! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub enum WhichCheck {
        Advisories,
        Bans,
        Licenses,
        All,
    }
}

#[derive(StructOpt, Debug)]
pub struct Args {
    /// The path to the config file used to determine which crates are
    /// allowed or denied. Will default to <context>/deny.toml if not specified.
    #[structopt(short, long, parse(from_os_str), default_value = "deny.toml")]
    config: PathBuf,
    /// A root directory to place dotviz graphs into when duplicate crate
    /// versions are detected. Will be <dir>/graph_output/<crate_name>.dot.
    /// The /graph_output/* is deleted and recreated each run.
    #[structopt(short, long, parse(from_os_str))]
    graph: Option<PathBuf>,
    /// Hides the inclusion graph when printing out info for a crate
    #[structopt(short, long)]
    hide_inclusion_graph: bool,
    /// Disables fetching of the security advisory database, if would be loaded.
    /// If this disabled, and there is not already an existing advisory database
    /// locally, an error will occur.
    #[structopt(short, long)]
    disable_fetch: bool,
    /// The check(s) to perform
    #[structopt(
        possible_values = &WhichCheck::variants(),
        case_insensitive = true,
    )]
    which: Vec<WhichCheck>,
}

#[derive(Deserialize)]
struct Config {
    advisories: Option<advisories::cfg::Config>,
    bans: Option<bans::cfg::Config>,
    licenses: Option<licenses::Config>,
}

struct ValidConfig {
    advisories: advisories::cfg::ValidConfig,
    bans: bans::cfg::ValidConfig,
    licenses: licenses::ValidConfig,
}

impl ValidConfig {
    fn load(cfg_path: PathBuf, files: &mut codespan::Files) -> Result<Self, Error> {
        let cfg_contents = if cfg_path.exists() {
            std::fs::read_to_string(&cfg_path)
                .with_context(|| format!("failed to read config from {}", cfg_path.display()))?
        } else {
            log::warn!(
                "config path '{}' doesn't exist, falling back to default config",
                cfg_path.display()
            );
            String::new()
        };

        let cfg: Config = toml::from_str(&cfg_contents).with_context(|| {
            format!("failed to deserialize config from '{}'", cfg_path.display())
        })?;

        let id = files.add(cfg_path.to_string_lossy(), cfg_contents);

        let validate = || -> Result<Self, Vec<Diagnostic>> {
            let advisories = cfg.advisories.unwrap_or_default().validate(id)?;
            let bans = cfg.bans.unwrap_or_default().validate(id)?;
            let licenses = cfg.licenses.unwrap_or_default().validate(id)?;

            Ok(Self {
                advisories,
                bans,
                licenses,
            })
        };

        match validate() {
            Ok(vc) => Ok(vc),
            Err(diags) => {
                use codespan_reporting::term;

                let writer =
                    term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
                let config = term::Config::default();
                for diag in &diags {
                    term::emit(&mut writer.lock(), &config, &files, &diag).unwrap();
                }

                anyhow::bail!(
                    "failed to validate configuration file {}",
                    cfg_path.display()
                );
            }
        }
    }
}

pub fn cmd(log_level: log::LevelFilter, args: Args, context_dir: PathBuf) -> Result<(), Error> {
    let mut files = codespan::Files::new();
    let cfg = ValidConfig::load(
        make_absolute_path(args.config.clone(), &context_dir),
        &mut files,
    )?;

            Some((
                gatherer.gather(krates.as_ref(), &mut files, Some(&licenses)),
                licenses,
            ))
        } else {
            None
        }
    } else {
        None
    };

    let (ban_cfg, lock_id, lock_contents) =
        if args.which == WhichCheck::All || args.which == WhichCheck::Bans {
            let lock_contents = std::fs::read_to_string(&krates.lock_file)?;
            let lock_id = files.add(krates.lock_file.to_string_lossy(), lock_contents.clone());

            (cfg.bans, Some(lock_id), Some(lock_contents))
        } else {
            (None, None, None)
        };

    let graph_out_dir = args.graph;

    let (send, recv) = crossbeam::channel::unbounded();

    let krates = &krates;
    let mut inc_grapher = if args.hide_inclusion_graph {
        None
    } else {
        Some(cargo_deny::inclusion_graph::Grapher::new(krates))
    };

    use codespan_reporting::diagnostic::Severity;

    let max_severity = match log_level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Debug => Some(Severity::Help),
        log::LevelFilter::Error => Some(Severity::Error),
        log::LevelFilter::Info => Some(Severity::Note),
        log::LevelFilter::Trace => Some(Severity::Help),
        log::LevelFilter::Warn => Some(Severity::Warning),
    };

    let (check_error, error) = rayon::join(
        move || {
            if let Some((summary, lic_cfg)) = lic_cfg {
                log::info!("checking licenses...");
                licenses::check(summary, &lic_cfg, send.clone());
            }

            if let Some(bans) = ban_cfg {
                let output_graph = graph_out_dir.map(|pb| {
                    let output_dir = pb.join("graph_output");
                    let _ = std::fs::remove_dir_all(&output_dir);

                    std::fs::create_dir_all(&output_dir).unwrap();

                    move |dup_graph: bans::DupGraph| {
                        std::fs::write(
                            output_dir.join(format!("{}.dot", dup_graph.duplicate)),
                            dup_graph.graph.as_bytes(),
                        )?;

                        Ok(())
                    }
                });

                log::info!("checking bans...");
                return bans::check(
                    krates,
                    bans,
                    (lock_id.unwrap(), &lock_contents.unwrap()),
                    output_graph,
                    send.clone(),
                );
            }

            Ok(())
        },
        move || {
            use codespan_reporting::term;

            let writer =
                term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
            let config = term::Config::default();

            let mut error_count = 0;

            for pack in recv {
                let mut note = pack
                    .krate_id
                    .and_then(|pid| inc_grapher.as_mut().map(|ig| (pid, ig)))
                    .map(|(pid, ig)| ig.write_graph(&pid).unwrap());

                for mut diag in pack.diagnostics.into_iter() {
                    if diag.severity >= codespan_reporting::diagnostic::Severity::Error {
                        error_count += 1;
                    }

                    match max_severity {
                        Some(max) => {
                            if diag.severity < max {
                                continue;
                            }
                        }
                        None => continue,
                    }

                    if note.is_some() {
                        diag = diag.with_notes(vec![note.take().unwrap()]);
                    }

                    term::emit(&mut writer.lock(), &config, &files, &diag).unwrap();
                }
            }

            if error_count > 0 {
                Some(anyhow::anyhow!("encountered {} errors", error_count))
            } else {
                None
            }
        },
    );

    if let Some(err) = error {
        Err(err)
    } else if let Err(err) = check_error {
        Err(err)
    } else {
        Ok(())
    }
}
