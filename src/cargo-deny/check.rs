use ansi_term::Color;
use cargo_deny::{self, ban, licenses};
use failure::{bail, format_err, Error};
use serde::Deserialize;
use slog::info;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug, PartialEq)]
pub enum WhichCheck {
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
pub struct Args {
    /// The path to the config file used to determine which crates are
    /// allowed or denied. Will default to <context>/deny.toml if not specified.
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
    /// A root directory to place dotviz graphs into when duplicate crate
    /// versions are detected. Will be <dir>/graph_output/<crate_name>.dot.
    /// The /graph_output/* is deleted and recreated each run.
    #[structopt(short, long, parse(from_os_str))]
    graph: Option<PathBuf>,
    /// The check(s) to perform: 'all', 'license', or 'ban'
    #[structopt(default_value = "all")]
    which: WhichCheck,
}

impl Args {
    pub fn needs_license_store(&self) -> bool {
        self.which != WhichCheck::Ban
    }
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

pub fn cmd(
    log: slog::Logger,
    context_dir: PathBuf,
    args: Args,
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
