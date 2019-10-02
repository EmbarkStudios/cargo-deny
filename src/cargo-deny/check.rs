use cargo_deny::{ban, licenses};
use clap::arg_enum;
use codespan_reporting::diagnostic::Diagnostic;
use failure::{format_err, Error};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

arg_enum! {
    #[derive(Debug, PartialEq)]
    pub enum WhichCheck {
        License,
        Ban,
        All,
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
    /// The check(s) to perform
    #[structopt(
        default_value = "all",
        possible_values = &WhichCheck::variants(),
        case_insensitive = true,
    )]
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

struct ValidatedConfig {
    licenses: Option<licenses::ValidConfig>,
    bans: Option<ban::ValidConfig>,
}

impl Config {
    fn validate(
        self,
        files: &mut codespan::Files,
        path: &Path,
        contents: String,
    ) -> Result<ValidatedConfig, Vec<Diagnostic>> {
        let id = files.add(path.to_string_lossy(), contents.clone());

        let licenses = match self.licenses {
            Some(lc) => Some(lc.validate(id)?),
            None => None,
        };

        let bans = match self.bans {
            Some(b) => Some(b.validate(id, &contents)?),
            None => None,
        };

        Ok(ValidatedConfig { licenses, bans })
    }
}

pub fn cmd(
    log_level: log::LevelFilter,
    context_dir: PathBuf,
    args: Args,
    krates: cargo_deny::Krates,
    store: Option<licenses::LicenseStore>,
) -> Result<(), Error> {
    let cfg_path = args
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

    let mut files = codespan::Files::new();

    let cfg = {
        let cfg_contents = std::fs::read_to_string(&cfg_path)
            .map_err(|e| format_err!("failed to read config from {}: {}", cfg_path.display(), e))?;

        let cfg: Config = toml::from_str(&cfg_contents).map_err(|e| {
            format_err!(
                "failed to deserialize config from {}: {}",
                cfg_path.display(),
                e
            )
        })?;

        match cfg.validate(&mut files, &cfg_path, cfg_contents) {
            Ok(vcfg) => vcfg,
            Err(diags) => {
                use codespan_reporting::term;

                let writer =
                    term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
                let config = term::Config::default();
                for diag in &diags {
                    term::emit(&mut writer.lock(), &config, &files, &diag).unwrap();
                }

                return Err(format_err!(
                    "failed to validate configuration file {}",
                    cfg_path.display()
                ));
            }
        }
    };

    let lic_cfg = if args.which == WhichCheck::All || args.which == WhichCheck::License {
        if let Some(licenses) = cfg.licenses {
            let gatherer = licenses::Gatherer::default()
                .with_store(std::sync::Arc::new(
                    store.expect("we should have a license store"),
                ))
                .with_confidence_threshold(licenses.confidence_threshold);

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

    let ban_cfg = if args.which == WhichCheck::All || args.which == WhichCheck::Ban {
        cfg.bans
    } else {
        None
    };

    let graph_out_dir = args.graph;

    let (send, recv) = crossbeam::channel::unbounded();

    let krates = &krates;
    let mut inc_grapher = cargo_deny::inclusion_graph::Grapher::new(krates);

    use codespan_reporting::diagnostic::Severity;

    let max_severity = match log_level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Debug => Some(Severity::Help),
        log::LevelFilter::Error => Some(Severity::Error),
        log::LevelFilter::Info => Some(Severity::Note),
        log::LevelFilter::Trace => Some(Severity::Help),
        log::LevelFilter::Warn => Some(Severity::Warning),
    };
        move || {
            if let Some((summary, lic_cfg)) = lic_cfg {
                licenses::check_licenses(summary, &lic_cfg, send.clone());
            }

            if let Some(ref bans) = ban_cfg {
                let output_graph = graph_out_dir.map(|pb| {
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

                let _: Result<(), _> = ban::check_bans(
                    log.new(slog::o!("stage" => "ban_check")),
                    krates,
                    bans,
                    output_graph,
                );
            }
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
                    .map(|pid| inc_grapher.write_graph(&pid).unwrap());

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
                Some(failure::format_err!("encountered {} errors", error_count))
            } else {
                None
            }
        },
    );

    if let Some(err) = error {
        Err(err)
    } else {
        Ok(())
    }
}
