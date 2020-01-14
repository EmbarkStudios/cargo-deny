use anyhow::{Context, Error};
use cargo_deny::{advisories, bans, diag::Diagnostic, licenses, sources};
use clap::arg_enum;
use log::error;
use serde::Deserialize;
use std::path::PathBuf;
use structopt::StructOpt;

use crate::common::make_absolute_path;

arg_enum! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub enum WhichCheck {
        Advisories,
        Ban,
        Bans,
        License,
        Licenses,
        Sources,
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
struct Target {
    triple: toml::Spanned<String>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Deserialize)]
struct Config {
    advisories: Option<advisories::cfg::Config>,
    bans: Option<bans::cfg::Config>,
    licenses: Option<licenses::Config>,
    sources: Option<sources::Config>,
    #[serde(default)]
    targets: Vec<Target>,
}

struct ValidConfig {
    advisories: advisories::cfg::ValidConfig,
    bans: bans::cfg::ValidConfig,
    licenses: licenses::ValidConfig,
    sources: sources::ValidConfig,
    targets: Vec<(String, Vec<String>)>,
}

impl ValidConfig {
    fn load(cfg_path: PathBuf, files: &mut codespan::Files<String>) -> Result<Self, Error> {
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

        let validate = || -> Result<(Vec<Diagnostic>, Self), Vec<Diagnostic>> {
            let advisories = cfg.advisories.unwrap_or_default().validate(id)?;
            let bans = cfg.bans.unwrap_or_default().validate(id)?;
            let licenses = cfg.licenses.unwrap_or_default().validate(id)?;
            let sources = cfg.sources.unwrap_or_default().validate(id)?;

            let mut targets = Vec::with_capacity(cfg.targets.len());
            let mut diagnostics = Vec::new();
            for target in cfg.targets {
                let triple = target.triple.get_ref();

                if krates::cfg_expr::targets::get_target_by_triple(triple).is_none() {
                    diagnostics.push(Diagnostic::new_warning(
                        format!("unknown target `{}` specified", triple),
                        cargo_deny::diag::Label::new(
                            id,
                            target.triple.span().0 as u32..target.triple.span().1 as u32,
                            "the triple won't be evaluated against cfg() sections, just explicit triples"
                        ),
                    ));
                }

                targets.push((triple.into(), target.features));
            }

            Ok((
                diagnostics,
                Self {
                    advisories,
                    bans,
                    licenses,
                    sources,
                    targets,
                },
            ))
        };

        let print = |diags: Vec<Diagnostic>| {
            use codespan_reporting::term;

            if diags.is_empty() {
                return;
            }

            let writer =
                term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
            let config = term::Config::default();
            let mut writer = writer.lock();
            for diag in &diags {
                term::emit(&mut writer, &config, &files, &diag).unwrap();
            }
        };

        match validate() {
            Ok((diags, vc)) => {
                print(diags);
                Ok(vc)
            }
            Err(diags) => {
                print(diags);

                anyhow::bail!(
                    "failed to validate configuration file {}",
                    cfg_path.display()
                );
            }
        }
    }
}

pub fn cmd(
    log_level: log::LevelFilter,
    args: Args,
    targets: Vec<String>,
    context_dir: PathBuf,
) -> Result<(), Error> {
    let mut files = codespan::Files::new();
    let cfg = ValidConfig::load(
        make_absolute_path(args.config.clone(), &context_dir),
        &mut files,
    )?;

    let check_advisories = args.which.is_empty()
        || args
            .which
            .iter()
            .any(|w| *w == WhichCheck::Advisories || *w == WhichCheck::All);

    let check_bans = args.which.is_empty()
        || args
            .which
            .iter()
            .any(|w| *w == WhichCheck::Bans || *w == WhichCheck::Ban || *w == WhichCheck::All);

    let check_licenses = args.which.is_empty()
        || args.which.iter().any(|w| {
            *w == WhichCheck::Licenses || *w == WhichCheck::License || *w == WhichCheck::All
        });

    let check_sources = args.which.is_empty()
        || args
            .which
            .iter()
            .any(|w| *w == WhichCheck::Sources || *w == WhichCheck::All);

    let mut krates = None;
    let mut license_store = None;
    let mut advisory_db = None;
    let mut advisory_lockfile = None;
    let mut krate_spans = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            let targets = if !targets.is_empty() {
                targets.into_iter().map(|name| (name, Vec::new())).collect()
            } else if !cfg.targets.is_empty() {
                cfg.targets
                    .iter()
                    .map(|(name, features)| (name.clone(), features.clone()))
                    .collect()
            } else {
                Vec::new()
            };

            let gathered = crate::common::gather_krates(context_dir, targets);

            if let Ok(ref krates) = gathered {
                rayon::scope(|s| {
                    if check_advisories {
                        s.spawn(|_| {
                            advisory_lockfile = Some(advisories::generate_lockfile(&krates))
                        });
                    }

                    if check_advisories || check_bans || check_sources {
                        s.spawn(|_| krate_spans = Some(cargo_deny::diag::KrateSpans::new(&krates)));
                    }
                });
            }

            krates = Some(gathered);
        });

        if check_advisories {
            s.spawn(|_| {
                advisory_db = Some(advisories::load_db(
                    cfg.advisories.db_url.as_ref().map(AsRef::as_ref),
                    cfg.advisories.db_path.as_ref().cloned(),
                    if args.disable_fetch {
                        advisories::Fetch::Disallow
                    } else {
                        advisories::Fetch::Allow
                    },
                ));
            });
        }

        if check_licenses {
            s.spawn(|_| license_store = Some(crate::common::load_license_store()));
        }
    });

    let krates = krates.unwrap()?;

    let advisory_ctx = if check_advisories {
        let db = advisory_db.unwrap()?;
        let lockfile = advisory_lockfile.unwrap();

        Some((db, lockfile))
    } else {
        None
    };

    let krate_spans = krate_spans.map(|(spans, contents)| {
        let id = files.add(krates.lock_path().to_string_lossy(), contents);
        (spans, id)
    });

    let license_summary = if check_licenses {
        let store = license_store.unwrap()?;
        let gatherer = licenses::Gatherer::default()
            .with_store(std::sync::Arc::new(store))
            .with_confidence_threshold(cfg.licenses.confidence_threshold);

        Some(gatherer.gather(&krates, &mut files, Some(&cfg.licenses)))
    } else {
        None
    };

    let graph_out_dir = args.graph;

    let (tx, rx) = crossbeam::channel::unbounded();

    let krates = &krates;
    let inc_grapher = if args.hide_inclusion_graph {
        None
    } else {
        Some(cargo_deny::diag::Grapher::new(krates))
    };

    use cargo_deny::diag::Severity;

    let max_severity = match log_level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Error => Some(Severity::Error),
        log::LevelFilter::Warn => Some(Severity::Warning),
        log::LevelFilter::Info => Some(Severity::Note),
        log::LevelFilter::Debug => Some(Severity::Help),
        log::LevelFilter::Trace => Some(Severity::Help),
    };

    let mut has_errors = None;

    rayon::scope(|s| {
        // Asynchronously displays messages sent from the checks
        s.spawn(|_| {
            has_errors = print_diagnostics(rx, inc_grapher, max_severity, files);
        });

        if let Some(summary) = license_summary {
            let lic_tx = tx.clone();
            let lic_cfg = cfg.licenses;
            s.spawn(move |_| {
                log::info!("checking licenses...");
                licenses::check(&lic_cfg, summary, lic_tx);
            });
        }

        if check_bans {
            let output_graph = graph_out_dir.map(|pb| -> Box<bans::OutputGraph> {
                let output_dir = pb.join("graph_output");
                let _ = std::fs::remove_dir_all(&output_dir);

                match std::fs::create_dir_all(&output_dir) {
                    Ok(_) => Box::new(move |dup_graph: bans::DupGraph| {
                        std::fs::write(
                            output_dir.join(format!("{}.dot", dup_graph.duplicate)),
                            dup_graph.graph.as_bytes(),
                        )?;

                        Ok(())
                    }),
                    Err(e) => {
                        error!(
                            "unable to create directory '{}': {}",
                            output_dir.display(),
                            e
                        );

                        Box::new(move |dup_graph: bans::DupGraph| {
                            anyhow::bail!(
                                "unable to write {}.dot: could not create parent directory",
                                dup_graph.duplicate
                            );
                        })
                    }
                }
            });

            let ban_tx = tx.clone();
            let ban_cfg = cfg.bans;

            s.spawn(|_| {
                log::info!("checking bans...");
                bans::check(
                    ban_cfg,
                    krates,
                    krate_spans.as_ref().map(|(s, id)| (s, *id)).unwrap(),
                    output_graph,
                    ban_tx,
                );
            });
        }

        if check_sources {
            let sources_tx = tx.clone();
            let sources_cfg = cfg.sources;

            s.spawn(|_| {
                log::info!("checking sources...");
                sources::check(
                    sources_cfg,
                    krates,
                    krate_spans.as_ref().map(|(s, id)| (s, *id)).unwrap(),
                    sources_tx,
                );
            });
        }

        if let Some((db, lockfile)) = advisory_ctx {
            let adv_cfg = cfg.advisories;
            let krate_spans = krate_spans.as_ref().map(|(s, id)| (s, *id)).unwrap();
            s.spawn(move |_| {
                log::info!("checking advisories...");
                advisories::check(adv_cfg, krates, krate_spans, &db, &lockfile, tx);
            });
        }
    });

    match has_errors {
        Some(errs) => Err(errs),
        None => Ok(()),
    }
}

fn print_diagnostics(
    rx: crossbeam::channel::Receiver<cargo_deny::diag::Pack>,
    mut inc_grapher: Option<cargo_deny::diag::Grapher<'_>>,
    max_severity: Option<cargo_deny::diag::Severity>,
    files: codespan::Files<String>,
) -> Option<Error> {
    use codespan_reporting::term;

    let writer = term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
    let config = term::Config::default();

    let mut error_count = 0;

    for pack in rx {
        let mut inclusion_graph = pack
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

            // Only add the dependency graph to the first diagnostic for a particular crate
            if let Some(graph) = inclusion_graph.take() {
                diag.notes.push(graph);
            }

            // We _could_ just take a single lock, but then normal log messages would
            // not be displayed until after this thread exited
            term::emit(&mut writer.lock(), &config, &files, &diag).unwrap();
        }
    }

    if error_count > 0 {
        Some(anyhow::anyhow!("encountered {} errors", error_count))
    } else {
        None
    }
}
