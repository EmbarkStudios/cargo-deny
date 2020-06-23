use crate::stats::{AllStats, Stats};
use anyhow::{Context, Error};
use cargo_deny::{advisories, bans, diag::Diagnostic, licenses, sources, CheckCtx};
use clap::arg_enum;
use log::error;
use serde::Deserialize;
use std::{path::PathBuf, time::Instant};
use structopt::StructOpt;

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
    /// Path to the config to use
    ///
    /// Defaults to <cwd>/deny.toml if not specified
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
    /// Path to graph_output root directory
    ///
    /// If set, a dotviz graph will be created for whenever multiple versions of the same crate are detected.
    ///
    /// Each file will be created at <dir>/graph_output/<crate_name>.dot. <dir>/graph_output/* is deleted and recreated each run.
    #[structopt(short, long, parse(from_os_str))]
    graph: Option<PathBuf>,
    /// Hides the inclusion graph when printing out info for a crate
    #[structopt(long)]
    hide_inclusion_graph: bool,
    /// Disable fetching of the advisory database
    ///
    /// When running the `advisories` check, the configured advisory database will be fetched and opened. If this flag is passed, the database won't be fetched, but an error will occur if it doesn't already exist locally.
    #[structopt(short, long)]
    disable_fetch: bool,
    /// Show stats for all the checks, regardless of the log-level
    #[structopt(short, long = "show-stats")]
    pub show_stats: bool,
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
    sources: Option<sources::Config>,
    #[serde(default)]
    targets: Vec<crate::common::Target>,
}

struct ValidConfig {
    advisories: advisories::cfg::ValidConfig,
    bans: bans::cfg::ValidConfig,
    licenses: licenses::ValidConfig,
    sources: sources::ValidConfig,
    targets: Vec<(krates::Target, Vec<String>)>,
}

impl ValidConfig {
    fn load(
        cfg_path: Option<PathBuf>,
        files: &mut codespan::Files<String>,
        format: crate::Format,
        color: crate::Color,
    ) -> Result<Self, Error> {
        let (cfg_contents, cfg_path) = match cfg_path {
            Some(cfg_path) if cfg_path.exists() => (
                std::fs::read_to_string(&cfg_path).with_context(|| {
                    format!("failed to read config from {}", cfg_path.display())
                })?,
                cfg_path,
            ),
            Some(cfg_path) => {
                log::warn!(
                    "config path '{}' doesn't exist, falling back to default config",
                    cfg_path.display()
                );
                (String::new(), cfg_path)
            }
            None => {
                log::warn!("unable to find a config path, falling back to default config");
                (String::new(), PathBuf::from("deny.default.toml"))
            }
        };

        let cfg: Config = toml::from_str(&cfg_contents).with_context(|| {
            format!("failed to deserialize config from '{}'", cfg_path.display())
        })?;

        log::info!("using config from {}", cfg_path.display());

        let id = files.add(&cfg_path, cfg_contents);

        let validate = || -> Result<(Vec<Diagnostic>, Self), Vec<Diagnostic>> {
            let advisories = cfg.advisories.unwrap_or_default().validate(id)?;
            let bans = cfg.bans.unwrap_or_default().validate(id)?;
            let licenses = cfg.licenses.unwrap_or_default().validate(id)?;

            // Sources has a special case where it has a default value if one isn't specified,
            // which doesn't play nicely with the toml::Spanned type, so we pass in the
            // file contents as well so that sources validation can scan the contents itself
            // if needed.
            let sources = cfg
                .sources
                .unwrap_or_default()
                .validate(id, files.source(id))?;

            let mut diagnostics = Vec::new();
            let targets = crate::common::load_targets(cfg.targets, &mut diagnostics, id);

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
            if diags.is_empty() {
                return;
            }

            match format {
                crate::Format::Human => {
                    use codespan_reporting::term::{self, termcolor::ColorChoice};
                    let writer = term::termcolor::StandardStream::stderr(match color {
                        crate::Color::Auto => {
                            // The termcolor crate doesn't check the stream to see if it's a TTY
                            // which doesn't really fit with how the rest of the coloring works
                            if atty::is(atty::Stream::Stderr) {
                                ColorChoice::Auto
                            } else {
                                ColorChoice::Never
                            }
                        }
                        crate::Color::Always => ColorChoice::Always,
                        crate::Color::Never => ColorChoice::Never,
                    });

                    let config = term::Config::default();
                    let mut writer = writer.lock();
                    for diag in diags {
                        term::emit(&mut writer, &config, files, &diag).unwrap();
                    }
                }
                crate::Format::Json => {
                    use codespan_reporting::diagnostic::Severity;
                    use std::io::Write;

                    let mut json = Vec::new();
                    let stderr = std::io::stderr();
                    let mut el = stderr.lock();

                    for diag in diags {
                        let mut to_print = serde_json::json!({
                            "type": "diagnostic",
                            "fields": {
                                "severity": match diag.severity {
                                    Severity::Error => "error",
                                    Severity::Warning => "warning",
                                    Severity::Note => "note",
                                    Severity::Help => "help",
                                    Severity::Bug => "bug",
                                },
                                "message": diag.message,
                            },
                        });

                        {
                            let obj = to_print.as_object_mut().unwrap();
                            let obj = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

                            if !diag.labels.is_empty() {
                                let mut labels = Vec::with_capacity(diag.labels.len());

                                for label in diag.labels {
                                    let location = files
                                        .location(label.file_id, label.range.start as u32)
                                        .unwrap();
                                    labels.push(serde_json::json!({
                                        "message": label.message,
                                        "span": &files.source(label.file_id)[label.range],
                                        "line": location.line.to_usize(),
                                        "column": location.column.to_usize(),
                                    }));
                                }

                                obj.insert("labels".to_owned(), serde_json::Value::Array(labels));
                            }
                        }

                        json.clear();
                        let cursor = std::io::Cursor::new(&mut json);
                        if serde_json::to_writer(cursor, &to_print).is_ok() {
                            let _ = el.write_all(&json);
                            let _ = el.write(b"\n");
                        }
                    }
                }
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

pub(crate) fn cmd(
    log_level: log::LevelFilter,
    format: crate::Format,
    color: crate::Color,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<AllStats, Error> {
    let mut files = codespan::Files::new();
    let mut cfg = ValidConfig::load(
        krate_ctx.get_config_path(args.config.clone()),
        &mut files,
        format,
        color,
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

    let targets = std::mem::replace(&mut cfg.targets, Vec::new());

    rayon::scope(|s| {
        s.spawn(|_| {
            let gathered = krate_ctx.gather_krates(targets);

            if let Ok(ref krates) = gathered {
                rayon::scope(|s| {
                    if check_advisories {
                        s.spawn(|_| {
                            advisory_lockfile = Some(advisories::load_lockfile(krates.lock_path()));
                        });
                    }

                    s.spawn(|_| krate_spans = Some(cargo_deny::diag::KrateSpans::new(&krates)));
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
        let lockfile = advisory_lockfile.unwrap()?;

        Some((db, lockfile))
    } else {
        None
    };

    let (krate_spans, spans_id) = krate_spans
        .map(|(spans, contents)| {
            let id = files.add(krates.lock_path(), contents);
            (spans, id)
        })
        .unwrap();

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

    use cargo_deny::diag::Severity;

    let max_severity = match log_level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Error => Some(Severity::Error),
        log::LevelFilter::Warn => Some(Severity::Warning),
        log::LevelFilter::Info => Some(Severity::Note),
        log::LevelFilter::Debug => Some(Severity::Help),
        log::LevelFilter::Trace => Some(Severity::Help),
    };

    let mut stats = AllStats::default();

    if check_advisories {
        stats.advisories = Some(Stats::default());
    }

    if check_bans {
        stats.bans = Some(Stats::default());
    }

    if check_licenses {
        stats.licenses = Some(Stats::default());
    }

    if check_sources {
        stats.sources = Some(Stats::default());
    }

    let show_inclusion_graphs = !args.hide_inclusion_graph;

    rayon::scope(|s| {
        // Asynchronously displays messages sent from the checks
        s.spawn(|_| {
            print_diagnostics(
                rx,
                show_inclusion_graphs,
                format,
                krates,
                max_severity,
                files,
                &mut stats,
                color,
            );
        });

        if let Some(summary) = license_summary {
            let lic_tx = tx.clone();
            let lic_cfg = cfg.licenses;

            let ctx = CheckCtx {
                cfg: lic_cfg,
                krates: &krates,
                krate_spans: &krate_spans,
                spans_id,
            };

            s.spawn(move |_| {
                log::info!("checking licenses...");
                let start = Instant::now();
                licenses::check(ctx, summary, lic_tx);
                let end = Instant::now();

                log::info!("licenses checked in {}ms", (end - start).as_millis());
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

            let ctx = CheckCtx {
                cfg: ban_cfg,
                krates: &krates,
                krate_spans: &krate_spans,
                spans_id,
            };

            s.spawn(|_| {
                log::info!("checking bans...");
                let start = Instant::now();
                bans::check(ctx, output_graph, ban_tx);
                let end = Instant::now();

                log::info!("bans checked in {}ms", (end - start).as_millis());
            });
        }

        if check_sources {
            let sources_tx = tx.clone();
            let sources_cfg = cfg.sources;

            let ctx = CheckCtx {
                cfg: sources_cfg,
                krates: &krates,
                krate_spans: &krate_spans,
                spans_id,
            };

            s.spawn(|_| {
                log::info!("checking sources...");
                let start = Instant::now();
                sources::check(ctx, sources_tx);
                let end = Instant::now();

                log::info!("sources checked in {}ms", (end - start).as_millis());
            });
        }

        if let Some((db, lockfile)) = advisory_ctx {
            let adv_cfg = cfg.advisories;

            let ctx = CheckCtx {
                cfg: adv_cfg,
                krates: &krates,
                krate_spans: &krate_spans,
                spans_id,
            };

            s.spawn(move |_| {
                log::info!("checking advisories...");
                let start = Instant::now();
                advisories::check(ctx, &db, lockfile, tx);
                let end = Instant::now();

                log::info!("advisories checked in {}ms", (end - start).as_millis());
            });
        }
    });

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn print_diagnostics(
    rx: crossbeam::channel::Receiver<cargo_deny::diag::Pack>,
    show_inclusion_graphs: bool,
    format: crate::Format,
    krates: &cargo_deny::Krates,
    max_severity: Option<cargo_deny::diag::Severity>,
    files: codespan::Files<String>,
    stats: &mut AllStats,
    color: crate::Color,
) {
    use crate::Format;
    use cargo_deny::diag::Check;
    use codespan_reporting::{
        diagnostic::Severity,
        term::{self, termcolor::ColorChoice},
    };
    use std::io::Write;

    let text_grapher = cargo_deny::diag::TextGrapher::new(krates);
    let obj_grapher = cargo_deny::diag::ObjectGrapher::new(krates);

    let mut json = Vec::new();
    let stderr = std::io::stderr();

    let writer = term::termcolor::StandardStream::stderr(match color {
        crate::Color::Auto => {
            // The termcolor crate doesn't check the stream to see if it's a TTY
            // which doesn't really fit with how the rest of the coloring works
            if atty::is(atty::Stream::Stderr) {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        crate::Color::Always => ColorChoice::Always,
        crate::Color::Never => ColorChoice::Never,
    });
    let config = term::Config::default();

    for pack in rx {
        let mut lock = writer.lock();

        let check_stats = match pack.check {
            Check::Advisories => stats.advisories.as_mut().unwrap(),
            Check::Bans => stats.bans.as_mut().unwrap(),
            Check::Licenses => stats.licenses.as_mut().unwrap(),
            Check::Sources => stats.sources.as_mut().unwrap(),
        };

        for diag in pack.into_iter() {
            let mut inner = diag.diag;

            match inner.severity {
                Severity::Error => check_stats.errors += 1,
                Severity::Warning => check_stats.warnings += 1,
                Severity::Note => check_stats.notes += 1,
                Severity::Help => check_stats.helps += 1,
                Severity::Bug => {}
            }

            match max_severity {
                Some(max) => {
                    if inner.severity < max {
                        continue;
                    }
                }
                None => continue,
            }

            // We _could_ just take a single lock, but then normal log messages would
            // not be displayed until after this thread exited
            match format {
                Format::Human => {
                    if show_inclusion_graphs {
                        for kid in diag.kids {
                            if let Ok(graph) = text_grapher.write_graph(&kid) {
                                inner.notes.push(graph);
                            }
                        }
                    }

                    let _ = term::emit(&mut lock, &config, &files, &inner);
                }
                Format::Json => {
                    let mut to_print = serde_json::json!({
                        "type": "diagnostic",
                        "fields": {
                            "severity": match inner.severity {
                                Severity::Error => "error",
                                Severity::Warning => "warning",
                                Severity::Note => "note",
                                Severity::Help => "help",
                                Severity::Bug => "bug",
                            },
                            "message": inner.message,
                        },
                    });

                    {
                        let obj = to_print.as_object_mut().unwrap();
                        let obj = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

                        if let Some(code) = inner.code {
                            obj.insert("code".to_owned(), serde_json::Value::String(code));
                        }

                        if !inner.labels.is_empty() {
                            let mut labels = Vec::with_capacity(inner.labels.len());

                            for label in inner.labels {
                                let location = files
                                    .location(label.file_id, label.range.start as u32)
                                    .unwrap();
                                labels.push(serde_json::json!({
                                    "message": label.message,
                                    "span": &files.source(label.file_id)[label.range],
                                    "line": location.line.to_usize(),
                                    "column": location.column.to_usize(),
                                }));
                            }

                            obj.insert("labels".to_owned(), serde_json::Value::Array(labels));
                        }

                        if !inner.notes.is_empty() {
                            obj.insert(
                                "notes".to_owned(),
                                serde_json::Value::Array(
                                    inner
                                        .notes
                                        .into_iter()
                                        .map(|s| serde_json::Value::String(s))
                                        .collect(),
                                ),
                            );
                        }

                        if show_inclusion_graphs {
                            let mut graphs = Vec::new();
                            for kid in diag.kids {
                                if let Ok(graph) = obj_grapher.write_graph(&kid) {
                                    if let Ok(sgraph) = serde_json::value::to_value(graph) {
                                        graphs.push(sgraph);
                                    }
                                }
                            }

                            obj.insert("graphs".to_owned(), serde_json::Value::Array(graphs));
                        }
                    }

                    json.clear();
                    let cursor = std::io::Cursor::new(&mut json);
                    if serde_json::to_writer(cursor, &to_print).is_ok() {
                        let mut el = stderr.lock();
                        let _ = el.write_all(&json);
                        let _ = el.write(b"\n");
                    }
                }
            }
        }
    }
}
