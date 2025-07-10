use crate::{
    common::ValidConfig,
    stats::{AllStats, Stats},
};
use anyhow::Context;
use cargo_deny::{
    CheckCtx, PathBuf, advisories, bans,
    diag::{DiagnosticCode, DiagnosticOverrides, ErrorSink, Files, Severity},
    licenses, sources,
};
use log::error;
use std::time::Instant;

#[derive(clap::ValueEnum, Debug, PartialEq, Eq, Copy, Clone)]
pub enum WhichCheck {
    Advisories,
    Ban,
    Bans,
    License,
    Licenses,
    Sources,
    All,
}

#[derive(strum::EnumString, Debug, Copy, Clone, PartialEq, Eq)]
#[strum(serialize_all = "kebab-case")]
pub enum Level {
    Allowed,
    Warnings,
    Denied,
}

impl From<Level> for Severity {
    fn from(l: Level) -> Self {
        match l {
            Level::Allowed => Self::Note,
            Level::Warnings => Self::Warning,
            Level::Denied => Self::Error,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeOrLevel {
    Code(DiagnosticCode),
    Level(Level),
}

impl std::str::FromStr for CodeOrLevel {
    type Err = strum::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt to parse level first, since the error
        // for codes are probably more meaningful for most users
        s.parse::<Level>()
            .map(Self::Level)
            .or_else(|_err| s.parse::<DiagnosticCode>().map(Self::Code))
    }
}

#[derive(clap::Parser, Debug)]
pub struct LintLevels {
    /// Set lint warnings
    #[arg(long, short = 'W')]
    warn: Vec<CodeOrLevel>,
    /// Set lint allowed
    #[arg(long, short = 'A')]
    allow: Vec<CodeOrLevel>,
    /// Set lint denied
    #[arg(long, short = 'D')]
    deny: Vec<CodeOrLevel>,
}

#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to <cwd>/deny.toml if not specified
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Path to cargo metadata json
    /// 
    /// By default we use `cargo metadata` to generate
    /// the metadata json, but you can override that behaviour by
    /// providing the path to cargo metadata.
    #[arg(long)]
    pub metadata_path: Option<PathBuf>,

    /// Path to graph output root directory
    ///
    /// If set, a dotviz graph will be created for whenever multiple versions of the same crate are detected.
    ///
    /// Each file will be created at `<dir>/graph_output/<crate_name>.dot`. `<dir>/graph_output/*` is deleted and recreated each run.
    #[arg(short, long)]
    pub graph: Option<PathBuf>,
    /// Hides the inclusion graph when printing out info for a crate
    #[arg(long)]
    pub hide_inclusion_graph: bool,
    /// Disable fetching of the advisory database
    ///
    /// When running the `advisories` check, the configured advisory database will be fetched and opened. If this flag is passed, the database won't be fetched, but an error will occur if it doesn't already exist locally.
    #[arg(short, long)]
    pub disable_fetch: bool,
    /// If set, excludes all dev-dependencies, not just ones for non-workspace crates
    #[arg(long)]
    pub exclude_dev: bool,
    /// To ease transition from cargo-audit to cargo-deny, this flag will tell cargo-deny to output the exact same output as cargo-audit would, to `stdout` instead of `stderr`, just as with cargo-audit.
    ///
    /// Note that this flag only applies when the output format is JSON, and note that since cargo-deny supports multiple advisory databases, instead of a single JSON object, there will be 1 for each unique advisory database.
    #[arg(long)]
    pub audit_compatible_output: bool,
    /// Show stats for all the checks, regardless of the log-level
    #[arg(short, long)]
    pub show_stats: bool,
    #[command(flatten)]
    pub lint_levels: LintLevels,
    /// Specifies the depth at which feature edges are added in inclusion graphs
    #[arg(long, conflicts_with = "hide_inclusion_graph")]
    pub feature_depth: Option<u32>,
    /// The check(s) to perform
    #[arg(value_enum)]
    pub which: Vec<WhichCheck>,
}

pub(crate) fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    mut krate_ctx: crate::common::KrateContext,
) -> anyhow::Result<AllStats> {
    let mut files = Files::new();
    let ValidConfig {
        advisories,
        bans,
        licenses,
        sources,
        graph,
        output,
    } = ValidConfig::load(
        krate_ctx.get_config_path(args.config.clone()),
        krate_ctx.get_local_exceptions_path(),
        &mut files,
        log_ctx,
    )?;

    let metadata = if let Some(metadata_path) = args.metadata_path {
        let data = std::fs::read_to_string(metadata_path).context("metadata path")?;
        Some(serde_json::from_str(&data).context("cargo metadata")?)
    } else {
        None
    };

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

    let feature_depth = args.feature_depth.or(output.feature_depth);

    krate_ctx.all_features |= graph.all_features;
    krate_ctx.no_default_features |= graph.no_default_features;
    krate_ctx.exclude_dev |= graph.exclude_dev | args.exclude_dev;
    krate_ctx.exclude_unpublished |= graph.exclude_unpublished;

    // If not specified on the cmd line, fallback to the feature related config options
    if krate_ctx.features.is_empty() {
        krate_ctx.features = graph.features;
    }

    let mut krates = None;
    let mut license_store = None;
    let mut advisory_dbs = None;

    // Create an override structure that remaps specific codes
    let overrides = {
        let ll = args.lint_levels;

        if ll.allow.is_empty() && ll.deny.is_empty() && ll.warn.is_empty() {
            None
        } else {
            let mut code_overrides = std::collections::BTreeMap::new();
            let mut level_overrides = Vec::new();

            let mut insert = |list: Vec<CodeOrLevel>, severity: Severity| -> anyhow::Result<()> {
                for cl in list {
                    match cl {
                        CodeOrLevel::Code(code) => {
                            if let Some(current) = code_overrides.get(code.as_str()) {
                                anyhow::bail!(
                                    "unable to override code '{code}' to '{severity:?}', it has already been overridden to '{current:?}'"
                                );
                            }

                            code_overrides.insert(code.as_str(), severity);
                        }
                        CodeOrLevel::Level(level) => {
                            let ls = level.into();
                            if let Some(current) =
                                level_overrides.iter().find_map(|(input, output)| {
                                    if ls == *input { Some(*output) } else { None }
                                })
                            {
                                anyhow::bail!(
                                    "unable to override level '{level:?}' to '{severity:?}', it has already been overridden to '{current:?}'"
                                );
                            }

                            level_overrides.push((ls, severity));
                        }
                    }
                }

                Ok(())
            };

            insert(ll.allow, Severity::Note)?;
            insert(ll.warn, Severity::Warning)?;
            insert(ll.deny, Severity::Error)?;

            Some(std::sync::Arc::new(DiagnosticOverrides {
                code_overrides,
                level_overrides,
            }))
        }
    };

    rayon::scope(|s| {
        s.spawn(|_s| {
            // Always run a fetch first in a separate step so that the user can
            // see what parts are actually taking time
            let start = std::time::Instant::now();
            log::info!("fetching crates for {}", krate_ctx.manifest_path);
            if let Err(err) = krate_ctx.fetch_krates() {
                log::error!("failed to fetch crates: {err:#}");
            } else {
                log::info!("fetched crates in {:?}", start.elapsed());
            }

            krates = Some(krate_ctx.gather_krates(metadata, graph.targets, graph.exclude));
        });

        if check_advisories {
            s.spawn(|_| {
                advisory_dbs = Some(advisories::DbSet::load(
                    advisories.db_path.clone(),
                    advisories
                        .db_urls
                        .iter()
                        .map(|us| us.as_ref().clone())
                        .collect(),
                    if args.disable_fetch {
                        advisories::Fetch::Disallow(advisories.maximum_db_staleness.value)
                    } else if advisories.git_fetch_with_cli {
                        advisories::Fetch::AllowWithGitCli
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

    let advisory_db_set = if check_advisories {
        let dbset = advisory_dbs.unwrap()?;
        Some(dbset)
    } else {
        None
    };

    let krate_spans = cargo_deny::diag::KrateSpans::synthesize(
        &krates,
        krates.workspace_root().as_str(),
        &mut files,
    );

    let license_summary = if check_licenses {
        let store = license_store.unwrap()?;
        let gatherer = licenses::Gatherer::default()
            .with_store(std::sync::Arc::new(store))
            .with_confidence_threshold(licenses.confidence_threshold);

        Some(gatherer.gather(&krates, &mut files, Some(&licenses)))
    } else {
        None
    };

    let graph_out_dir = args.graph;

    let (tx, rx) = crossbeam::channel::unbounded();

    let krates = &krates;

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
    let serialize_extra = match log_ctx.format {
        crate::Format::Json => true,
        crate::Format::Human => false,
    };
    let audit_compatible_output =
        args.audit_compatible_output && log_ctx.format == crate::Format::Json;

    let colorize = log_ctx.format == crate::Format::Human
        && crate::common::should_colorize(log_ctx.color, std::io::stderr());

    let log_level = log_ctx.log_level;

    let files = &files;

    rayon::scope(|s| {
        // Asynchronously displays messages sent from the checks
        s.spawn(|_| {
            print_diagnostics(
                rx,
                log_ctx,
                if show_inclusion_graphs {
                    Some(krates)
                } else {
                    None
                },
                files,
                &mut stats,
                feature_depth,
            );
        });

        if let Some(summary) = license_summary {
            let sink = ErrorSink {
                overrides: overrides.clone(),
                channel: tx.clone(),
            };

            let ctx = CheckCtx {
                cfg: licenses,
                krates,
                krate_spans: &krate_spans,
                serialize_extra,
                colorize,
                log_level,
                files,
            };

            s.spawn(move |_| {
                log::info!("checking licenses...");
                let start = Instant::now();
                licenses::check(ctx, summary, sink);

                log::info!("licenses checked in {}ms", start.elapsed().as_millis());
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
                    Err(err) => {
                        error!("unable to create directory '{output_dir}': {err}");

                        Box::new(move |dup_graph: bans::DupGraph| {
                            anyhow::bail!(
                                "unable to write {}.dot: could not create parent directory",
                                dup_graph.duplicate
                            );
                        })
                    }
                }
            });

            let bans_sink = ErrorSink {
                overrides: overrides.clone(),
                channel: tx.clone(),
            };

            let ctx = CheckCtx {
                cfg: bans,
                krates,
                krate_spans: &krate_spans,
                serialize_extra,
                colorize,
                log_level,
                files,
            };

            s.spawn(|_| {
                log::info!("checking bans...");
                let start = Instant::now();
                bans::check(ctx, output_graph, bans_sink);

                log::info!("bans checked in {}ms", start.elapsed().as_millis());
            });
        }

        if check_sources {
            let sources_sink = ErrorSink {
                overrides: overrides.clone(),
                channel: tx.clone(),
            };

            let ctx = CheckCtx {
                cfg: sources,
                krates,
                krate_spans: &krate_spans,
                serialize_extra,
                colorize,
                log_level,
                files,
            };

            s.spawn(|_| {
                log::info!("checking sources...");
                let start = Instant::now();
                sources::check(ctx, sources_sink);

                log::info!("sources checked in {}ms", start.elapsed().as_millis());
            });
        }

        if let Some(dbset) = advisory_db_set {
            let mut advisories_sink = ErrorSink {
                overrides,
                channel: tx,
            };

            let ctx = CheckCtx {
                cfg: advisories,
                krates,
                krate_spans: &krate_spans,
                serialize_extra,
                colorize,
                log_level,
                files,
            };

            s.spawn(move |_| {
                // We need to have all the crates when opening indices, so can't
                // load them at the same time as the dbset, but meh, this should
                // be very fast since we only load from cache, in parallel
                let indices = if !ctx.cfg.disable_yank_checking {
                    // If we can't find the cargo home directory, we won't be able
                    // to load the cargo indices. We _could_ actually do a fetch
                    // into a temporary directory instead, but this almost certainly
                    // means that something is wrong
                    match tame_index::utils::cargo_home() {
                        Ok(cargo_home) => {
                            log::info!("loading index metadata for crates...");
                            let start = Instant::now();

                            let indices = advisories::Indices::load(krates, cargo_home);

                            log::info!(
                                "cached index metadata loaded in {}ms",
                                start.elapsed().as_millis()
                            );
                            Some(indices)
                        }
                        Err(err) => {
                            advisories_sink.push(ctx.diag_for_index_load_failure(format!(
                                "unable to find cargo home directory: {err:#}"
                            )));
                            None
                        }
                    }
                } else {
                    None
                };

                log::info!("checking advisories...");
                let start = Instant::now();

                #[allow(clippy::disallowed_macros)]
                let audit_reporter = if audit_compatible_output {
                    Some(|val: serde_json::Value| {
                        println!("{val}");
                    })
                } else {
                    None
                };

                advisories::check(ctx, &dbset, audit_reporter, indices, advisories_sink);

                log::info!("advisories checked in {}ms", start.elapsed().as_millis());
            });
        }
    });

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn print_diagnostics(
    rx: crossbeam::channel::Receiver<cargo_deny::diag::Pack>,
    log_ctx: crate::common::LogContext,
    krates: Option<&cargo_deny::Krates>,
    files: &Files,
    stats: &mut AllStats,
    feature_depth: Option<u32>,
) {
    use cargo_deny::diag::Check;

    let dp = crate::common::DiagPrinter::new(log_ctx, krates, feature_depth);

    for pack in rx {
        let check_stats = match pack.check {
            Check::Advisories => stats.advisories.as_mut().unwrap(),
            Check::Bans => stats.bans.as_mut().unwrap(),
            Check::Licenses => stats.licenses.as_mut().unwrap(),
            Check::Sources => stats.sources.as_mut().unwrap(),
        };

        for diag in pack.iter() {
            match diag.diag.severity {
                Severity::Error => check_stats.errors += 1,
                Severity::Warning => check_stats.warnings += 1,
                Severity::Note => check_stats.notes += 1,
                Severity::Help => check_stats.helps += 1,
                Severity::Bug => {}
            }
        }

        if let Some(mut lock) = dp.as_ref().map(|dp| dp.lock()) {
            lock.print_krate_pack(pack, files);
        }
    }
}
