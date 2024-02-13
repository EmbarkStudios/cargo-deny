use anyhow::{Context as _, Result};
use cargo_deny::{
    diag::{Diagnostic, Files, Severity},
    root_cfg::{GraphConfig, OutputConfig},
    PathBuf, {advisories, bans, licenses, sources},
};

pub struct ValidConfig {
    pub advisories: advisories::cfg::ValidConfig,
    pub bans: bans::cfg::ValidConfig,
    pub licenses: licenses::cfg::ValidConfig,
    pub sources: sources::cfg::ValidConfig,
    pub graph: GraphConfig,
    pub output: OutputConfig,
}

impl ValidConfig {
    pub fn load(
        cfg_path: Option<PathBuf>,
        exceptions_cfg_path: Option<PathBuf>,
        files: &mut Files,
        log_ctx: crate::common::LogContext,
    ) -> Result<Self> {
        use cargo_deny::UnvalidatedConfig;

        let (cfg_contents, cfg_path) = match cfg_path {
            Some(cfg_path) if cfg_path.exists() => (
                std::fs::read_to_string(&cfg_path)
                    .with_context(|| format!("failed to read config from {cfg_path}"))?,
                cfg_path,
            ),
            Some(cfg_path) => {
                log::warn!(
                    "config path '{cfg_path}' doesn't exist, falling back to default config"
                );
                (String::new(), cfg_path)
            }
            None => {
                log::warn!("unable to find a config path, falling back to default config");
                (String::new(), PathBuf::from("deny.default.toml"))
            }
        };

        let id = files.add(&cfg_path, cfg_contents);

        let print = |files: &Files, diags: Vec<Diagnostic>| {
            if diags.is_empty() {
                return;
            }

            if let Some(printer) = crate::common::DiagPrinter::new(log_ctx, None, None) {
                let mut lock = printer.lock();
                for diag in diags {
                    lock.print(diag, files);
                }
            }
        };

        let mut parsed = toml_file::parse(files.source(id))
            .with_context(|| format!("failed to parse config from '{cfg_path}'"))?;

        use cargo_deny::Deserialize;
        let cfg = match cargo_deny::root_cfg::RootConfig::deserialize(&mut parsed) {
            Ok(c) => c,
            Err(err) => {
                let diags = err
                    .errors
                    .into_iter()
                    .map(|d| d.to_diagnostic(id))
                    .collect();
                print(files, diags);
                anyhow::bail!("failed to deserialize config from '{cfg_path}'");
            }
        };

        log::info!("using config from {cfg_path}");

        let validate = || -> (Vec<Diagnostic>, Self) {
            // Accumulate all configuration diagnostics rather than earlying out so
            // the user has the full list of problems to fix

            let mut diags = Vec::new();

            let advisories =
                cfg.advisories
                    .unwrap_or_default()
                    .validate(cargo_deny::cfg::ValidationContext {
                        cfg_id: id,
                        files,
                        diagnostics: &mut diags,
                    });

            let bans = cfg
                .bans
                .unwrap_or_default()
                .validate(cargo_deny::cfg::ValidationContext {
                    cfg_id: id,
                    files,
                    diagnostics: &mut diags,
                });
            let mut licenses =
                cfg.licenses
                    .unwrap_or_default()
                    .validate(cargo_deny::cfg::ValidationContext {
                        cfg_id: id,
                        files,
                        diagnostics: &mut diags,
                    });

            // Allow for project-local exceptions. Relevant in corporate environments.
            // https://github.com/EmbarkStudios/cargo-deny/issues/541
            if let Some(ecp) = exceptions_cfg_path {
                licenses::cfg::load_exceptions(&mut licenses, ecp, files, &mut diags);
            };

            let sources =
                cfg.sources
                    .unwrap_or_default()
                    .validate(cargo_deny::cfg::ValidationContext {
                        cfg_id: id,
                        files,
                        diagnostics: &mut diags,
                    });

            // Warn the user if they used a target triple that was not a built-in
            // or even parseable as it might mean it won't match against a cfg
            // expression they were expecting it to
            for target in &cfg.graph.targets {
                if !matches!(&target.filter.value, krates::Target::Unknown(_)) {
                    continue;
                }

                diags.push(
                    Diagnostic::warning()
                        .with_message(format!("unknown target `{}` specified", target.filter.value))
                        .with_labels(vec![
                    cargo_deny::diag::Label::primary(
                        id,
                        target.filter.span).with_message(
                        "the triple won't be evaluated against cfg() sections, just explicit triples"),
                    ]),
                );
            }

            // Warn the user if they are using deprecated keys
            {
                use cargo_deny::diag::general::{Deprecated, DeprecationReason};

                diags.extend(cfg.graph_deprecated.into_iter().map(|key| {
                    Deprecated {
                        key,
                        reason: DeprecationReason::Moved("graph"),
                        file_id: id,
                    }
                    .into()
                }));

                if let Some(key) = cfg.output_deprecated {
                    diags.push(
                        Deprecated {
                            key,
                            reason: DeprecationReason::Moved("output"),
                            file_id: id,
                        }
                        .into(),
                    );
                }
            }

            (
                diags,
                Self {
                    advisories,
                    bans,
                    licenses,
                    sources,
                    graph: cfg.graph,
                    output: cfg.output,
                },
            )
        };

        let (diags, valid_cfg) = validate();

        let has_errors = diags.iter().any(|d| d.severity >= Severity::Error);

        print(files, diags);

        // While we could continue in the face of configuration errors, the user
        // may end up with unexpected results, so just abort so they can fix them
        if has_errors {
            anyhow::bail!("failed to validate configuration file {cfg_path}");
        } else {
            Ok(valid_cfg)
        }
    }
}
