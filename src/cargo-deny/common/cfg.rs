use anyhow::{Context as _, Result};
use cargo_deny::{
    PathBuf,
    diag::{Diagnostic, Files, Severity},
    root_cfg::{GraphConfig, OutputConfig},
    {advisories, bans, licenses, sources},
};
use toml_span::value::{Value, ValueInner};

/// The manifest tables a config can be sourced from, in priority order
const MANIFEST_CFG_POINTERS: [&str; 2] = [
    "/workspace/metadata/cargo-deny",
    "/package/metadata/cargo-deny",
];

/// Where the config for a run is read from
pub enum ConfigSource {
    /// A dedicated config file, eg. `deny.toml`
    File(PathBuf),
    /// A `metadata.cargo-deny` table in a `Cargo.toml`
    Manifest(PathBuf),
}

/// Retrieves the pointer to the `metadata.cargo-deny` table of a parsed manifest
pub fn manifest_cfg_pointer(manifest: &Value<'_>) -> Option<&'static str> {
    MANIFEST_CFG_POINTERS
        .into_iter()
        .find(|ptr| manifest.pointer(ptr).is_some())
}

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
        cfg_src: Option<ConfigSource>,
        exceptions_cfg_path: Option<PathBuf>,
        files: &mut Files,
        log_ctx: crate::common::LogContext,
    ) -> Result<Self> {
        use cargo_deny::UnvalidatedConfig;

        let (cfg_contents, cfg_path, from_manifest) = match cfg_src {
            Some(ConfigSource::File(cfg_path)) if cfg_path.exists() => (
                std::fs::read_to_string(&cfg_path)
                    .with_context(|| format!("failed to read config from {cfg_path}"))?,
                cfg_path,
                false,
            ),
            Some(ConfigSource::File(cfg_path)) => {
                log::warn!(
                    "config path '{cfg_path}' doesn't exist, falling back to default config"
                );
                (String::new(), cfg_path, false)
            }
            Some(ConfigSource::Manifest(manifest_path)) => (
                std::fs::read_to_string(&manifest_path)
                    .with_context(|| format!("failed to read config from {manifest_path}"))?,
                manifest_path,
                true,
            ),
            None => {
                log::warn!("unable to find a config path, falling back to default config");
                (String::new(), PathBuf::from("deny.default.toml"), false)
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

        let mut parsed = toml_span::parse(files.source(id))
            .with_context(|| format!("failed to parse config from '{cfg_path}'"))?;

        // The manifest is added to the files as a whole, so the spans of the
        // metadata table are already relative to it and diagnostics point at
        // the manifest just as they would at a config file
        let root = if from_manifest {
            let md = manifest_cfg_pointer(&parsed)
                .and_then(|ptr| parsed.pointer_mut(ptr))
                .with_context(|| format!("'{cfg_path}' has no cargo-deny metadata table"))?;

            // `workspace-duplicates` is read from the manifest of each workspace
            // crate directly when gathering spans, it's not part of the config
            let mut inner = md.take();
            if let ValueInner::Table(table) = &mut inner {
                table.remove("workspace-duplicates");
            }
            md.set(inner);
            md
        } else {
            &mut parsed
        };

        use cargo_deny::Deserialize;
        let cfg = match cargo_deny::root_cfg::RootConfig::deserialize(root) {
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
                        .with_message(format_args!("unknown target `{}` specified", target.filter.value))
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

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"[package]
name = "metadata-config"
version = "0.1.0"

[package.metadata.cargo-deny]
workspace-duplicates = []

[package.metadata.cargo-deny.licenses]
allow = ["MIT"]
"#;

    #[inline]
    fn log_ctx() -> crate::common::LogContext {
        crate::common::LogContext {
            format: crate::Format::Human,
            color: crate::Color::Never,
            log_level: log::LevelFilter::Off,
        }
    }

    /// Ensures the spans of the metadata config are relative to the manifest
    /// itself so that diagnostics point at the offending value
    #[test]
    fn test_manifest_cfg_pointer() {
        let manifest = toml_span::parse(MANIFEST).unwrap();

        assert_eq!(
            manifest_cfg_pointer(&manifest),
            Some("/package/metadata/cargo-deny")
        );

        let span = manifest
            .pointer("/package/metadata/cargo-deny/licenses/allow/0")
            .unwrap()
            .span;
        assert_eq!(&MANIFEST[span.start..span.end], "MIT");
    }

    #[test]
    fn test_load_from_manifest() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = PathBuf::from_path_buf(temp_dir.path().join("Cargo.toml")).unwrap();
        std::fs::write(&manifest_path, MANIFEST).unwrap();

        let mut files = Files::new();
        let cfg = ValidConfig::load(
            Some(ConfigSource::Manifest(manifest_path)),
            None,
            &mut files,
            log_ctx(),
        )
        .unwrap();

        assert_eq!(cfg.licenses.allowed.len(), 1);
        assert_eq!(cfg.licenses.allowed[0].0.value.to_string(), "MIT");
    }
}
