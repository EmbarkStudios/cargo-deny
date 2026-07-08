use crate::common::ValidConfig;
use anyhow::{Context as _, Error};
use cargo_deny::{PathBuf, diag::Files, licenses};

#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to a deny.toml in the same folder as the manifest path, or a deny.toml in a parent directory.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Path to cargo metadata json
    ///
    /// By default we use `cargo metadata` to generate
    /// the metadata json, but you can override that behaviour by
    /// providing the path to cargo metadata.
    #[arg(long)]
    metadata_path: Option<PathBuf>,
    /// Minimum confidence threshold for license text
    ///
    /// When determining the license from file contents, a confidence score is assigned according to how close the contents are to the canonical license text. If the confidence score is below this threshold, they license text will ignored, which might mean the crate is treated as unlicensed.
    ///
    /// [possible values: 0.0 - 1.0]
    #[arg(short, long, default_value = "0.8")]
    threshold: f32,
    /// The format of the output
    #[arg(short, long, default_value = "human", value_enum)]
    format: licenses::OutputFormat,
    /// The layout for the output, does not apply to TSV
    #[arg(short, long, default_value = "license", value_enum)]
    layout: licenses::Layout,
}

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    let cfg_path = krate_ctx.get_config_path(args.config.as_deref())?;

    let mut files = Files::new();
    let ValidConfig {
        graph, licenses, ..
    } = ValidConfig::load(
        cfg_path,
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

    let (krates, store) = rayon::join(
        || krate_ctx.gather_krates(metadata, graph.targets, graph.exclude),
        crate::common::load_license_store,
    );

    let krates = krates.context("failed to gather crates")?;
    let store = store.context("failed to load license store")?;

    let gatherer = licenses::Gatherer::default()
        .with_store(std::sync::Arc::new(store))
        .with_confidence_threshold(args.threshold);

    let mut files = Files::new();

    let summary = gatherer.gather(&krates, &mut files, &licenses);

    let colorize = crate::common::should_colorize(log_ctx.color, std::io::stdout());

    cargo_deny::licenses::list(
        &mut std::io::stdout(),
        &summary,
        args.format,
        args.layout,
        colorize,
    )?;

    Ok(())
}
