use anyhow::{Context, Error};
use cargo_deny::{
    diag::Files,
    licenses::{self, LicenseExprSource, LicenseInfo},
};
use spdx::{expression::ExprNode, LicenseItem};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};
use tokio::runtime;

#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to a deny.toml in the same folder as the manifest path, or a deny.toml in a parent directory.
    #[clap(short, long, action)]
    config: Option<PathBuf>,
    /// Minimum confidence threshold for license text
    ///
    /// When determining the license from file contents, a confidence score is assigned according to how close the contents are to the canonical license text. If the confidence score is below this threshold, they license text will ignored, which might mean the crate is treated as unlicensed.
    ///
    /// [possible values: 0.0 - 1.0]
    #[clap(short, long, default_value = "0.8", action)]
    threshold: f32,
    /// The directory in which generated license notices are stored. Defaults to ./intellectual-property-notices.
    /// This directory will be created if it does not already exist.
    output_path: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
struct Config {
    #[serde(default)]
    targets: Vec<crate::common::Target>,
    #[serde(default)]
    exclude: Vec<String>,
}

struct ValidConfig {
    targets: Vec<(krates::Target, Vec<String>)>,
    exclude: Vec<String>,
}

impl ValidConfig {
    fn load(
        cfg_path: Option<PathBuf>,
        files: &mut Files,
        log_ctx: crate::common::LogContext,
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

                return Ok(Self {
                    targets: Vec::new(),
                    exclude: Vec::new(),
                });
            }
            None => {
                log::warn!("unable to find a config path, falling back to default config");

                return Ok(Self {
                    targets: Vec::new(),
                    exclude: Vec::new(),
                });
            }
        };

        let cfg: Config = toml::from_str(&cfg_contents).with_context(|| {
            format!("failed to deserialize config from '{}'", cfg_path.display())
        })?;

        log::info!("using config from {}", cfg_path.display());

        let id = files.add(&cfg_path, cfg_contents);

        use cargo_deny::diag::Diagnostic;

        let validate = || -> Result<(Vec<Diagnostic>, Self), Vec<Diagnostic>> {
            let mut diagnostics = Vec::new();
            let targets = crate::common::load_targets(cfg.targets, &mut diagnostics, id);
            let exclude = cfg.exclude;

            Ok((diagnostics, Self { targets, exclude }))
        };

        let print = |diags: Vec<Diagnostic>| {
            if diags.is_empty() {
                return;
            }

            if let Some(printer) = crate::common::DiagPrinter::new(log_ctx, None) {
                let mut lock = printer.lock();
                for diag in diags {
                    lock.print(diag, files);
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

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    let mut exit_code = 0;
    {
        let mut files = Files::new();
        let cfg = ValidConfig::load(krate_ctx.get_config_path(args.config), &mut files, log_ctx)?;

        let (krates, store) = rayon::join(
            || krate_ctx.gather_krates(cfg.targets, cfg.exclude),
            crate::common::load_license_store,
        );

        let krates = krates.context("failed to gather crates")?;
        let store = store.context("failed to load license store")?;

        let gatherer = licenses::Gatherer::default()
            .with_store(std::sync::Arc::new(store))
            .with_confidence_threshold(args.threshold);

        let mut files = Files::new();

        let summary = gatherer.gather(&krates, &mut files, None);
        let output_path = args
            .output_path
            .unwrap_or_else(|| PathBuf::from("./intellectual-property-notices"));
        fs::create_dir_all(&output_path).context("failed to create output directory")?;
        let mut license_text_cache = HashMap::new();
        let tokio_runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to init tokio runtime")?;
        for krate in summary.nfos {
            let mut keep_folder = false;
            let krate_path = output_path.join(&krate.krate.name);
            if !krate_path.exists() {
                fs::create_dir(&krate_path).with_context(|| {
                    format!(
                        "failed to create license directory for crate {}",
                        krate.krate.name
                    )
                })?;
            }
            for license in &krate.krate.license_file {
                let license_path = krate.krate.manifest_path.parent().unwrap().join(license);
                let res = fs::copy(
                    &license_path,
                    krate_path.join(license.file_name().expect("infallible")),
                );
                if let Err(e) = res {
                    exit_code = 1;
                    log::error!(
                        "Failed to copy {license_path} file for crate {} {e:?}",
                        krate.krate.name
                    );
                };
                keep_folder = true;
            }
            let name = &krate.krate.name;
            match krate.lic_info {
                LicenseInfo::SpdxExpression { expr, nfo } => {
                    let version = env!("CARGO_PKG_VERSION");
                    let spdx = expr.as_ref();
                    let mut licenses = String::new();
                    // Sometimes an spdx references a license multiple times, only include it once.
                    let mut described_licenses = HashSet::new();
                    for spdx_license in expr.iter().filter_map(|e| match e {
                        ExprNode::Req(r) => Some(r),
                        ExprNode::Op(_) => None,
                    }) {
                        match &spdx_license.req.license {
                            LicenseItem::Spdx { id, .. } => {
                                if !described_licenses.contains(id.name) {
                                    described_licenses.insert(id.name);
                                    if !license_text_cache.contains_key(id.name) {
                                        let http_resp = tokio_runtime.block_on(async {
                                        reqwest::get(
                                            format!("https://raw.githubusercontent.com/spdx/license-list-data/master/text/{}.txt", id.name)
                                        )
                                        .await
                                        .with_context(|| format!("failed to download license text for {}", id.full_name))?
                                        .text()
                                        .await
                                        .with_context(|| format!("failed to decode license text response for {}", id.full_name))
                                    })?;
                                        license_text_cache.insert(id.name, http_resp);
                                    }
                                    let license_text = license_text_cache.get(id.name).unwrap();
                                    licenses.push_str(license_text);
                                    licenses.push_str("\r\n\r\n");
                                }
                            }
                            LicenseItem::Other { lic_ref, .. } => {
                                log::warn!("non-regular SPDX license id {lic_ref} found in {name}, these are not supported at this time");
                            }
                        }
                    }
                    match &nfo.source {
                        LicenseExprSource::Metadata => {
                            let contents = format!("\
                        This notice is automatically generated by cargo-deny {version}. If you've found an inaccuracy in it please\r\n\
                        file a bug at https://github.com/EmbarkStudios/cargo-deny/issues\r\n\
                        \r\n\
                        This software makes use of the Rust crate \"{name}\" which had the following license descriptor\r\n\
                        attached.\r\n\
                        \r\n\
                        {spdx}\r\n\
                        \r\n\
                        Below is a reproduction of the license(s) associated with this descriptor.\r\n\
                        \r\n\
                        {licenses}\
                        ");
                            fs::write(krate_path.join("crate-license.txt"), contents)
                                .with_context(|| {
                                    format!("failed to write crate license data for {}", name)
                                })?;
                            keep_folder = true;
                        }
                        LicenseExprSource::LicenseFiles => {
                            // Do nothing, this is covered by the prior for loop
                        }
                        LicenseExprSource::OverlayOverride | LicenseExprSource::UserOverride => {
                            log::warn!("crate {name} had a manually overridden license. This command will not emit license notices for overrides.");
                        }
                    }
                }
                LicenseInfo::Unlicensed => {
                    log::warn!("crate {name} was unlicensed. This command will not emit license notices for unlicensed crates.");
                }
            }
            if !keep_folder {
                if let Err(e) = fs::remove_dir(krate_path) {
                    log::error!("failed to remove empty folder for {name} {e:?}");
                }
            }
        }
    }
    std::process::exit(exit_code);
}
