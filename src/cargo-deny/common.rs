use cargo_deny::{
    diag::{self, FileId, Files, Severity},
    licenses::LicenseStore,
    PathBuf,
};

pub(crate) fn load_license_store() -> Result<LicenseStore, anyhow::Error> {
    log::debug!("loading license store...");
    LicenseStore::from_cache()
}

#[derive(serde::Deserialize)]
pub(crate) struct Target {
    pub(crate) triple: cargo_deny::Spanned<String>,
    #[serde(default)]
    pub(crate) features: Vec<String>,
}

use cargo_deny::diag::Diagnostic;

pub(crate) fn load_targets(
    in_targets: Vec<Target>,
    diagnostics: &mut Vec<Diagnostic>,
    id: FileId,
) -> Vec<(krates::Target, Vec<String>)> {
    let mut targets = Vec::with_capacity(in_targets.len());
    for target in in_targets {
        let triple = target.triple.as_ref();

        let filter: krates::Target = triple.into();

        if let krates::Target::Unknown(_) = &filter {
            diagnostics.push(
                    Diagnostic::warning()
                        .with_message(format!("unknown target `{triple}` specified"))
                        .with_labels(vec![
                    cargo_deny::diag::Label::primary(
                        id,
                        target.triple.span().clone()).with_message(
                        "the triple won't be evaluated against cfg() sections, just explicit triples"),
                    ]),
                );
        }

        targets.push((filter, target.features));
    }

    targets
}

pub struct KrateContext {
    pub manifest_path: PathBuf,
    pub workspace: bool,
    pub exclude: Vec<String>,
    pub targets: Vec<String>,
    pub no_default_features: bool,
    pub all_features: bool,
    pub features: Vec<String>,
    pub frozen: bool,
    pub locked: bool,
    pub offline: bool,
    /// If true, allows using the crates.io git index, otherwise the sparse index
    /// is assumed to be the only index
    pub allow_git_index: bool,
}

impl KrateContext {
    pub fn get_config_path(&self, config_path: Option<PathBuf>) -> Option<PathBuf> {
        if let Some(cp) = config_path {
            if cp.is_absolute() {
                Some(cp)
            } else {
                Some(self.manifest_path.parent().unwrap().join(cp))
            }
        } else {
            let mut p = self.manifest_path.parent();

            while let Some(parent) = p {
                let mut config_path = parent.join("deny.toml");

                if config_path.exists() {
                    return Some(config_path);
                }

                config_path.pop();
                config_path.push(".deny.toml");

                if config_path.exists() {
                    return Some(config_path);
                }

                config_path.pop();
                config_path.push(".cargo/deny.toml");
                if config_path.exists() {
                    return Some(config_path);
                }

                p = parent.parent();
            }

            None
        }
    }

    pub fn get_local_exceptions_path(&self) -> Option<PathBuf> {
        let mut p = self.manifest_path.parent();

        while let Some(parent) = p {
            let mut config_path = parent.join("deny.exceptions.toml");

            if config_path.exists() {
                return Some(config_path);
            }

            config_path.pop();
            config_path.push(".deny.exceptions.toml");

            if config_path.exists() {
                return Some(config_path);
            }

            config_path.pop();
            config_path.push(".cargo/deny.exceptions.toml");
            if config_path.exists() {
                return Some(config_path);
            }

            p = parent.parent();
        }

        None
    }

    #[inline]
    pub fn fetch_krates(&self) -> anyhow::Result<()> {
        fetch(MetadataOptions {
            no_default_features: false,
            all_features: false,
            features: Vec::new(),
            manifest_path: self.manifest_path.clone(),
            frozen: self.frozen,
            locked: self.locked,
            offline: self.offline,
        })
    }

    pub fn gather_krates(
        self,
        cfg_targets: Vec<(krates::Target, Vec<String>)>,
        cfg_excludes: Vec<String>,
    ) -> Result<cargo_deny::Krates, anyhow::Error> {
        log::info!("gathering crates for {}", self.manifest_path);
        let start = std::time::Instant::now();

        log::debug!("gathering crate metadata");
        let metadata = Self::get_metadata(MetadataOptions {
            no_default_features: self.no_default_features,
            all_features: self.all_features,
            features: self.features,
            manifest_path: self.manifest_path,
            frozen: self.frozen,
            locked: self.locked,
            offline: self.offline,
        })?;
        log::debug!(
            "gathered crate metadata in {}ms",
            start.elapsed().as_millis()
        );

        use krates::{Builder, DepKind};

        let mut gb = Builder::new();

        // Use targets passed on the command line first, and fallback to config
        // based targets otherwise
        if !self.targets.is_empty() {
            gb.include_targets(self.targets.into_iter().map(|t| (t, Vec::new())));
        } else if !cfg_targets.is_empty() {
            gb.include_targets(cfg_targets);
        }

        let scope = krates::Scope::NonWorkspace; // krates::Scope::All
        gb.ignore_kind(DepKind::Dev, scope);
        gb.workspace(self.workspace);

        if !self.exclude.is_empty() || !cfg_excludes.is_empty() {
            gb.exclude(
                self.exclude
                    .into_iter()
                    .chain(cfg_excludes)
                    .filter_map(|spec| match spec.parse() {
                        Ok(spec) => Some(spec),
                        Err(err) => {
                            log::warn!("invalid pkg spec '{spec}': {err}");
                            None
                        }
                    }),
            );
        }

        // Attempt to open the crates.io index so that the feature sets for every
        // crate in the graph are correct, however, don't consider it a hard failure
        // if we can't for some reason, as the graph will _probably_ still be accurate
        // as incorrect feature sets are not the norm by any means
        // see https://github.com/rust-lang/cargo/issues/11319 for an example of
        // what this can look like in practice if we don't have the index metadata
        // to supplement/fix the cargo metadata
        if let Err(err) = cargo_deny::krates_with_index(&mut gb, None, None) {
            log::error!("failed to open the local crates.io index, feature sets for crates may not be correct: {err}");
        }

        let graph = gb.build_with_metadata(metadata, |filtered: krates::cm::Package| {
            let name = filtered.name;
            let vers = filtered.version;

            if let Some(src) = filtered.source.filter(|src| !src.is_crates_io()) {
                log::debug!("filtered {name} {vers} {src}");
            } else {
                log::debug!("filtered {name} {vers}");
            }
        });

        if let Ok(krates) = &graph {
            log::info!(
                "gathered {} crates in {}ms",
                krates.len(),
                start.elapsed().as_millis()
            );
        }

        Ok(graph?)
    }

    #[cfg(not(feature = "standalone"))]
    fn get_metadata(opts: MetadataOptions) -> Result<krates::cm::Metadata, anyhow::Error> {
        let mut mdc = krates::Cmd::new();

        if opts.no_default_features {
            mdc.no_default_features();
        }

        if opts.all_features {
            mdc.all_features();
        }

        mdc.features(opts.features)
            .manifest_path(opts.manifest_path)
            .lock_opts(krates::LockOptions {
                frozen: opts.frozen,
                locked: opts.locked,
                offline: opts.offline,
            });

        let mdc: krates::cm::MetadataCommand = mdc.into();
        Ok(mdc.exec()?)
    }

    #[cfg(feature = "standalone")]
    fn get_metadata(opts: MetadataOptions) -> Result<krates::cm::Metadata, anyhow::Error> {
        use anyhow::Context as _;
        use cargo::{core, ops, util};

        let mut config = util::Config::default()?;

        config.configure(
            0,
            true,
            None,
            opts.frozen,
            opts.locked,
            opts.offline,
            &None,
            &[],
            &[],
        )?;

        let mut manifest_path = opts.manifest_path;

        // Cargo doesn't like non-absolute paths
        if !manifest_path.is_absolute() {
            manifest_path = cargo_deny::utf8path(
                std::env::current_dir()
                    .context("unable to determine current directory")?
                    .join(manifest_path),
            )?;
        }

        let features = std::rc::Rc::new(
            opts.features
                .into_iter()
                .map(|feat| core::FeatureValue::new(util::interning::InternedString::new(&feat)))
                .collect(),
        );

        let ws = core::Workspace::new(manifest_path.as_std_path(), &config)?;
        let options = ops::OutputMetadataOptions {
            cli_features: core::resolver::features::CliFeatures {
                features,
                all_features: opts.all_features,
                uses_default_features: !opts.no_default_features,
            },
            no_deps: false,
            version: 1,
            filter_platforms: vec![],
        };

        let md = ops::output_metadata(&ws, &options)?;
        let md_value = serde_json::to_value(md)?;

        Ok(serde_json::from_value(md_value)?)
    }
}

struct MetadataOptions {
    no_default_features: bool,
    all_features: bool,
    features: Vec<String>,
    manifest_path: PathBuf,
    frozen: bool,
    locked: bool,
    offline: bool,
}

#[cfg(not(feature = "standalone"))]
fn fetch(opts: MetadataOptions) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let mut cargo =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_ve| "cargo".to_owned()));

    cargo.arg("fetch");
    cargo.arg("--manifest-path");
    cargo.arg(&opts.manifest_path);
    if opts.frozen {
        cargo.arg("--frozen");
    }

    if opts.locked {
        cargo.arg("--locked");
    }

    if opts.offline {
        cargo.arg("--offline");
    }

    cargo.stderr(std::process::Stdio::piped());
    let output = cargo.output().context("failed to run cargo")?;
    if output.status.success() {
        Ok(())
    } else {
        anyhow::bail!(String::from_utf8(output.stderr).context("non-utf8 error output")?);
    }
}

#[cfg(feature = "standalone")]
fn fetch(opts: MetadataOptions) -> anyhow::Result<()> {
    use anyhow::Context;
    use cargo::{core, ops, util};

    let mut config = util::Config::default()?;

    config.configure(
        0,
        true,
        None,
        opts.frozen,
        opts.locked,
        opts.offline,
        &None,
        &[],
        &[],
    )?;

    let mut manifest_path = opts.manifest_path;

    // Cargo doesn't like non-absolute paths
    if !manifest_path.is_absolute() {
        manifest_path = cargo_deny::utf8path(
            std::env::current_dir()
                .context("unable to determine current directory")?
                .join(manifest_path),
        )?;
    }

    let ws = core::Workspace::new(manifest_path.as_std_path(), &config)?;
    let options = ops::FetchOptions {
        config: &config,
        targets: Vec::new(),
    };
    ops::fetch(&ws, &options)?;
    Ok(())
}

#[inline]
pub fn log_level_to_severity(log_level: log::LevelFilter) -> Option<Severity> {
    match log_level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Error => Some(Severity::Error),
        log::LevelFilter::Warn => Some(Severity::Warning),
        log::LevelFilter::Info => Some(Severity::Note),
        log::LevelFilter::Debug | log::LevelFilter::Trace => Some(Severity::Help),
    }
}

use codespan_reporting::term::{self, termcolor::ColorChoice};
use std::io::Write;

fn color_to_choice(color: crate::Color, stream: impl std::io::IsTerminal) -> ColorChoice {
    match color {
        crate::Color::Auto => {
            // The termcolor crate doesn't check the stream to see if it's a TTY
            // which doesn't really fit with how the rest of the coloring works
            if stream.is_terminal() {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        crate::Color::Always => ColorChoice::Always,
        crate::Color::Never => ColorChoice::Never,
    }
}

#[inline]
pub fn should_colorize(color: crate::Color, stream: impl std::io::IsTerminal) -> bool {
    match color {
        crate::Color::Auto => stream.is_terminal(),
        crate::Color::Always => true,
        crate::Color::Never => false,
    }
}

type CsDiag = codespan_reporting::diagnostic::Diagnostic<FileId>;

pub struct Human<'a> {
    stream: term::termcolor::StandardStream,
    grapher: Option<diag::InclusionGrapher<'a>>,
    config: term::Config,
    feature_depth: Option<u32>,
}

pub enum StdioStream {
    //Out(std::io::Stdout),
    Err(std::io::Stderr),
}

impl StdioStream {
    pub fn lock(&self) -> StdLock<'_> {
        match self {
            //Self::Out(o) => StdLock::Out(o.lock()),
            Self::Err(o) => StdLock::Err(o.lock()),
        }
    }
}

pub struct Json<'a> {
    stream: StdioStream,
    grapher: Option<diag::InclusionGrapher<'a>>,
}

#[allow(clippy::large_enum_variant)]
enum OutputFormat<'a> {
    Human(Human<'a>),
    Json(Json<'a>),
}

impl<'a> OutputFormat<'a> {
    fn lock(&'a self, max_severity: Severity) -> OutputLock<'a, '_> {
        match self {
            Self::Human(human) => OutputLock::Human(
                human,
                max_severity,
                human.stream.lock(),
                human.feature_depth,
            ),
            Self::Json(json) => OutputLock::Json(json, max_severity, json.stream.lock()),
        }
    }
}

pub enum StdLock<'a> {
    Err(std::io::StderrLock<'a>),
    //Out(std::io::StdoutLock<'a>),
}

impl<'a> Write for StdLock<'a> {
    fn write(&mut self, d: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Err(stderr) => stderr.write(d),
            //Self::Out(stdout) => stdout.write(d),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Err(stderr) => stderr.flush(),
            //Self::Out(stdout) => stdout.flush(),
        }
    }
}

pub enum OutputLock<'a, 'b> {
    Human(
        &'a Human<'a>,
        Severity,
        term::termcolor::StandardStreamLock<'b>,
        Option<u32>,
    ),
    Json(&'a Json<'a>, Severity, StdLock<'b>),
}

impl<'a, 'b> OutputLock<'a, 'b> {
    pub fn print(&mut self, diag: CsDiag, files: &Files) {
        match self {
            Self::Human(cfg, max, l, _) => {
                if diag.severity < *max {
                    return;
                }

                let _ = term::emit(l, &cfg.config, files, &diag);
            }
            Self::Json(_cfg, max, w) => {
                if diag.severity < *max {
                    return;
                }

                let to_print = diag::cs_diag_to_json(diag, files);

                use serde::Serialize;

                let mut ser = serde_json::Serializer::new(w);
                if to_print.serialize(&mut ser).is_ok() {
                    let w = ser.into_inner();
                    let _ = w.write(b"\n");
                }
            }
        }
    }

    pub fn print_krate_pack(&mut self, pack: cargo_deny::diag::Pack, files: &Files) {
        let mut emitted = std::collections::BTreeSet::new();

        match self {
            Self::Human(cfg, max, l, fd) => {
                for mut diag in pack {
                    if diag.diag.severity < *max {
                        continue;
                    }

                    if let Some(grapher) = &cfg.grapher {
                        for gn in diag.graph_nodes {
                            if emitted.contains(&gn.kid) {
                                let krate =
                                    &grapher.krates[grapher.krates.nid_for_kid(&gn.kid).unwrap()];
                                diag.diag
                                    .notes
                                    .push(format!("{} v{} (*)", krate.name, krate.version));
                            } else if let Ok(graph) = grapher.build_graph(
                                &gn,
                                if diag.with_features {
                                    fd.unwrap_or(1) as usize
                                } else {
                                    0
                                },
                            ) {
                                let graph_text = diag::write_graph_as_text(&graph);
                                diag.diag.notes.push(graph_text);
                                emitted.insert(gn.kid);
                            }
                        }
                    }

                    let _ = term::emit(l, &cfg.config, files, &diag.diag);
                }
            }
            Self::Json(cfg, max, w) => {
                for diag in pack {
                    if diag.diag.severity < *max {
                        continue;
                    }

                    let to_print = diag::diag_to_json(diag, files, cfg.grapher.as_ref());

                    use serde::Serialize;

                    let mut ser = serde_json::Serializer::new(&mut *w);
                    if to_print.serialize(&mut ser).is_ok() {
                        let w = ser.into_inner();
                        let _ = w.write(b"\n");
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct LogContext {
    pub format: crate::Format,
    pub color: crate::Color,
    pub log_level: log::LevelFilter,
}

pub struct DiagPrinter<'a> {
    which: OutputFormat<'a>,
    max_severity: Severity,
}

impl<'a> DiagPrinter<'a> {
    pub fn new(
        ctx: LogContext,
        krates: Option<&'a cargo_deny::Krates>,
        feature_depth: Option<u32>,
    ) -> Option<Self> {
        let max_severity = log_level_to_severity(ctx.log_level);

        max_severity.map(|max_severity| match ctx.format {
            crate::Format::Human => {
                let stream = term::termcolor::StandardStream::stderr(color_to_choice(
                    ctx.color,
                    std::io::stderr(),
                ));

                Self {
                    which: OutputFormat::Human(Human {
                        stream,
                        grapher: krates.map(diag::InclusionGrapher::new),
                        config: term::Config::default(),
                        feature_depth,
                    }),
                    max_severity,
                }
            }
            crate::Format::Json => Self {
                which: OutputFormat::Json(Json {
                    stream: StdioStream::Err(std::io::stderr()),
                    grapher: krates.map(diag::InclusionGrapher::new),
                }),
                max_severity,
            },
        })
    }

    #[inline]
    pub fn lock(&'a self) -> OutputLock<'a, '_> {
        self.which.lock(self.max_severity)
    }
}
