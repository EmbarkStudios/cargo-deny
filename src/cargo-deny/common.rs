use std::path::PathBuf;

use cargo_deny::{
    diag::{self, FileId, Files, Severity},
    licenses::LicenseStore,
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
                        .with_message(format!("unknown target `{}` specified", triple))
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

                p = parent.parent();
            }

            None
        }
    }

    pub fn gather_krates(
        self,
        cfg_targets: Vec<(krates::Target, Vec<String>)>,
        cfg_excludes: Vec<String>,
    ) -> Result<cargo_deny::Krates, anyhow::Error> {
        log::info!("gathering crates for {}", self.manifest_path.display());
        let start = std::time::Instant::now();

        let metadata = get_metadata(MetadataOptions {
            no_default_features: self.no_default_features,
            all_features: self.all_features,
            features: self.features,
            manifest_path: self.manifest_path,
            frozen: self.frozen,
            locked: self.locked,
            offline: self.offline,
        })?;

        use krates::{Builder, DepKind};

        let mut gb = Builder::new();

        // Use targets passed on the command line first, and fallback to config
        // based targets otherwise
        if !self.targets.is_empty() {
            gb.include_targets(self.targets.into_iter().map(|t| (t, Vec::new())));
        } else if !cfg_targets.is_empty() {
            gb.include_targets(cfg_targets);
        }

        gb.ignore_kind(DepKind::Dev, krates::Scope::NonWorkspace);
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

        let graph = gb.build_with_metadata(metadata, |filtered: krates::cm::Package| {
            let name = filtered.name;
            let vers = filtered.version;

            if let Some(src) = filtered.source.filter(|src| !src.is_crates_io()) {
                log::debug!("filtered {name} {vers} {src}");
            } else {
                log::debug!("filtered {name} {vers}");
            }
        });

        if let Ok(ref krates) = graph {
            let end = std::time::Instant::now();
            log::info!(
                "gathered {} crates in {}ms",
                krates.len(),
                (end - start).as_millis()
            );
        }

        Ok(graph?)
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
        manifest_path = std::env::current_dir()
            .context("unable to determine current directory")?
            .join(manifest_path);
    }

    let features = std::rc::Rc::new(
        opts.features
            .into_iter()
            .map(|feat| core::FeatureValue::new(util::interning::InternedString::new(&feat)))
            .collect(),
    );

    let ws = core::Workspace::new(&manifest_path, &config)?;
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

fn color_to_choice(color: crate::Color, stream: atty::Stream) -> ColorChoice {
    match color {
        crate::Color::Auto => {
            // The termcolor crate doesn't check the stream to see if it's a TTY
            // which doesn't really fit with how the rest of the coloring works
            if atty::is(stream) {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        crate::Color::Always => ColorChoice::Always,
        crate::Color::Never => ColorChoice::Never,
    }
}

type CsDiag = codespan_reporting::diagnostic::Diagnostic<FileId>;

pub struct Human<'a> {
    stream: term::termcolor::StandardStream,
    grapher: Option<diag::TextGrapher<'a>>,
    config: term::Config,
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
    grapher: Option<diag::ObjectGrapher<'a>>,
}

#[allow(clippy::large_enum_variant)]
enum OutputFormat<'a> {
    Human(Human<'a>),
    Json(Json<'a>),
}

impl<'a> OutputFormat<'a> {
    fn lock(&'a self, max_severity: Severity) -> OutputLock<'a, '_> {
        match self {
            Self::Human(ref human) => OutputLock::Human(human, max_severity, human.stream.lock()),
            Self::Json(ref json) => OutputLock::Json(json, max_severity, json.stream.lock()),
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
    ),
    Json(&'a Json<'a>, Severity, StdLock<'b>),
}

impl<'a, 'b> OutputLock<'a, 'b> {
    pub fn print(&mut self, diag: CsDiag, files: &Files) {
        match self {
            Self::Human(cfg, max, l) => {
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

    pub fn print_krate_diag(&mut self, mut diag: cargo_deny::diag::Diag, files: &Files) {
        match self {
            Self::Human(cfg, max, l) => {
                if diag.diag.severity < *max {
                    return;
                }

                if let Some(grapher) = &cfg.grapher {
                    for kid in diag.kids {
                        if let Ok(graph) = grapher.write_graph(&kid) {
                            diag.diag.notes.push(graph);
                        }
                    }
                }

                let _ = term::emit(l, &cfg.config, files, &diag.diag);
            }
            Self::Json(cfg, max, w) => {
                if diag.diag.severity < *max {
                    return;
                }

                let to_print = diag::diag_to_json(diag, files, cfg.grapher.as_ref());

                use serde::Serialize;

                let mut ser = serde_json::Serializer::new(w);
                if to_print.serialize(&mut ser).is_ok() {
                    let w = ser.into_inner();
                    let _ = w.write(b"\n");
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
    pub fn new(ctx: LogContext, krates: Option<&'a cargo_deny::Krates>) -> Option<Self> {
        let max_severity = log_level_to_severity(ctx.log_level);

        max_severity.map(|max_severity| match ctx.format {
            crate::Format::Human => {
                let stream = term::termcolor::StandardStream::stderr(color_to_choice(
                    ctx.color,
                    atty::Stream::Stderr,
                ));

                Self {
                    which: OutputFormat::Human(Human {
                        stream,
                        grapher: krates.map(diag::TextGrapher::new),
                        config: term::Config::default(),
                    }),
                    max_severity,
                }
            }
            crate::Format::Json => Self {
                which: OutputFormat::Json(Json {
                    stream: StdioStream::Err(std::io::stderr()),
                    grapher: krates.map(diag::ObjectGrapher::new),
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
