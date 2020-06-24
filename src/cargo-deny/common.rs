use std::path::PathBuf;

use cargo_deny::licenses::LicenseStore;

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
    id: codespan::FileId,
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
}

impl KrateContext {
    pub fn get_config_path(&self, config_path: Option<PathBuf>) -> Option<PathBuf> {
        match config_path {
            Some(cp) => {
                if cp.is_absolute() {
                    Some(cp)
                } else {
                    Some(self.manifest_path.parent().unwrap().join(cp))
                }
            }
            None => {
                let mut p = self.manifest_path.parent();

                while let Some(parent) = p {
                    let config_path = parent.join("deny.toml");

                    if config_path.exists() {
                        return Some(config_path);
                    }

                    p = parent.parent();
                }

                None
            }
        }
    }

    pub fn gather_krates(
        self,
        cfg_targets: Vec<(krates::Target, Vec<String>)>,
    ) -> Result<cargo_deny::Krates, anyhow::Error> {
        log::info!("gathering crates for {}", self.manifest_path.display());
        let start = std::time::Instant::now();

        let mut mdc = krates::Cmd::new();

        mdc.all_features();
        mdc.manifest_path(self.manifest_path);

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

        if !self.exclude.is_empty() {
            gb.exclude(
                self.exclude
                    .into_iter()
                    .filter_map(|spec| match spec.parse() {
                        Ok(spec) => Some(spec),
                        Err(e) => {
                            log::warn!("invalid pkg spec '{}': {}", spec, e);
                            None
                        }
                    }),
            );
        }

        let graph = gb.build(mdc, |filtered: krates::cm::Package| match filtered.source {
            Some(src) => {
                if src.is_crates_io() {
                    log::debug!("filtered {} {}", filtered.name, filtered.version);
                } else {
                    log::debug!("filtered {} {} {}", filtered.name, filtered.version, src);
                }
            }
            None => log::debug!("filtered {} {}", filtered.name, filtered.version),
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

pub fn log_level_to_severity(log_level: log::LevelFilter) -> Option<Severity> {
    match log_level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Error => Some(Severity::Error),
        log::LevelFilter::Warn => Some(Severity::Warning),
        log::LevelFilter::Info => Some(Severity::Note),
        log::LevelFilter::Debug => Some(Severity::Help),
        log::LevelFilter::Trace => Some(Severity::Help),
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

use cargo_deny::diag;
use codespan_reporting::diagnostic::{Diagnostic as cs_diag, Severity};

type CSDiag = cs_diag<codespan::FileId>;

pub struct Human<'a> {
    stream: term::termcolor::StandardStream,
    grapher: Option<diag::TextGrapher<'a>>,
    config: codespan_reporting::term::Config,
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
    fn diag_to_json(diag: CSDiag, files: &codespan::Files<String>) -> serde_json::Value {
        let mut val = serde_json::json!({
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
            let obj = val.as_object_mut().unwrap();
            let obj = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

            if let Some(code) = diag.code {
                obj.insert("code".to_owned(), serde_json::Value::String(code));
            }

            if !diag.labels.is_empty() {
                let mut labels = Vec::with_capacity(diag.labels.len());

                for label in diag.labels {
                    let location = files
                        .location(label.file_id, label.range.start as u32)
                        .unwrap();
                    labels.push(serde_json::json!({
                        "message": label.message,
                        "span": &files.source(label.file_id)[label.range],
                        "line": location.line.to_usize() + 1,
                        "column": location.column.to_usize() + 1,
                    }));
                }

                obj.insert("labels".to_owned(), serde_json::Value::Array(labels));
            }

            if !diag.notes.is_empty() {
                obj.insert(
                    "notes".to_owned(),
                    serde_json::Value::Array(
                        diag.notes
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
        }

        val
    }

    pub fn print(&mut self, diag: CSDiag, files: &codespan::Files<String>) {
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

                let to_print = Self::diag_to_json(diag, files);

                use serde::Serialize;

                let mut ser = serde_json::Serializer::new(w);
                if to_print.serialize(&mut ser).is_ok() {
                    let w = ser.into_inner();
                    let _ = w.write(b"\n");
                }
            }
        }
    }

    pub fn print_krate_diag(
        &mut self,
        mut diag: cargo_deny::diag::Diag,
        files: &codespan::Files<String>,
    ) {
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

                let mut to_print = Self::diag_to_json(diag.diag, files);

                if let Some(grapher) = &cfg.grapher {
                    let mut graphs = Vec::new();
                    for kid in diag.kids {
                        if let Ok(graph) = grapher.write_graph(&kid) {
                            if let Ok(sgraph) = serde_json::value::to_value(graph) {
                                graphs.push(sgraph);
                            }
                        }
                    }

                    let obj = to_print.as_object_mut().unwrap();
                    obj.insert("graphs".to_owned(), serde_json::Value::Array(graphs));
                }

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

pub struct DiagPrinter<'a> {
    which: OutputFormat<'a>,
    max_severity: Severity,
}

impl<'a> DiagPrinter<'a> {
    pub fn new(
        format: crate::Format,
        color: crate::Color,
        krates: Option<&'a cargo_deny::Krates>,
        max_severity: Severity,
    ) -> Self {
        match format {
            crate::Format::Human => {
                let stream = term::termcolor::StandardStream::stderr(color_to_choice(
                    color,
                    atty::Stream::Stderr,
                ));

                Self {
                    which: OutputFormat::Human(Human {
                        stream,
                        grapher: krates.map(diag::TextGrapher::new),
                        config: codespan_reporting::term::Config::default(),
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
        }
    }

    #[inline]
    pub fn lock(&'a self) -> OutputLock<'a, '_> {
        self.which.lock(self.max_severity)
    }
}
