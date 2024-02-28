use crate::{
    cfg::ValidationContext,
    diag::{self, CargoSpans, ErrorSink, FileId, Files, KrateSpans, PackChannel},
    CheckCtx, PathBuf,
};

#[derive(Default, Clone)]
pub struct KrateGather<'k> {
    pub name: &'k str,
    pub features: &'k [&'k str],
    pub targets: &'k [&'k str],
    pub all_features: bool,
    pub no_default_features: bool,
}

impl<'k> KrateGather<'k> {
    pub fn new(name: &'k str) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    pub fn gather(self) -> crate::Krates {
        let mut project_dir = crate::PathBuf::from("./tests/test_data");
        project_dir.push(self.name);

        let mut cmd = krates::Cmd::new();
        cmd.current_dir(project_dir);

        if self.all_features {
            cmd.all_features();
        }

        if self.no_default_features {
            cmd.no_default_features();
        }

        if !self.features.is_empty() {
            cmd.features(self.features.iter().map(|f| (*f).to_owned()));
        }

        let mut kb = krates::Builder::new();

        if !self.targets.is_empty() {
            kb.include_targets(self.targets.iter().map(|t| (t, vec![])));
        }

        kb.build(cmd, krates::NoneFilter)
            .expect("failed to build crate graph")
    }
}

pub struct Config<C> {
    pub deserialized: C,
    pub config: String,
}

impl<C> Default for Config<C>
where
    C: Default,
{
    fn default() -> Self {
        Self {
            deserialized: C::default(),
            config: "".to_owned(),
        }
    }
}

impl<C> Config<C>
where
    C: toml_span::DeserializeOwned,
{
    pub fn new(config: impl Into<String>) -> Self {
        let config = config.into();
        let mut val = toml_span::parse(&config).expect("failed to parse test config");
        let deserialized = C::deserialize(&mut val).expect("failed to deserialize test config");
        Self {
            deserialized,
            config,
        }
    }
}

impl<'de, C> From<&'de str> for Config<C>
where
    C: toml_span::DeserializeOwned,
{
    fn from(s: &'de str) -> Self {
        Self::new(s)
    }
}

impl<C> From<String> for Config<C>
where
    C: toml_span::DeserializeOwned + Default,
{
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

pub struct ConfigData<T> {
    pub config: T,
    pub files: Files,
    pub id: FileId,
}

impl<T> ConfigData<T> {
    pub fn file(&self) -> &str {
        self.files.source(self.id)
    }
}

impl<T> ConfigData<T>
where
    T: toml_span::DeserializeOwned,
{
    pub fn load_str(name: impl Into<std::ffi::OsString>, contents: impl Into<String>) -> Self {
        let contents: String = contents.into();

        let res = {
            let mut cval = toml_span::parse(&contents).expect("failed to parse toml");
            T::deserialize(&mut cval)
        };

        let mut files = Files::new();
        let id = files.add(name, contents);

        let config = match res {
            Ok(v) => v,
            Err(derr) => {
                let diag_str = write_diagnostics(
                    &files,
                    derr.errors.into_iter().map(|err| err.to_diagnostic(id)),
                );
                panic!("failed to deserialize:\n---\n{diag_str}\n---");
            }
        };

        ConfigData { config, files, id }
    }

    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let contents = std::fs::read_to_string(&path).unwrap();

        Self::load_str(path, contents)
    }
}

impl<T> ConfigData<T> {
    pub fn validate<IV, V>(mut self, conv: impl FnOnce(T) -> IV) -> V
    where
        IV: super::UnvalidatedConfig<ValidCfg = V>,
    {
        let uvc = conv(self.config);

        let mut diagnostics = Vec::new();
        let vcfg = uvc.validate(ValidationContext {
            cfg_id: self.id,
            files: &mut self.files,
            diagnostics: &mut diagnostics,
        });

        if diagnostics.is_empty() {
            vcfg
        } else {
            let diag_str = write_diagnostics(&self.files, diagnostics.into_iter());

            panic!("failed to validate config:\n---\n{diag_str}\n---");
        }
    }

    pub fn validate_with_diags<IV, V>(
        mut self,
        conv: impl FnOnce(T) -> IV,
        on_diags: impl FnOnce(&Files, Vec<crate::diag::Diagnostic>),
    ) -> V
    where
        IV: super::UnvalidatedConfig<ValidCfg = V>,
    {
        let uvc = conv(self.config);

        let mut diagnostics = Vec::new();
        let vcfg = uvc.validate(ValidationContext {
            cfg_id: self.id,
            files: &mut self.files,
            diagnostics: &mut diagnostics,
        });

        on_diags(&self.files, diagnostics);
        vcfg
    }
}

pub(crate) fn write_diagnostics(
    files: &Files,
    errors: impl Iterator<Item = crate::diag::Diagnostic>,
) -> String {
    let mut s = codespan_reporting::term::termcolor::NoColor::new(Vec::new());
    let config = codespan_reporting::term::Config::default();

    for diag in errors {
        codespan_reporting::term::emit(&mut s, &config, files, &diag).unwrap();
    }

    String::from_utf8(s.into_inner()).unwrap()
}

#[inline]
pub fn gather_diagnostics<C, VC, R>(
    krates: &crate::Krates,
    test_name: &str,
    cfg: Config<C>,
    runner: R,
) -> Vec<serde_json::Value>
where
    C: crate::UnvalidatedConfig<ValidCfg = VC>,
    VC: Send,
    R: FnOnce(CheckCtx<'_, VC>, CargoSpans, PackChannel, &mut Files) + Send,
{
    gather_diagnostics_with_files(krates, test_name, cfg, Files::new(), runner)
}

pub fn gather_diagnostics_with_files<C, VC, R>(
    krates: &crate::Krates,
    test_name: &str,
    cfg: Config<C>,
    mut files: Files,
    runner: R,
) -> Vec<serde_json::Value>
where
    C: crate::UnvalidatedConfig<ValidCfg = VC>,
    VC: Send,
    R: FnOnce(CheckCtx<'_, VC>, CargoSpans, PackChannel, &mut Files) + Send,
{
    let (spans, content, hashmap) = KrateSpans::synthesize(krates);

    let spans_id = files.add(format!("{test_name}/Cargo.lock"), content);
    let spans = KrateSpans::with_spans(spans, spans_id);

    let config = cfg.deserialized;
    let cfg_id = files.add(format!("{test_name}.toml"), cfg.config);

    let mut newmap = CargoSpans::new();
    for (key, val) in hashmap {
        let cargo_id = files.add(val.0, val.1);
        newmap.insert(key, (cargo_id, val.2));
    }

    let mut cfg_diags = Vec::new();
    let cfg = config.validate(crate::cfg::ValidationContext {
        cfg_id,
        files: &mut files,
        diagnostics: &mut cfg_diags,
    });

    if cfg_diags
        .iter()
        .any(|d| d.severity >= crate::diag::Severity::Error)
    {
        panic!("encountered errors validating config: {cfg_diags:#?}");
    }

    let (tx, rx) = crossbeam::channel::unbounded();

    let grapher = diag::InclusionGrapher::new(krates);

    let (_, gathered) = rayon::join(
        || {
            let ctx = crate::CheckCtx {
                krates,
                krate_spans: &spans,
                cfg,
                serialize_extra: true,
                colorize: false,
                log_level: log::LevelFilter::Info,
            };
            runner(ctx, newmap, tx, &mut files);
        },
        || {
            let mut diagnostics = Vec::new();

            const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

            let trx = crossbeam::channel::after(TIMEOUT);
            loop {
                crossbeam::select! {
                    recv(rx) -> msg => {
                        if let Ok(pack) = msg {
                            diagnostics.extend(pack);
                        } else {
                            // Yay, the sender was dopped (i.e. check was finished)
                            break;
                        }
                    }
                    recv(trx) -> _ => {
                        anyhow::bail!("Timed out after {TIMEOUT:?}");
                    }
                }
            }

            Ok(diagnostics)
        },
    );

    gathered
        .unwrap()
        .into_iter()
        .map(|d| diag::diag_to_json(d, &files, Some(&grapher)))
        .collect()
}

#[macro_export]
macro_rules! field_eq {
    ($obj:expr, $field:expr, $expected:expr) => {
        $obj.pointer($field) == Some(&serde_json::json!($expected))
    };
}

#[macro_export]
macro_rules! assert_field_eq {
    ($obj:expr, $field:expr, $expected:expr) => {
        assert_eq!($obj.pointer($field), Some(&serde_json::json!($expected)));
    };
}

#[macro_export]
macro_rules! func_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

#[macro_export]
macro_rules! overrides {
    ($($code:expr => $severity:ident),* $(,)?) => {
        {
            let mut map = std::collections::BTreeMap::new();

            $(map.insert($code, $crate::diag::Severity::$severity);)*

            $crate::diag::DiagnosticOverrides {
                code_overrides: map,
                level_overrides: Vec::new(),
            }
        }
    }
}

#[inline]
pub fn gather_bans(
    name: &str,
    kg: KrateGather<'_>,
    cfg: impl Into<Config<crate::bans::cfg::Config>>,
) -> Vec<serde_json::Value> {
    let krates = kg.gather();
    let cfg = cfg.into();

    gather_diagnostics::<crate::bans::cfg::Config, _, _>(&krates, name, cfg, |ctx, cs, tx, _| {
        crate::bans::check(ctx, None, cs, tx);
    })
}

#[inline]
pub fn gather_bans_with_overrides(
    name: &str,
    kg: KrateGather<'_>,
    cfg: impl Into<Config<crate::bans::cfg::Config>>,
    overrides: diag::DiagnosticOverrides,
) -> Vec<serde_json::Value> {
    let krates = kg.gather();
    let cfg = cfg.into();

    gather_diagnostics::<crate::bans::cfg::Config, _, _>(&krates, name, cfg, |ctx, cs, tx, _| {
        crate::bans::check(
            ctx,
            None,
            cs,
            ErrorSink {
                overrides: Some(std::sync::Arc::new(overrides)),
                channel: tx,
            },
        );
    })
}
