use crate::{
    diag::{self, CargoSpans, ErrorSink, Files, KrateSpans, PackChannel},
    CheckCtx,
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
    C: serde::de::DeserializeOwned,
{
    pub fn new(config: impl Into<String>) -> Self {
        let config = config.into();
        Self {
            deserialized: toml::from_str(&config).expect("failed to deserialize test config"),
            config,
        }
    }
}

impl<'s, C> From<&'s str> for Config<C>
where
    C: serde::de::DeserializeOwned + Default,
{
    fn from(s: &'s str) -> Self {
        Self::new(s)
    }
}

impl<C> From<String> for Config<C>
where
    C: serde::de::DeserializeOwned + Default,
{
    fn from(s: String) -> Self {
        Self::new(s)
    }
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
    R: FnOnce(CheckCtx<'_, VC>, CargoSpans, PackChannel) + Send,
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
    R: FnOnce(CheckCtx<'_, VC>, CargoSpans, PackChannel) + Send,
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
            };
            runner(ctx, newmap, tx);
        },
        || {
            let mut diagnostics = Vec::new();

            const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

            let trx = crossbeam::channel::after(TIMEOUT);
            loop {
                crossbeam::select! {
                    recv(rx) -> msg => {
                        if let Ok(pack) = msg {
                            diagnostics.extend(pack.into_iter().map(|d| diag::diag_to_json(d, &files, Some(&grapher))));
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

    gathered.unwrap()
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

// #[inline]
// pub fn gather_bans(
//     name: &str,
//     kg: KrateGather<'_>,
//     cfg: impl Into<Config<crate::bans::cfg::Config>>,
// ) -> Vec<serde_json::Value> {
//     let krates = kg.gather();
//     let cfg = cfg.into();

//     gather_diagnostics::<crate::bans::cfg::Config, _, _>(&krates, name, cfg, |ctx, cs, tx| {
//         crate::bans::check(ctx, None, cs, tx);
//     })
// }

// #[inline]
// pub fn gather_bans_with_overrides(
//     name: &str,
//     kg: KrateGather<'_>,
//     cfg: impl Into<Config<crate::bans::cfg::Config>>,
//     overrides: diag::DiagnosticOverrides,
// ) -> Vec<serde_json::Value> {
//     let krates = kg.gather();
//     let cfg = cfg.into();

//     gather_diagnostics::<crate::bans::cfg::Config, _, _>(&krates, name, cfg, |ctx, cs, tx| {
//         crate::bans::check(
//             ctx,
//             None,
//             cs,
//             ErrorSink {
//                 overrides: Some(std::sync::Arc::new(overrides)),
//                 channel: tx,
//             },
//         );
//     })
// }
