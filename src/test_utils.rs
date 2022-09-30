use crate::{
    diag::{self, CargoSpans, ErrorSink, Files, KrateSpans},
    CheckCtx,
};
use anyhow::Context as _;

#[derive(Default)]
pub struct KrateGather<'k> {
    pub name: &'k str,
    pub features: &'k [&'k str],
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
}

pub enum KratesSrc {
    Provided(crate::Krates),
    Cmd(krates::Cmd),
}

impl From<crate::Krates> for KratesSrc {
    fn from(krates: crate::Krates) -> Self {
        Self::Provided(krates)
    }
}

impl<'k> From<KrateGather<'k>> for KratesSrc {
    fn from(kg: KrateGather<'k>) -> Self {
        let mut project_dir = std::path::PathBuf::from("./tests/test_data");
        project_dir.push(kg.name);

        let mut cmd = krates::Cmd::new();
        cmd.current_dir(project_dir);

        if kg.all_features {
            cmd.all_features();
        }

        if kg.no_default_features {
            cmd.no_default_features();
        }

        if !kg.features.is_empty() {
            cmd.features(kg.features.iter().map(|f| (*f).to_owned()));
        }

        Self::Cmd(cmd)
    }
}

pub fn gather_diagnostics<C, VC, R>(
    cmd: impl Into<KratesSrc>,
    test_name: &str,
    cfg: Option<&str>,
    targets: Option<&[&str]>,
    runner: R,
) -> anyhow::Result<Vec<serde_json::Value>>
where
    C: serde::de::DeserializeOwned + Default + crate::UnvalidatedConfig<ValidCfg = VC>,
    VC: Send,
    R: FnOnce(CheckCtx<'_, VC>, CargoSpans, ErrorSink) + Send,
{
    let cmd = cmd.into();

    let krates = match cmd {
        KratesSrc::Provided(krates) => krates,
        KratesSrc::Cmd(cmd) => {
            let mut kb = krates::Builder::new();

            if let Some(targets) = targets {
                kb.include_targets(targets.iter().map(|t| (t, vec![])));
            }

            kb.build(cmd, krates::NoneFilter)
                .context("failed to build crate graph")?
        }
    };

    let (spans, content, hashmap) = KrateSpans::synthesize(&krates);
    let mut files = Files::new();

    let spans_id = files.add(format!("{test_name}/Cargo.lock"), content);

    let spans = KrateSpans::with_spans(spans, spans_id);

    let (config, cfg_id) = match cfg {
        Some(cfg) => {
            let config: C = toml::from_str(cfg).context("failed to deserialize test config")?;

            let cfg_id = files.add(format!("{test_name}.toml"), cfg.to_owned());

            (config, cfg_id)
        }
        None => (
            C::default(),
            files.add(format!("{test_name}.toml"), "".to_owned()),
        ),
    };

    let mut newmap = CargoSpans::new();
    for (key, val) in hashmap {
        let cargo_id = files.add(val.0, val.1);
        newmap.insert(key, (cargo_id, val.2));
    }

    let mut cfg_diags = Vec::new();
    let cfg = config.validate(cfg_id, &mut cfg_diags);

    if cfg_diags
        .iter()
        .any(|d| d.severity >= crate::diag::Severity::Error)
    {
        anyhow::bail!("encountered errors validating config: {cfg_diags:#?}");
    }

    let (tx, rx) = crossbeam::channel::unbounded();

    let grapher = diag::InclusionGrapher::new(&krates);

    let (_, gathered) = rayon::join(
        || {
            let ctx = crate::CheckCtx {
                krates: &krates,
                krate_spans: &spans,
                cfg,
                serialize_extra: true,
                colorize: false,
            };
            runner(ctx, newmap, ErrorSink::Channel(tx));
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

    gathered
}

#[inline]
pub fn to_snapshot(diags: Vec<serde_json::Value>) -> String {
    serde_json::to_string_pretty(&diags).unwrap()
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
