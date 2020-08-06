#![allow(unused_macros, dead_code)]

use anyhow::{Context, Error};
use cargo_deny::{
    diag::{Files, KrateSpans, Pack},
    CheckCtx,
};

pub fn get_test_data_krates(name: &str) -> Result<cargo_deny::Krates, Error> {
    let project_dir = std::path::Path::new("./tests/test_data").join(name);

    let mut metadata_cmd = krates::Cmd::new();
    metadata_cmd.current_dir(&project_dir);

    krates::Builder::new()
        .build(metadata_cmd, krates::NoneFilter)
        .context("failed to build crate graph")
}

pub fn gather_diagnostics<
    C: serde::de::DeserializeOwned + Default + cargo_deny::UnvalidatedConfig<ValidCfg = VC>,
    VC: Send,
    R: FnOnce(CheckCtx<'_, VC>, crossbeam::channel::Sender<Pack>) + Send,
>(
    krates: cargo_deny::Krates,
    test_name: &str,
    cfg: Option<&str>,
    timeout: Option<std::time::Duration>,
    runner: R,
) -> Result<Vec<serde_json::Value>, Error> {
    let (spans, content, hashmap) = KrateSpans::new(&krates);
    let mut files = Files::new();
    let spans_id = files.add(format!("{}/Cargo.lock", test_name), content);

    let (config, cfg_id) = match cfg {
        Some(cfg) => {
            let config: C = toml::from_str(cfg).context("failed to deserialize test config")?;

            let cfg_id = files.add(format!("{}.toml", test_name), cfg.to_owned());

            (config, cfg_id)
        }
        None => (
            C::default(),
            files.add(format!("{}.toml", test_name), "".to_owned()),
        ),
    };

    let mut newmap = std::collections::HashMap::new();
    for (key, val) in hashmap {
        let cargo_id = files.add(val.0, val.1);
        newmap.insert(key, (cargo_id, val.2));
    }

    let cfg = config
        .validate(cfg_id)
        .map_err(|e| anyhow::anyhow!("encountered {} errors validating config", e.len()))?;

    let (tx, rx) = crossbeam::unbounded();

    let (_, gathered) = rayon::join(
        || {
            let ctx = cargo_deny::CheckCtx {
                krates: &krates,
                krate_spans: &spans,
                spans_id,
                cfg,
                serialize_extra: false,
                cargo_spans: Some(newmap),
            };
            runner(ctx, tx);
        },
        || {
            let mut diagnostics = Vec::new();

            match timeout {
                Some(timeout) => {
                    let trx = crossbeam::after(timeout);
                    loop {
                        crossbeam::select! {
                            recv(rx) -> msg => {
                                if let Ok(pack) = msg {
                                    diagnostics.extend(pack.into_iter().map(|d| cargo_deny::diag::diag_to_json(d, &files, None)));
                                } else {
                                    // Yay, the sender was dopped (i.e. check was finished)
                                    break;
                                }
                            }
                            recv(trx) -> _ => {
                                anyhow::bail!("Timed out after {:?}", timeout);
                            }
                        }
                    }
                }
                None => {
                    while let Ok(pack) = rx.recv() {
                        diagnostics.extend(
                            pack.into_iter()
                                .map(|d| cargo_deny::diag::diag_to_json(d, &files, None)),
                        );
                    }
                }
            }

            Ok(diagnostics)
        },
    );

    gathered
}

macro_rules! field_eq {
    ($obj:expr, $field:expr, $expected:expr) => {
        $obj.pointer($field) == Some(&serde_json::json!($expected))
    };
}

macro_rules! assert_field_eq {
    ($obj:expr, $field:expr, $expected:expr) => {
        assert_eq!($obj.pointer($field), Some(&serde_json::json!($expected)));
    };
}
