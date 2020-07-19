use cargo_deny::{
    bans::{
        self,
        cfg::{Config, ValidConfig},
    },
    diag::{Files, KrateSpans},
    CheckCtx,
};
use std::{fs, path::PathBuf, time::Duration};

fn with_test_data(project_name: &str, accept_ctx: impl FnOnce(CheckCtx<'_, ValidConfig>)) {
    let project_dir = PathBuf::from("./tests/test_data").join(project_name);

    let mut metadata_cmd = krates::cm::MetadataCommand::new();
    metadata_cmd.current_dir(&project_dir);

    let krates = &krates::Builder::new()
        .build(metadata_cmd, krates::NoneFilter)
        .unwrap();

    let (spans, content, hashmap) = KrateSpans::new(krates);
    let mut files = Files::new();
    let spans_id = files.add(project_dir.join("Cargo.lock"), content);

    let config: Config = fs::read_to_string(project_dir.join("deny.toml"))
        .map(|it| toml::from_str(&it).unwrap())
        .unwrap_or_default();

    let mut newmap = std::collections::HashMap::new();
    for (key, val) in hashmap {
        let cargo_id = files.add(val.0, val.1);
        newmap.insert(key, (cargo_id, val.2));
    }

    accept_ctx(cargo_deny::CheckCtx {
        krates,
        krate_spans: &spans,
        spans_id,
        cfg: config.validate(spans_id).unwrap(),
        serialize_extra: false,
        cargo_spans: Some(newmap),
    });
}

// Covers issue https://github.com/EmbarkStudios/cargo-deny/issues/184
#[test]
fn cyclic_dependencies_do_not_cause_infinite_loop() {
    let (tx, rx) = crossbeam::unbounded();

    let handle = std::thread::spawn(|| {
        with_test_data("cyclic_dependencies", |check_ctx| {
            let graph_output = Box::new(|_| Ok(()));
            bans::check(check_ctx, Some(graph_output), tx);
        });
    });

    let timeout_duration = Duration::from_millis(10000);
    let timeout = crossbeam::after(timeout_duration);
    loop {
        crossbeam::select! {
            recv(rx) -> msg => {
                if msg.is_err() {
                    // Yay, the sender was dopped (i.e. check was finished)
                    break;
                }
            }
            recv(timeout) -> _ => {
                panic!("Bans check timed out after {:?}", timeout_duration);
            }
        }
    }

    handle.join().unwrap();
}

#[test]
fn wildcards_deny_test() {
    let (tx, rx) = crossbeam::unbounded();

    let handle = std::thread::spawn(|| {
        with_test_data("wildcards/maincrate", |check_ctx| {
            let graph_output = Box::new(|_| Ok(()));
            bans::check(check_ctx, Some(graph_output), tx);
        });
    });

    let timeout_duration = Duration::from_millis(10000);
    let timeout = crossbeam::after(timeout_duration);
    let mut packs: Vec<cargo_deny::diag::Pack> = vec![];
    loop {
        crossbeam::select! {
            recv(rx) -> msg => {
                match msg {
                    Ok(msg) => packs.push(msg),
                    Err(_e) => {
                        // Yay, the sender was dopped (i.e. check was finished)
                        break;
                    }
                }
            }
            recv(timeout) -> _ => {
                panic!("Bans check timed out after {:?}", timeout_duration);
            }
        }
    }

    handle.join().unwrap();

    assert_eq!(packs.len(), 2);

    let mut msgs = packs.into_iter().map(|pack| {
        let mut diags = pack.into_iter().collect::<Vec<_>>();
        assert_eq!(diags.len(), 1);
        let diag = diags.pop().unwrap();

        assert_eq!(
            diag.diag.severity,
            codespan_reporting::diagnostic::Severity::Error
        );
        assert!(diag.diag.message.starts_with("found 1 wildcard dependency"));
        diag.diag.message
    });

    // both crates have wildcard deps so check that both are reported
    assert!(msgs.any(|s| s.contains("wildcards-test-crate")));
    assert!(msgs.any(|s| s.contains("wildcards-test-dep")));
}
