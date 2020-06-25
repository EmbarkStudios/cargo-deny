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

    let spans = KrateSpans::new(krates);
    let mut files = Files::new();
    let spans_id = files.add(project_dir.join("Cargo.lock"), spans.1);

    let config: Config = fs::read_to_string(project_dir.join("deny.toml"))
        .map(|it| toml::from_str(&it).unwrap())
        .unwrap_or_default();

    accept_ctx(cargo_deny::CheckCtx {
        krates,
        krate_spans: &spans.0,
        spans_id,
        cfg: config.validate(spans_id).unwrap(),
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
