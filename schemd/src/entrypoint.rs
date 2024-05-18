use crate::prelude::*;
use std::process::ExitCode;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;

pub fn run() -> ExitCode {
    match std::panic::catch_unwind(try_run) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            error!("Exiting with error: {err:?}");
            ExitCode::FAILURE
        }
        Err(_) => {
            error!("Exiting with error due to a panic");
            ExitCode::FAILURE
        }
    }
}

fn try_run() -> Result {
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_env_var("SCHEMD_LOG")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let fmt = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr)
        .with_ansi(std::env::var("COLORS").as_deref() != Ok("0"))
        .pretty();

    tracing_subscriber::registry()
        .with(fmt)
        .with(env_filter)
        .init();

    crate::cli::run()
}
