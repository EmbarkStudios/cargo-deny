use anyhow::Result;
use std::process::ExitCode;
use tracing_subscriber::prelude::*;

pub fn run() -> ExitCode {
    let Err(err) = try_run() else {
        return ExitCode::SUCCESS;
    };

    eprintln!("Exitting with error: {err:?}");
    ExitCode::FAILURE
}

fn try_run() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::from_env("XTASK_LOG");

    let fmt = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_ansi(std::env::var("COLORS").as_deref() != Ok("0"))
        .pretty();

    tracing_subscriber::registry()
        .with(fmt)
        .with(env_filter)
        .init();

    crate::cli::run()
}
