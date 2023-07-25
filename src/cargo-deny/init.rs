use crate::PathBuf;
use anyhow::{ensure, Context, Error};

#[derive(clap::Parser, Debug, Clone)]
pub struct Args {
    /// The path to create
    ///
    /// Defaults to <cwd>/deny.toml
    #[clap(action)]
    config: Option<PathBuf>,
}

const CONTENTS: &[u8] = include_bytes!("../../deny.template.toml");

pub fn cmd(args: Args, ctx: crate::common::KrateContext) -> Result<(), Error> {
    let cfg_path = args.config.unwrap_or_else(|| PathBuf::from("deny.toml"));
    let cfg_path = ctx
        .get_config_path(Some(cfg_path))
        .context("unable to get full path to config")?;

    // make sure the file does not exist yet
    ensure!(
        std::fs::metadata(&cfg_path).is_err(),
        "unable to initialize cargo-deny config: '{cfg_path}' already exists"
    );

    // make sure the path does not terminate in '..'; we need a file name.
    ensure!(
        cfg_path.file_name().is_some(),
        "unable to create cargo-deny config: '{cfg_path}' has an invalid filename"
    );

    std::fs::write(&cfg_path, CONTENTS).context("unable to write config file")?;
    log::info!("saved config file to: {cfg_path}");

    Ok(())
}
