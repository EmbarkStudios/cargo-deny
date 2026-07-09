use crate::PathBuf;
use anyhow::{Context, Error, ensure};

#[derive(Clone)]
pub struct Args;

impl Args {
    pub fn cmd() -> clap::Command {
        clap::Command::new("init").about("Creates a cargo-deny config from a template")
    }

    pub fn parse(_args: &mut clap::ArgMatches) -> Self {
        Self
    }
}

const CONTENTS: &[u8] = include_bytes!("../../deny.template.toml");

pub fn cmd(_args: Args, ctx: crate::common::KrateContext) -> Result<(), Error> {
    let cfg_path = ctx.get_config_path()?.unwrap_or_else(|| {
        let mut pb = PathBuf::new();
        pb.push("./deny.toml");
        pb
    });

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
