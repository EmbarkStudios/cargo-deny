use anyhow::{ensure, Context, Error};
use std::path::PathBuf;
use structopt::StructOpt;

use crate::common::make_absolute_path;

#[derive(StructOpt, Debug, Clone)]
pub struct Args {
    /// The path to the config file. Defaults to <context>/deny.toml
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
}

const DENY_TOML: &str = "deny.toml";
const CONTENTS: &[u8] = include_bytes!("../../resources/template.toml");

pub fn cmd(args: Args, context_dir: PathBuf) -> Result<(), Error> {
    let cfg_file = args
        .config
        .or_else(|| Some(DENY_TOML.into()))
        .map(|path| make_absolute_path(path, &context_dir))
        .context("unable to determine config path")?;

    // make sure the file does not exist yet
    ensure!(
        std::fs::metadata(&cfg_file).is_err(),
        "unable to initialize cargo-deny config: '{}' already exists",
        cfg_file.display(),
    );

    // make sure the path does not terminate in '..'; we need a file name.
    ensure!(
        cfg_file.file_name().is_some(),
        "unable to create cargo-deny config: '{}' has an invalid filename",
        cfg_file.display(),
    );

    std::fs::write(&cfg_file, CONTENTS).context("unable to write config file")?;
    log::info!("saved config file to: {}", cfg_file.display());

    Ok(())
}
