use anyhow::{ensure, Context, Error};
use std::path::PathBuf;
use structopt::StructOpt;

use crate::common::make_absolute_path;

#[derive(StructOpt, Debug, Clone)]
pub struct Args {
    /// The path to create
    ///
    /// Defaults to <context>/deny.toml
    #[structopt(parse(from_os_str), default_value = "deny.toml")]
    config: PathBuf,
}

const CONTENTS: &[u8] = include_bytes!("../../resources/template.toml");

pub fn cmd(args: Args, context_dir: PathBuf) -> Result<(), Error> {
    let cfg_file = make_absolute_path(args.config, &context_dir);

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
