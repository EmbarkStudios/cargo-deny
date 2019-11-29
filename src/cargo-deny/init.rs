use anyhow::{bail, ensure, Context, Error};
use clap::arg_enum;
use serde::Serialize;
use std::path::PathBuf;
use structopt::StructOpt;

use crate::common::make_absolute_path;

arg_enum! {
    #[derive(Debug, PartialEq, Clone)]
    pub enum AllowOsiFsfFree {
        Both,
        Either,
        OSIOnly,
        FSFOnly,
        Neither,
    }
}

impl From<AllowOsiFsfFree> for String {
    fn from(value: AllowOsiFsfFree) -> Self {
        let out = match value {
            AllowOsiFsfFree::Both => "both",
            AllowOsiFsfFree::Either => "either",
            AllowOsiFsfFree::OSIOnly => "osi-only",
            AllowOsiFsfFree::FSFOnly => "fsf-only",
            AllowOsiFsfFree::Neither => "neither",
        };

        out.to_string()
    }
}

arg_enum! {
    #[derive(Debug, PartialEq, Clone)]
    pub enum LintLevel {
        Allow,
        Deny,
        Warn,
    }
}

impl From<LintLevel> for String {
    fn from(value: LintLevel) -> Self {
        let out = match value {
            LintLevel::Allow => "allow",
            LintLevel::Deny => "deny",
            LintLevel::Warn => "warn",
        };

        out.to_string()
    }
}

#[derive(StructOpt, Debug, Clone)]
pub struct Args {
    /// The path to the config file. Defaults to <context>/deny.toml
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,

    /// Determines what happens when a crate has not explicitly specified its license terms, and no
    /// license information could be easily detected via LICENSE* files in the crate's source
    #[structopt(
        long,
        possible_values = &LintLevel::variants(),
        case_insensitive = true,
    )]
    unlicensed: Option<LintLevel>,

    /// Determines what happens when a license that is considered copyleft is encountered
    #[structopt(
        long,
        possible_values = &LintLevel::variants(),
        case_insensitive = true,
    )]
    copyleft: Option<LintLevel>,

    /// Determines what happens when licenses aren't explicitly allowed or denied,
    /// but are marked as OSI Approved or FSF Free/Libre in the current version of the SPDX License
    /// List
    #[structopt(
        long,
        possible_values = &AllowOsiFsfFree::variants(),
        case_insensitive = true,
    )]
    allow_osi_fsf_free: Option<AllowOsiFsfFree>,

    /// Determines how close the match between a license text must be to the canonical license text
    /// of a valid SPDX license file [possible values: any value between 0.0 and 1.0]
    #[structopt(
        long,
        parse(try_from_str = parse_confidence_threshold)
    )]
    confidence_threshold: Option<f32>,
}

impl From<Args> for InitConfig {
    fn from(value: Args) -> Self {
        InitConfig {
            licenses: Licenses {
                unlicensed: value.unlicensed.map(From::from),
                copyleft: value.copyleft.map(From::from),
                allow_osi_fsf_free: value.allow_osi_fsf_free.map(From::from),
                confidence_threshold: value.confidence_threshold,
            },
        }
    }
}

// Valid values: `0.0 <= x <= 1.0`
fn parse_confidence_threshold(src: &str) -> Result<f32, Error> {
    let error_msg = || "The confidence threshold should be a value between 0.0 and 1.0";
    fn naive_in_range(value: f32) -> bool {
        value >= 0.0 && value <= 1.0
    }

    let result: f32 = src.parse().with_context(error_msg)?;

    if naive_in_range(result) {
        Ok(result)
    } else {
        bail!(error_msg())
    }
}

#[derive(Debug, Serialize)]
struct InitConfig {
    licenses: Licenses,
}

#[derive(Debug, Serialize)]
struct Licenses {
    unlicensed: Option<String>,
    copyleft: Option<String>,
    #[serde(rename = "allow-osi-fsf-free")]
    allow_osi_fsf_free: Option<String>,
    #[serde(rename = "confidence-threshold")]
    confidence_threshold: Option<f32>,
}

const DENY_TOML: &str = "deny.toml";

pub fn cmd(args: Args, context_dir: PathBuf) -> Result<(), Error> {
    let cfg_file = args
        .config
        .clone()
        .or_else(|| Some(DENY_TOML.into()))
        .map(|path| make_absolute_path(path, context_dir))
        .context("unable to determine config path")?;

    // make sure the file does not exist yet
    ensure!(
        std::fs::metadata(&cfg_file).is_err(),
        "unable to initialize cargo deny config file ; the provided path already exists"
    );
    // make sure the path does not terminate in '..'; we need a file name.
    ensure!(
        &cfg_file.file_name().is_some(),
        "unable to create a config file with the given name ; the given file path is not valid"
    );

    let config: InitConfig = args.into();
    let content = toml::to_string(&config).context("unable to create config (toml) file")?;

    std::fs::write(cfg_file, content).context("unable to write config file")?;

    Ok(())
}
