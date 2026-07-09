use crate::{clap_err, common::ValidConfig};
use anyhow::{Context as _, Error};
use cargo_deny::{diag::Files, licenses};

#[derive(Clone)]
struct ThresholdParser;

impl clap::builder::TypedValueParser for ThresholdParser {
    type Value = f32;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let Some(v) = value.to_str() else {
            return Err(clap_err!(InvalidUtf8, cmd));
        };

        let Ok(t) = v.parse::<f32>() else {
            let mut err = clap_err!(ValueValidation, cmd);
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(v.to_owned()),
            );
            return Err(err);
        };

        if !(0.0..=1.0).contains(&t) {
            let mut err = clap_err!(ValueValidation, cmd);
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(v.to_owned()),
            );
            Err(err)
        } else {
            Ok(t)
        }
    }
}

crate::enum_args!(licenses::OutputFormat : FormatParser => {
   "human" => Human,
   "json" => Json,
   "tsv" => Tsv,
});

crate::enum_args!(licenses::Layout : LayoutParser => {
   "crate" => Crate,
   "license" => License,
});

pub struct Args {
    threshold: f32,
    format: licenses::OutputFormat,
    layout: licenses::Layout,
}

impl Args {
    pub fn cmd() -> clap::Command {
        clap::Command::new("list")
            .about("Outputs a listing of all licenses and the crates that use them")
            .args([
                clap::Arg::new("THRESHOLD").short('t').long("threshold").help("Minimum confidence threshold for license text").long_help("When determining the license from file contents, a confidence score is assigned according to how close the contents are to the canonical license text. If the confidence score is below this threshold, they license text will ignored, which might mean the crate is treated as unlicensed. This overrides the `licenses.confidence-threshold` configuration field.\n\n[possible values: 0.0 - 1.0]").default_value("0.8").value_parser(ThresholdParser),
                clap::Arg::new("FORMAT").short('f').long("format").help("The format of the output.").default_value("human").value_parser(FormatParser),
                clap::Arg::new("LAYOUT").short('l').long("layout").help("The layout for the output, does not apply to TSV.").default_value("license").value_parser(LayoutParser),
            ])
    }

    pub fn parse(args: &mut clap::ArgMatches) -> Self {
        let threshold = args.remove_one("THRESHOLD").unwrap();
        let format = args.remove_one("FORMAT").unwrap();
        let layout = args.remove_one("LAYOUT").unwrap();

        Self {
            threshold,
            format,
            layout,
        }
    }
}

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    let cfg_path = krate_ctx.get_config_path()?;

    let mut files = Files::new();
    let ValidConfig {
        graph, licenses, ..
    } = ValidConfig::load(
        cfg_path,
        krate_ctx.get_local_exceptions_path(),
        &mut files,
        log_ctx,
    )?;

    let (krates, store) = rayon::join(
        || krate_ctx.gather_krates(graph.targets, graph.exclude),
        crate::common::load_license_store,
    );

    let krates = krates.context("failed to gather crates")?;
    let store = store.context("failed to load license store")?;

    let gatherer = licenses::Gatherer::default()
        .with_store(std::sync::Arc::new(store))
        .with_confidence_threshold(args.threshold);

    let mut files = Files::new();

    let summary = gatherer.gather(&krates, &mut files, &licenses);

    let colorize = crate::common::should_colorize(log_ctx.color, std::io::stdout());

    cargo_deny::licenses::list(
        &mut std::io::stdout(),
        &summary,
        args.format,
        args.layout,
        colorize,
    )?;

    Ok(())
}
