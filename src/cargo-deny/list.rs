use ansi_term::Color;
use anyhow::{Context, Error};
use cargo_deny::{licenses, Kid};
use clap::arg_enum;
use serde::Serialize;
use std::path::PathBuf;
use structopt::StructOpt;

arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum ColorWhen {
        Always,
        Never,
        Auto,
    }
}

arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum Layout {
        Crate,
        License,
    }
}

arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum OutputFormat {
        Human,
        Json,
        Tsv,
    }
}

#[derive(StructOpt, Debug)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to a deny.toml in the same folder as the manifest path, or a deny.toml in a parent directory.
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
    /// Minimum confidence threshold for license text
    ///
    /// When determining the license from file contents, a confidence score is assigned according to how close the contents are to the canonical license text. If the confidence score is below this threshold, they license text will ignored, which might mean the crate is treated as unlicensed.
    ///
    /// [possible values: 0.0 - 1.0]
    #[structopt(short, long, default_value = "0.8")]
    threshold: f32,
    /// The format of the output
    #[structopt(
        short,
        long,
        default_value = "human",
        possible_values = &OutputFormat::variants(),
        case_insensitive = true,
    )]
    format: OutputFormat,
    /// Output coloring, only applies to 'human' format
    #[structopt(
        long,
        default_value = "auto",
        possible_values = &ColorWhen::variants(),
        case_insensitive = true,
    )]
    color: ColorWhen,
    /// Determines if log messages are emitted
    ///
    /// The log level specified at the top level still applies
    #[structopt(short, long)]
    verbose: bool,
    /// The layout for the output, does not apply to TSV
    #[structopt(
        short,
        long,
        default_value = "license",
        possible_values = &Layout::variants(),
        case_insensitive = true,
    )]
    layout: Layout,
}

#[derive(serde::Deserialize)]
struct Config {
    #[serde(default)]
    targets: Vec<crate::common::Target>,
}

struct ValidConfig {
    targets: Vec<(String, Vec<String>)>,
}

impl ValidConfig {
    fn load(cfg_path: Option<PathBuf>, files: &mut codespan::Files<String>) -> Result<Self, Error> {
        let (cfg_contents, cfg_path) = match cfg_path {
            Some(cfg_path) if cfg_path.exists() => (
                std::fs::read_to_string(&cfg_path).with_context(|| {
                    format!("failed to read config from {}", cfg_path.display())
                })?,
                cfg_path,
            ),
            Some(cfg_path) => {
                log::warn!(
                    "config path '{}' doesn't exist, falling back to default config",
                    cfg_path.display()
                );

                return Ok(Self {
                    targets: Vec::new(),
                });
            }
            None => {
                log::warn!("unable to find a config path, falling back to default config");

                return Ok(Self {
                    targets: Vec::new(),
                });
            }
        };

        let cfg: Config = toml::from_str(&cfg_contents).with_context(|| {
            format!("failed to deserialize config from '{}'", cfg_path.display())
        })?;

        log::info!("using config from {}", cfg_path.display());

        let id = files.add(cfg_path.to_string_lossy(), cfg_contents);

        use cargo_deny::diag::Diagnostic;

        let validate = || -> Result<(Vec<Diagnostic>, Self), Vec<Diagnostic>> {
            let mut diagnostics = Vec::new();
            let targets = crate::common::load_targets(cfg.targets, &mut diagnostics, id);

            Ok((diagnostics, Self { targets }))
        };

        let print = |diags: Vec<Diagnostic>| {
            use codespan_reporting::term;

            if diags.is_empty() {
                return;
            }

            let writer =
                term::termcolor::StandardStream::stderr(term::termcolor::ColorChoice::Auto);
            let config = term::Config::default();
            let mut writer = writer.lock();
            for diag in &diags {
                term::emit(&mut writer, &config, &files, &diag).unwrap();
            }
        };

        match validate() {
            Ok((diags, vc)) => {
                print(diags);
                Ok(vc)
            }
            Err(diags) => {
                print(diags);

                anyhow::bail!(
                    "failed to validate configuration file {}",
                    cfg_path.display()
                );
            }
        }
    }
}

#[allow(clippy::cognitive_complexity)]
pub fn cmd(args: Args, krate_ctx: crate::common::KrateContext) -> Result<(), Error> {
    use licenses::LicenseInfo;
    use std::{collections::BTreeMap, fmt::Write};

    let mut files = codespan::Files::new();
    let cfg = ValidConfig::load(krate_ctx.get_config_path(args.config), &mut files)?;

    let (krates, store) = rayon::join(
        || krate_ctx.gather_krates(cfg.targets),
        crate::common::load_license_store,
    );

    let krates = krates.context("failed to gather crates")?;
    let store = store.context("failed to load license store")?;

    let gatherer = licenses::Gatherer::default()
        .with_store(std::sync::Arc::new(store))
        .with_confidence_threshold(args.threshold);

    let mut files = codespan::Files::new();

    let summary = gatherer.gather(&krates, &mut files, None);

    #[derive(Serialize)]
    struct Crate {
        licenses: Vec<String>,
    }

    #[derive(Serialize)]
    struct LicenseLayout<'a> {
        licenses: Vec<(String, Vec<&'a Kid>)>,
        unlicensed: Vec<&'a Kid>,
    }

    struct CrateLayout {
        crates: BTreeMap<Kid, Crate>,
    }

    impl CrateLayout {
        fn search(&self, id: &Kid) -> &Crate {
            self.crates.get(id).expect("unable to find crate")
        }
    }

    let mut crate_layout = CrateLayout {
        crates: BTreeMap::new(),
    };

    let mut license_layout = LicenseLayout {
        licenses: Vec::with_capacity(20),
        unlicensed: Vec::new(),
    };

    {
        let licenses = &mut license_layout.licenses;
        let unlicensed = &mut license_layout.unlicensed;

        for krate_lic_nfo in summary.nfos {
            let mut cur = Crate {
                licenses: Vec::with_capacity(2),
            };

            match krate_lic_nfo.lic_info {
                LicenseInfo::SPDXExpression { expr, .. } => {
                    for req in expr.requirements() {
                        let s = req.req.to_string();

                        if cur.licenses.contains(&s) {
                            continue;
                        }

                        match licenses.binary_search_by(|(r, _)| r.cmp(&s)) {
                            Ok(i) => licenses[i].1.push(&krate_lic_nfo.krate.id),
                            Err(i) => {
                                let mut v = Vec::with_capacity(20);
                                v.push(&krate_lic_nfo.krate.id);
                                licenses.insert(i, (s.clone(), v));
                            }
                        }
                        cur.licenses.push(s);
                    }
                }
                LicenseInfo::Unlicensed => {
                    unlicensed.push(&krate_lic_nfo.krate.id);
                }
            }

            crate_layout
                .crates
                .insert(krate_lic_nfo.krate.id.clone(), cur);
        }
    }

    fn get_parts(pid: &Kid) -> (&str, &str) {
        let mut it = pid.repr.split(' ');

        (it.next().unwrap(), it.next().unwrap())
    }

    fn write_pid(out: &mut String, pid: &Kid) -> Result<(), Error> {
        let parts = get_parts(pid);

        Ok(write!(out, "{}@{}", parts.0, parts.1)?)
    }

    match args.format {
        OutputFormat::Human => {
            let mut output = String::with_capacity(4 * 1024);
            let color = match args.color {
                ColorWhen::Always => true,
                ColorWhen::Never => false,
                ColorWhen::Auto => atty::is(atty::Stream::Stdout),
            };

            match args.layout {
                Layout::License => {
                    for license in license_layout.licenses {
                        if color {
                            write!(
                                output,
                                "{} ({}): ",
                                Color::Cyan.paint(&license.0),
                                Color::White.bold().paint(license.1.len().to_string())
                            )?;
                        } else {
                            write!(output, "{} ({}): ", license.0, license.1.len())?;
                        }

                        for (i, krate_id) in license.1.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            if color {
                                let krate = crate_layout.search(krate_id);
                                let color = if krate.licenses.len() > 1 {
                                    Color::Yellow
                                } else {
                                    Color::White
                                };

                                let parts = get_parts(krate_id);
                                write!(output, "{}@{}", color.paint(parts.0), parts.1,)?;
                            } else {
                                write_pid(&mut output, krate_id)?;
                            }
                        }

                        writeln!(output)?;
                    }

                    if !license_layout.unlicensed.is_empty() {
                        if color {
                            write!(
                                output,
                                "{} ({}): ",
                                Color::Red.paint("Unlicensed"),
                                Color::White
                                    .bold()
                                    .paint(license_layout.unlicensed.len().to_string())
                            )?;
                        } else {
                            write!(output, "Unlicensed ({}): ", license_layout.unlicensed.len())?;
                        }

                        for (i, krate) in license_layout.unlicensed.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            write_pid(&mut output, krate)?;
                        }

                        writeln!(output)?;
                    }
                }
                Layout::Crate => {
                    for (id, krate) in crate_layout.crates {
                        if color {
                            let color = match krate.licenses.len() {
                                1 => Color::White,
                                0 => Color::Red,
                                _ => Color::Yellow,
                            };

                            let parts = get_parts(&id);
                            write!(
                                output,
                                "{}@{} ({}): ",
                                color.paint(parts.0),
                                parts.1,
                                Color::White.bold().paint(krate.licenses.len().to_string()),
                            )?;
                        } else {
                            let parts = get_parts(&id);
                            write!(
                                output,
                                "{}@{} ({}): ",
                                parts.0,
                                parts.1,
                                krate.licenses.len(),
                            )?;
                        }

                        for (i, license) in krate.licenses.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            if color {
                                write!(output, "{}", Color::Cyan.paint(license))?;
                            } else {
                                write!(output, "{}", license)?;
                            }
                        }

                        writeln!(output)?;
                    }
                }
            }

            std::io::Write::write_all(&mut std::io::stdout(), output.as_bytes())?;
        }
        OutputFormat::Json => match args.layout {
            Layout::License => {
                serde_json::to_writer(std::io::stdout(), &license_layout)?;
            }
            Layout::Crate => serde_json::to_writer(std::io::stdout(), &crate_layout.crates)?,
        },
        OutputFormat::Tsv => {
            // We ignore the layout specification and always just do a grid of crate rows x license/exception columns
            let mut output = String::with_capacity(4 * 1024);

            // Column headers
            {
                write!(output, "crate")?;

                for license in &license_layout.licenses {
                    write!(output, "\t{}", license.0)?;
                }

                if !license_layout.unlicensed.is_empty() {
                    write!(output, "\tUnlicensed")?;
                }

                writeln!(output)?;
            }

            for (id, krate) in crate_layout.crates {
                write_pid(&mut output, &id)?;

                for lic in &license_layout.licenses {
                    if lic.1.binary_search(&&id).is_ok() {
                        write!(output, "\tX")?;
                    } else {
                        write!(output, "\t")?;
                    }
                }

                if krate.licenses.is_empty() {
                    write!(output, "\tX")?;
                }

                writeln!(output)?;
            }

            std::io::Write::write_all(&mut std::io::stdout(), output.as_bytes())?;
        }
    }

    Ok(())
}
