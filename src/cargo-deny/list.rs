use crate::common::ValidConfig;
use anyhow::{Context as _, Error};
use cargo_deny::{Kid, PathBuf, diag::Files, licenses};
use nu_ansi_term::Color;
use serde::Serialize;

#[derive(clap::ValueEnum, Copy, Clone, Debug)]
pub enum Layout {
    Crate,
    License,
}

#[derive(clap::ValueEnum, Copy, Clone, Debug)]
pub enum OutputFormat {
    Human,
    Json,
    Markdown,
    Tsv,
}

#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the config to use
    ///
    /// Defaults to a deny.toml in the same folder as the manifest path, or a deny.toml in a parent directory.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Path to cargo metadata json
    ///
    /// By default we use `cargo metadata` to generate
    /// the metadata json, but you can override that behaviour by
    /// providing the path to cargo metadata.
    #[arg(long)]
    metadata_path: Option<PathBuf>,
    /// Minimum confidence threshold for license text
    ///
    /// When determining the license from file contents, a confidence score is assigned according to how close the contents are to the canonical license text. If the confidence score is below this threshold, they license text will ignored, which might mean the crate is treated as unlicensed.
    ///
    /// [possible values: 0.0 - 1.0]
    #[arg(short, long, default_value = "0.8")]
    threshold: f32,
    /// The format of the output
    #[arg(short, long, default_value = "human", value_enum)]
    format: OutputFormat,
    /// The layout for the output, does not apply to TSV
    #[arg(short, long, default_value = "license", value_enum)]
    layout: Layout,
}

pub fn cmd(
    log_ctx: crate::common::LogContext,
    args: Args,
    krate_ctx: crate::common::KrateContext,
) -> Result<(), Error> {
    use licenses::LicenseInfo;
    use std::{collections::BTreeMap, fmt::Write};

    let cfg_path = krate_ctx.get_config_path(args.config.clone());

    let mut files = Files::new();
    let ValidConfig { graph, .. } = ValidConfig::load(
        cfg_path,
        krate_ctx.get_local_exceptions_path(),
        &mut files,
        log_ctx,
    )?;

    let metadata = if let Some(metadata_path) = args.metadata_path {
        let data = std::fs::read_to_string(metadata_path).context("metadata path")?;
        Some(serde_json::from_str(&data).context("cargo metadata")?)
    } else {
        None
    };

    let (krates, store) = rayon::join(
        || krate_ctx.gather_krates(metadata, graph.targets, graph.exclude),
        crate::common::load_license_store,
    );

    let krates = krates.context("failed to gather crates")?;
    let store = store.context("failed to load license store")?;

    let gatherer = licenses::Gatherer::default()
        .with_store(std::sync::Arc::new(store))
        .with_confidence_threshold(args.threshold);

    let mut files = Files::new();

    let summary = gatherer.gather(&krates, &mut files, None);

    use std::borrow::Cow;

    #[derive(Ord, PartialOrd, PartialEq, Eq)]
    struct SerKid<'k>(Cow<'k, Kid>);

    impl serde::Serialize for SerKid<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&format!(
                "{} {} {}",
                self.0.name(),
                self.0.version(),
                self.0.source()
            ))
        }
    }

    impl SerKid<'_> {
        fn parts(&self) -> (&str, &str) {
            (self.0.name(), self.0.version())
        }
    }

    #[derive(Serialize)]
    struct Crate {
        licenses: Vec<String>,
    }

    #[derive(Serialize)]
    struct LicenseLayout<'k> {
        licenses: Vec<(String, Vec<SerKid<'k>>)>,
        unlicensed: Vec<SerKid<'k>>,
    }

    struct CrateLayout<'k> {
        crates: BTreeMap<SerKid<'k>, Crate>,
    }

    impl<'k> CrateLayout<'k> {
        fn search(&self, id: &SerKid<'k>) -> &Crate {
            self.crates.get(id).expect("unable to find crate")
        }
    }

    fn borrow(kid: &Kid) -> SerKid<'_> {
        SerKid(Cow::Borrowed(kid))
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
                LicenseInfo::SpdxExpression { expr, .. } => {
                    for req in expr.requirements() {
                        let s = req.req.to_string();

                        if cur.licenses.contains(&s) {
                            continue;
                        }

                        match licenses.binary_search_by(|(r, _)| r.cmp(&s)) {
                            Ok(i) => licenses[i].1.push(borrow(&krate_lic_nfo.krate.id)),
                            Err(i) => {
                                let mut v = Vec::with_capacity(20);
                                v.push(borrow(&krate_lic_nfo.krate.id));
                                licenses.insert(i, (s.clone(), v));
                            }
                        }
                        cur.licenses.push(s);
                    }
                }
                LicenseInfo::Unlicensed => {
                    unlicensed.push(borrow(&krate_lic_nfo.krate.id));
                }
            }

            crate_layout
                .crates
                .insert(SerKid(Cow::Owned(krate_lic_nfo.krate.id.clone())), cur);
        }
    }

    fn write_pid(out: &mut String, pid: &SerKid<'_>) -> Result<(), Error> {
        let (name, version) = pid.parts();
        Ok(write!(out, "{name}@{version}")?)
    }

    match args.format {
        OutputFormat::Human => {
            let mut output = String::with_capacity(4 * 1024);
            let color = crate::common::should_colorize(log_ctx.color, std::io::stdout());

            match args.layout {
                Layout::License => {
                    for (license, krates) in license_layout.licenses {
                        if color {
                            write!(
                                output,
                                "{} ({}): ",
                                Color::Cyan.paint(&license),
                                Color::White.bold().paint(krates.len().to_string())
                            )?;
                        } else {
                            write!(output, "{license} ({}): ", krates.len())?;
                        }

                        for (i, krate_id) in krates.iter().enumerate() {
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

                                let (name, version) = krate_id.parts();
                                write!(output, "{}@{version}", color.paint(name))?;
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
                        let (name, version) = id.parts();

                        if color {
                            let color = match krate.licenses.len() {
                                1 => Color::White,
                                0 => Color::Red,
                                _ => Color::Yellow,
                            };

                            write!(
                                output,
                                "{}@{version} ({}): ",
                                color.paint(name),
                                Color::White.bold().paint(krate.licenses.len().to_string()),
                            )?;
                        } else {
                            write!(output, "{name}@{version} ({}): ", krate.licenses.len(),)?;
                        }

                        for (i, license) in krate.licenses.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            if color {
                                write!(output, "{}", Color::Cyan.paint(license))?;
                            } else {
                                write!(output, "{license}")?;
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
        OutputFormat::Markdown => {
            let mut output = String::with_capacity(4 * 1024);
            match args.layout {
                Layout::License => {
                    // Column headers
                    {
                        writeln!(output, "| License | Crates |")?;
                        writeln!(output, "| ------- | ------ |")?;
                    }

                    for (license, krates) in license_layout.licenses {
                        write!(output, "| **{license}** ({}) | ", krates.len())?;
                        for (i, krate_id) in krates.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            let (name, version) = krate_id.parts();
                            write!(output, "`{name}@{version}`")?;
                        }

                        writeln!(output, " |")?;
                    }
                }
                Layout::Crate => {
                    // Column headers
                    {
                        writeln!(output, "| Crate | Licenses |")?;
                        writeln!(output, "| ----- | -------- |")?;
                    }

                    for (id, krate) in crate_layout.crates {
                        let (name, version) = id.parts();

                        write!(
                            output,
                            "| **{name}**@_{version}_ ({}) | ",
                            krate.licenses.len()
                        )?;
                        for (i, license) in krate.licenses.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            write!(output, "`{license}`")?;
                        }

                        writeln!(output, " |")?;
                    }
                }
            }

            std::io::Write::write_all(&mut std::io::stdout(), output.as_bytes())?;
        }
        OutputFormat::Tsv => {
            // We ignore the layout specification and always just do a grid of crate rows x license/exception columns
            let mut output = String::with_capacity(4 * 1024);

            // Column headers
            {
                write!(output, "crate")?;

                for (license, _) in &license_layout.licenses {
                    write!(output, "\t{license}")?;
                }

                if !license_layout.unlicensed.is_empty() {
                    write!(output, "\tUnlicensed")?;
                }

                writeln!(output)?;
            }

            for (id, krate) in crate_layout.crates {
                write_pid(&mut output, &id)?;

                for lic in &license_layout.licenses {
                    if lic.1.binary_search(&id).is_ok() {
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
