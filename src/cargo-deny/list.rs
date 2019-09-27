use ansi_term::Color;
use cargo_deny::licenses;
use clap::arg_enum;
use failure::Error;
use serde::Serialize;
use slog::warn;
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
    /// The confidence threshold required for license files
    /// to be positively identified: 0.0 - 1.0
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
    /// This just determines if log messages are emitted, the log level specified
    /// at the top level still applies
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

#[allow(clippy::cognitive_complexity)]
pub fn cmd(
    log: slog::Logger,
    args: Args,
    crates: cargo_deny::Crates,
    store: Option<licenses::LicenseStore>,
) -> Result<(), Error> {
    use licenses::{Note, Summary};
    use std::{
        collections::{BTreeMap, HashMap},
        fmt::Write,
    };

    let gatherer = licenses::Gatherer::new(log.new(slog::o!("stage" => "license_gather")))
        .with_store(std::sync::Arc::new(
            store.expect("we should have a license store"),
        ))
        .with_confidence_threshold(args.threshold);

    let summary = gatherer.gather(crates.as_ref(), HashMap::new());

    #[derive(Serialize)]
    struct Crate<'a> {
        licenses: Vec<&'a str>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        exceptions: Vec<&'a str>,
    }

    #[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
    struct CrateId<'a> {
        name: &'a str,
        version: &'a semver::Version,
    }

    impl<'a> Serialize for CrateId<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            s.serialize_str(&format!("{}@{}", self.name, self.version))
        }
    }

    #[inline]
    fn bin_search<T, Q>(s: &[(T, Vec<CrateId<'_>>)], query: &Q) -> Result<usize, usize>
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        s.binary_search_by(|(i, _)| i.borrow().cmp(query))
    }

    #[derive(Serialize)]
    struct LicenseLayout<'a> {
        licenses: Vec<(String, Vec<CrateId<'a>>)>,
        exceptions: Vec<(&'a str, Vec<CrateId<'a>>)>,
        unlicensed: Vec<CrateId<'a>>,
    }

    struct CrateLayout<'a> {
        crates: BTreeMap<CrateId<'a>, Crate<'a>>,
    }

    impl<'a> CrateLayout<'a> {
        fn search(&self, id: &CrateId<'a>) -> &Crate<'a> {
            self.crates.get(id).expect("unable to find crate")
        }
    }

    let mut crate_layout = CrateLayout {
        crates: BTreeMap::new(),
    };

    let mut license_layout = LicenseLayout {
        licenses: Vec::with_capacity(20),
        exceptions: Vec::with_capacity(4),
        unlicensed: Vec::new(),
    };

    {
        let licenses = &mut license_layout.licenses;
        let exceptions = &mut license_layout.exceptions;
        let unlicensed = &mut license_layout.unlicensed;

        for crate_note in summary.notes() {
            let id = CrateId {
                name: crate_note.name,
                version: &crate_note.version,
            };

            let mut cur = Crate {
                licenses: Vec::with_capacity(2),
                exceptions: Vec::new(),
            };

            for note in &crate_note.notes {
                match note {
                    Note::License { name, .. } => {
                        let license_name = Summary::resolve_id(*name);

                        // The same license can (often) be present in both metadata
                        // and a license file, so don't count them twice
                        if cur.licenses.contains(&license_name) {
                            continue;
                        }

                        match bin_search(licenses, license_name) {
                            Ok(i) => {
                                licenses[i].1.push(id);
                            }
                            Err(i) => {
                                let mut v = Vec::with_capacity(20);
                                v.push(id);
                                licenses.insert(i, (license_name.to_owned(), v));
                            }
                        };

                        cur.licenses.push(license_name);
                    }
                    Note::Unlicensed => {}
                    Note::Exception(exc) => {
                        match bin_search(exceptions, exc) {
                            Ok(i) => {
                                exceptions[i].1.push(id);
                            }
                            Err(i) => {
                                let mut v = Vec::with_capacity(20);
                                v.push(id);
                                exceptions.insert(i, (exc, v));
                            }
                        };

                        cur.exceptions.push(exc);
                    }
                    Note::Unknown { name, source } => {
                        if args.verbose {
                            warn!(
                                log,
                                "detected an unknown license";
                                "crate" => crate_note,
                                "src" => source,
                            );
                        }

                        match bin_search(licenses, name) {
                            Ok(i) => {
                                licenses[i].1.push(id);
                            }
                            Err(i) => {
                                let mut v = Vec::with_capacity(20);
                                v.push(id);
                                licenses.insert(i, (name.clone(), v));
                            }
                        };

                        cur.licenses.push(name);
                    }
                    Note::LowConfidence { score, source } => {
                        if args.verbose {
                            warn!(
                                log,
                                "unable to determine license with high confidence";
                                "crate" => crate_note,
                                "score" => score,
                                "src" => source,
                            );
                        }
                    }
                    Note::UnreadableLicense { path, err } => {
                        if args.verbose {
                            warn!(
                                log,
                                "license file is unreadable";
                                "crate" => crate_note,
                                "path" => path.display(),
                                "err" => err.to_string(), // io::Error makes slog sad
                            );
                        }
                    }
                    Note::Ignored(_) => unreachable!(),
                }
            }

            // This can happen if a crate does have a license file, but it
            // has a confidence score below the current threshold
            if cur.licenses.is_empty() && cur.exceptions.is_empty() {
                unlicensed.push(id);
            }

            crate_layout.crates.insert(id, cur);
        }

        // Drop the stderr log so all of its output is written first
        drop(log);
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

                        for (i, crate_id) in license.1.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            if color {
                                let crate_ = crate_layout.search(crate_id);
                                let color = if crate_.licenses.len() > 1 {
                                    Color::Yellow
                                } else {
                                    Color::White
                                };

                                write!(
                                    output,
                                    "{}@{}",
                                    color.paint(crate_id.name),
                                    crate_id.version
                                )?;
                            } else {
                                write!(output, "{}@{}", crate_id.name, crate_id.version)?;
                            }
                        }

                        writeln!(output)?;
                    }

                    for (i, except) in license_layout.exceptions.iter().enumerate() {
                        if i != 0 {
                            write!(output, ", ")?;
                        }

                        if color {
                            write!(
                                output,
                                "{} ({}): ",
                                Color::Purple.paint(except.0),
                                Color::White.bold().paint(except.1.len().to_string())
                            )?;
                        } else {
                            write!(output, "{} ({}): ", except.0, except.1.len())?;
                        }

                        for (i, crate_id) in except.1.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            if color {
                                let crate_ = crate_layout.search(crate_id);
                                let color = if crate_.licenses.len() > 1 {
                                    Color::Yellow
                                } else {
                                    Color::White
                                };

                                write!(
                                    output,
                                    "{}@{}",
                                    color.paint(crate_id.name),
                                    crate_id.version
                                )?;
                            } else {
                                write!(output, "{}@{}", crate_id.name, crate_id.version)?;
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

                        for (i, crate_) in license_layout.unlicensed.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            write!(output, "{}@{}", crate_.name, crate_.version)?;
                        }

                        writeln!(output)?;
                    }
                }
                Layout::Crate => {
                    for (id, crate_) in crate_layout.crates {
                        if color {
                            let color = if crate_.licenses.len() > 1 {
                                Color::Yellow
                            } else if crate_.licenses.len() == 1 {
                                Color::White
                            } else {
                                Color::Red
                            };

                            write!(
                                output,
                                "{}@{} ({}): ",
                                color.paint(id.name),
                                id.version,
                                Color::White.bold().paint(
                                    (crate_.licenses.len() + crate_.exceptions.len()).to_string()
                                ),
                            )?;
                        } else {
                            write!(
                                output,
                                "{}@{} ({}): ",
                                id.name,
                                id.version,
                                crate_.licenses.len() + crate_.exceptions.len(),
                            )?;
                        }

                        for (i, license) in crate_.licenses.iter().enumerate() {
                            if i != 0 {
                                write!(output, ", ")?;
                            }

                            if color {
                                write!(output, "{}", Color::Cyan.paint(*license))?;
                            } else {
                                write!(output, "{}", license)?;
                            }
                        }

                        for exc in crate_.exceptions.iter() {
                            write!(output, ", ")?;

                            if color {
                                write!(output, "{}", Color::Purple.paint(*exc))?;
                            } else {
                                write!(output, "{}", exc)?;
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

                for exc in &license_layout.exceptions {
                    write!(output, "\t{}", exc.0)?;
                }

                if !license_layout.unlicensed.is_empty() {
                    write!(output, "\tUnlicensed")?;
                }

                writeln!(output)?;
            }

            for (id, crate_) in crate_layout.crates {
                write!(output, "{}@{}", id.name, id.version)?;

                for lic in &license_layout.licenses {
                    if lic.1.binary_search(&id).is_ok() {
                        write!(output, "\tX")?;
                    } else {
                        write!(output, "\t")?;
                    }
                }

                for exc in &license_layout.exceptions {
                    if exc.1.binary_search(&id).is_ok() {
                        write!(output, "\tX")?;
                    } else {
                        write!(output, "\t")?;
                    }
                }

                if crate_.licenses.is_empty() && crate_.exceptions.is_empty() {
                    write!(output, "\tX")?;
                }

                writeln!(output)?;
            }

            std::io::Write::write_all(&mut std::io::stdout(), output.as_bytes())?;
        }
    }

    Ok(())
}
