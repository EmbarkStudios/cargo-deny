use crate::common::MessageFormat;
use ansi_term::Color;
use cargo_deny::licenses;
use failure::Error;
use slog::warn;
use structopt::StructOpt;

#[derive(Copy, Clone, Debug)]
pub enum ColorWhen {
    Always,
    Never,
    Auto,
}

impl std::str::FromStr for ColorWhen {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let c = match s {
            "auto" => ColorWhen::Auto,
            "always" => ColorWhen::Always,
            "never" => ColorWhen::Never,
            s => failure::bail!("unknown coloring flag '{}'", s),
        };

        Ok(c)
    }
}

#[derive(StructOpt, Debug)]
pub struct Args {
    /// The confidence threshold required for license files
    /// to be positively identified
    #[structopt(short, long, default_value = "0.8")]
    threshold: f32,
    /// The format of the output
    #[structopt(short, long, default_value = "human")]
    format: MessageFormat,
    /// Output coloring: 'auto', 'always', or 'never'
    #[structopt(long, default_value = "auto")]
    color: ColorWhen,
}

pub fn cmd(
    log: slog::Logger,
    args: Args,
    crates: cargo_deny::Crates,
    store: Option<licenses::LicenseStore>,
) -> Result<(), Error> {
    use cargo_deny::binary_search;
    use licenses::{Note, Summary};
    use std::{
        cmp::Ordering,
        collections::{BTreeMap, HashMap},
        fmt::{self, Write},
    };
    let gatherer = licenses::Gatherer::new(log.new(slog::o!("stage" => "license_gather")))
        .with_store(std::sync::Arc::new(
            store.expect("we should have a license store"),
        ))
        .with_confidence_threshold(args.threshold);

    let summary = gatherer.gather(crates.as_ref(), HashMap::new());

    #[derive(PartialEq, Eq, Ord)]
    enum Key<'a> {
        License(&'a str),
        Exception(&'a str),
        Unlicensed,
    }

    impl<'a> fmt::Display for Key<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let s = match self {
                Key::License(l) => l,
                Key::Exception(e) => e,
                Key::Unlicensed => "Unlicensed",
            };

            write!(f, "{}", s)
        }
    }

    impl<'a> serde::Serialize for Key<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                Key::License(l) => s.serialize_str(l),
                Key::Exception(e) => s.serialize_str(e),
                Key::Unlicensed => s.serialize_str("Unlicensed"),
            }
        }
    }

    impl<'a> std::cmp::PartialOrd for Key<'a> {
        fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
            match (self, o) {
                (Key::License(a), Key::License(b)) => a.partial_cmp(b),
                (Key::Exception(a), Key::Exception(b)) => a.partial_cmp(b),
                (Key::License(_), _) => Some(Ordering::Less),
                (_, Key::License(_)) => Some(Ordering::Greater),
                (Key::Unlicensed, Key::Unlicensed) => Some(Ordering::Equal),
                (Key::Unlicensed, _) => Some(Ordering::Greater),
                (_, Key::Unlicensed) => Some(Ordering::Less),
            }
        }
    }

    let mut license_map: BTreeMap<Key<'_>, Vec<String>> = BTreeMap::new();

    for crate_note in summary.notes() {
        for note in &crate_note.notes {
            match note {
                Note::License { name, .. } => {
                    let license_name = Summary::resolve_id(*name);

                    let key = Key::License(license_name);
                    match license_map.get_mut(&key) {
                        Some(v) => {
                            if let Err(i) = binary_search(v, crate_note.name) {
                                v.insert(i, crate_note.name.to_owned());
                            }
                        }
                        None => {
                            license_map.insert(key, vec![crate_note.name.to_owned()]);
                        }
                    }
                }
                Note::Unlicensed => match license_map.get_mut(&Key::Unlicensed) {
                    Some(v) => {
                        if let Err(i) = binary_search(v, crate_note.name) {
                            v.insert(i, crate_note.name.to_owned());
                        }
                    }
                    None => {
                        license_map.insert(Key::Unlicensed, vec![crate_note.name.to_owned()]);
                    }
                },
                Note::Exception(exc) => {
                    let key = Key::Exception(exc);
                    match license_map.get_mut(&key) {
                        Some(v) => {
                            if let Err(i) = binary_search(v, crate_note.name) {
                                v.insert(i, crate_note.name.to_owned());
                            }
                        }
                        None => {
                            license_map.insert(key, vec![crate_note.name.to_owned()]);
                        }
                    }
                }
                Note::Unknown { name, source } => {
                    warn!(
                        log,
                        "detected an unknown license";
                        "crate" => crate_note,
                        "src" => source,
                    );

                    let key = Key::License(name);
                    match license_map.get_mut(&key) {
                        Some(v) => {
                            if let Err(i) = binary_search(v, crate_note.name) {
                                v.insert(i, crate_note.name.to_owned());
                            }
                        }
                        None => {
                            license_map.insert(key, vec![crate_note.name.to_owned()]);
                        }
                    }
                }
                Note::LowConfidence { score, source } => {
                    warn!(
                        log,
                        "unable to determine license with high confidence";
                        "crate" => crate_note,
                        "score" => score,
                        "src" => source,
                    );
                }
                Note::UnreadableLicense { path, err } => {
                    warn!(
                        log,
                        "license file is unreadable";
                        "crate" => crate_note,
                        "path" => path.display(),
                        "err" => err.to_string(), // io::Error makes slog sad
                    );
                }
                Note::Ignored(_) => unreachable!(),
            }
        }
    }

    // Drop the stderr log so all of its output is written first
    drop(log);

    match args.format {
        MessageFormat::Human => {
            let mut output = String::with_capacity(4 * 1024);
            let color = match args.color {
                ColorWhen::Always => true,
                ColorWhen::Never => false,
                ColorWhen::Auto => atty::is(atty::Stream::Stdout),
            };

            for (k, v) in license_map {
                if color {
                    write!(
                        output,
                        "{}",
                        match k {
                            Key::License(l) => Color::Cyan.paint(l),
                            Key::Exception(e) => Color::Purple.paint(e),
                            Key::Unlicensed => Color::Red.paint("Unlicensed"),
                        }
                    )?;

                    write!(
                        output,
                        " ({}): ",
                        Color::White.bold().paint(v.len().to_string())
                    )?;
                } else {
                    write!(output, "{} ({}): ", k, v.len())?;
                }

                for (i, crate_name) in v.iter().enumerate() {
                    if i != 0 {
                        write!(output, ", {}", crate_name)?;
                    } else {
                        write!(output, "{}", crate_name)?;
                    }
                }

                writeln!(output)?;
            }

            std::io::Write::write_all(&mut std::io::stdout(), output.as_bytes())?;
        }
        MessageFormat::Json => {
            serde_json::to_writer(std::io::stdout(), &license_map)?;
        }
    }

    Ok(())
}
