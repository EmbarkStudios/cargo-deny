use crate::Format;
use is_terminal::IsTerminal as _;
use nu_ansi_term::Color;
use serde::Serialize;

#[derive(Default, Serialize)]
pub struct Stats {
    pub errors: u32,
    pub warnings: u32,
    pub notes: u32,
    pub helps: u32,
}

#[derive(Default, Serialize)]
pub struct AllStats {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisories: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bans: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Stats>,
}

impl AllStats {
    pub fn total_errors(&self) -> u32 {
        self.advisories.as_ref().map_or(0, |s| s.errors)
            + self.bans.as_ref().map_or(0, |s| s.errors)
            + self.licenses.as_ref().map_or(0, |s| s.errors)
            + self.sources.as_ref().map_or(0, |s| s.errors)
    }
}

pub(crate) fn print_stats(
    stats: AllStats,
    show_stats: bool,
    log_level: log::LevelFilter,
    format: Format,
    color: crate::Color,
) {
    // In the case of human, we print to stdout, to distinguish it from the rest
    // of the output, but for JSON we still go to stderr since presumably computers
    // will be looking at that output and we don't want to confuse them
    match format {
        Format::Human => {
            let mut summary = String::new();

            let color = match color {
                crate::Color::Auto => std::io::stdout().is_terminal(),
                crate::Color::Always => true,
                crate::Color::Never => false,
            };

            // If we're using the default or higher log level, just emit
            // a single line, anything else gets a full table
            if show_stats || log_level > log::LevelFilter::Warn {
                write_full_stats(&mut summary, &stats, color);
            } else if log_level != log::LevelFilter::Off && log_level <= log::LevelFilter::Warn {
                write_min_stats(&mut summary, &stats, color);
            }

            if !summary.is_empty() {
                print!("{}", summary);
            }
        }
        Format::Json => {
            let ssummary = serde_json::json!({
                "type": "summary",
                "fields": serde_json::to_value(&stats).unwrap(),
            });

            let to_print = serde_json::to_vec(&ssummary).unwrap();

            use std::io::Write;
            let stderr = std::io::stderr();
            let mut el = stderr.lock();
            let _ = el.write_all(&to_print);
            let _ = el.write(b"\n");
        }
    }
}

fn write_min_stats(mut summary: &mut String, stats: &AllStats, color: bool) {
    let mut print_stats = |check: &str, stats: Option<&Stats>| {
        use std::fmt::Write;

        if let Some(stats) = stats {
            write!(&mut summary, "{} ", check).unwrap();

            if color {
                write!(
                    &mut summary,
                    "{}, ",
                    if stats.errors > 0 {
                        Color::Red.paint("FAILED")
                    } else {
                        Color::Green.paint("ok")
                    }
                )
                .unwrap();
            } else {
                write!(
                    &mut summary,
                    "{}, ",
                    if stats.errors > 0 { "FAILED" } else { "ok" }
                )
                .unwrap();
            }
        }
    };

    print_stats("advisories", stats.advisories.as_ref());
    print_stats("bans", stats.bans.as_ref());
    print_stats("licenses", stats.licenses.as_ref());
    print_stats("sources", stats.sources.as_ref());

    // Remove trailing ", "
    summary.pop();
    summary.pop();
    summary.push('\n');
}

fn write_full_stats(summary: &mut String, stats: &AllStats, color: bool) {
    let column = {
        let mut max = 0;
        let mut count = |check: &str, s: Option<&Stats>| {
            max = std::cmp::max(
                max,
                s.map_or(0, |s| {
                    let status = if s.errors > 0 {
                        "FAILED".len()
                    } else {
                        "ok".len()
                    };

                    status + check.len()
                }),
            );
        };

        count("advisories", stats.advisories.as_ref());
        count("bans", stats.bans.as_ref());
        count("licenses", stats.licenses.as_ref());
        count("sources", stats.sources.as_ref());

        max + 2 /* spaces */ + if color { 9 /* color escapes */ } else { 0 }
    };

    let mut print_stats = |check: &str, stats: Option<&Stats>| {
        use std::fmt::Write;

        if let Some(stats) = stats {
            if color {
                writeln!(
                    summary,
                    "{:>column$}: {} errors, {} warnings, {} notes",
                    format!(
                        "{} {}",
                        check,
                        if stats.errors > 0 {
                            Color::Red.paint("FAILED")
                        } else {
                            Color::Green.paint("ok")
                        }
                    ),
                    Color::Red.paint(format!("{}", stats.errors)),
                    Color::Yellow.paint(format!("{}", stats.warnings)),
                    Color::Blue.paint(format!("{}", stats.notes + stats.helps)),
                    column = column,
                )
                .unwrap();
            } else {
                writeln!(
                    summary,
                    "{:>column$}: {} errors, {} warnings, {} notes",
                    format!(
                        "{} {}",
                        check,
                        if stats.errors > 0 { "FAILED" } else { "ok" }
                    ),
                    stats.errors,
                    stats.warnings,
                    stats.notes + stats.helps,
                    column = column,
                )
                .unwrap();
            }
        }
    };

    print_stats("advisories", stats.advisories.as_ref());
    print_stats("bans", stats.bans.as_ref());
    print_stats("licenses", stats.licenses.as_ref());
    print_stats("sources", stats.sources.as_ref());
}
