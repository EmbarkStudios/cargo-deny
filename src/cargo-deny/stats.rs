use crate::Format;
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

pub(crate) fn print_stats(
    stats: AllStats,
    show_stats: bool,
    log_level: log::LevelFilter,
    format: Format,
    color: crate::Color,
) -> Option<i32> {
    // In the case of human, we print to stdout, to distinguish it from the rest
    // of the output, but for JSON we still go to stderr since presumably computers
    // will be looking at that output and we don't want to confuse them
    match format {
        Format::Human => {
            let mut summary = String::new();

            let color = crate::common::should_colorize(color, std::io::stdout());

            // If we're using the default or higher log level, just emit
            // a single line, anything else gets a full table
            if show_stats || log_level > log::LevelFilter::Warn {
                write_full_stats(&mut summary, &stats, color);
            } else if log_level != log::LevelFilter::Off && log_level <= log::LevelFilter::Warn {
                write_min_stats(&mut summary, &stats, color);
            }

            #[allow(clippy::disallowed_macros)]
            if !summary.is_empty() {
                print!("{summary}");
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

    stats_to_exit_code(stats)
}

/// Given stats for checks, returns an exit code that is a bitset of the checks
/// that failed, or None if there were no errors
fn stats_to_exit_code(stats: AllStats) -> Option<i32> {
    let exit_code = [stats.advisories, stats.bans, stats.licenses, stats.sources]
        .into_iter()
        .enumerate()
        .fold(0, |mut acc, (i, stats)| {
            if stats.is_some_and(|s| s.errors > 0) {
                acc |= 1 << i;
            }
            acc
        });

    (exit_code > 0).then_some(exit_code)
}

fn write_min_stats(mut summary: &mut String, stats: &AllStats, color: bool) {
    let mut print_stats = |check: &str, stats: Option<&Stats>| {
        use std::fmt::Write;

        if let Some(stats) = stats {
            write!(&mut summary, "{check} ").unwrap();

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
                        "{check} {}",
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
                    format!("{check} {}", if stats.errors > 0 { "FAILED" } else { "ok" }),
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

#[cfg(test)]
mod test {
    use super::{stats_to_exit_code as ec, AllStats, Stats};

    #[test]
    fn exit_code() {
        assert!(ec(AllStats::default()).is_none());
        assert_eq!(
            Some(1),
            ec(AllStats {
                advisories: Some(Stats {
                    errors: 1,
                    ..Default::default()
                }),
                ..Default::default()
            })
        );
        assert_eq!(
            Some(2),
            ec(AllStats {
                bans: Some(Stats {
                    errors: 2,
                    ..Default::default()
                }),
                ..Default::default()
            })
        );
        assert_eq!(
            Some(4),
            ec(AllStats {
                licenses: Some(Stats {
                    errors: 4,
                    ..Default::default()
                }),
                ..Default::default()
            })
        );
        assert_eq!(
            Some(8),
            ec(AllStats {
                sources: Some(Stats {
                    errors: 8,
                    ..Default::default()
                }),
                ..Default::default()
            })
        );
        assert_eq!(
            Some(1 | 2 | 4 | 8),
            ec(AllStats {
                advisories: Some(Stats {
                    errors: 8,
                    ..Default::default()
                }),
                bans: Some(Stats {
                    errors: 4,
                    ..Default::default()
                }),
                licenses: Some(Stats {
                    errors: 2,
                    ..Default::default()
                }),
                sources: Some(Stats {
                    errors: 1,
                    ..Default::default()
                }),
            })
        );
    }
}
