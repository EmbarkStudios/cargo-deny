use crate::{
    diag::{Diagnostic, FileId, Label},
    LintLevel, PathBuf, Spanned,
};
use rustsec::advisory;
use serde::Deserialize;
use url::Url;

#[allow(clippy::reversed_empty_ranges)]
const fn yanked() -> Spanned<LintLevel> {
    Spanned::new(LintLevel::Warn, 0..0)
}

#[allow(clippy::reversed_empty_ranges)]
fn ninety_days() -> Spanned<String> {
    Spanned::new("P90D".to_owned(), 0..0)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Path to the root directory where advisory databases are stored (default: $CARGO_HOME/advisory-dbs)
    pub db_path: Option<PathBuf>,
    /// List of urls to git repositories of different advisory databases.
    #[serde(default)]
    pub db_urls: Vec<Spanned<String>>,
    /// How to handle crates that have a security vulnerability
    #[serde(default = "crate::lint_deny")]
    pub vulnerability: LintLevel,
    /// How to handle crates that have been marked as unmaintained in an advisory database
    #[serde(default = "crate::lint_warn")]
    pub unmaintained: LintLevel,
    /// How to handle crates that have been marked as unsound in an advisory database
    #[serde(default = "crate::lint_warn")]
    pub unsound: LintLevel,
    /// How to handle crates that have been yanked from eg crates.io
    #[serde(default = "yanked")]
    pub yanked: Spanned<LintLevel>,
    /// How to handle crates that have been marked with a notice in the advisory database
    #[serde(default = "crate::lint_warn")]
    pub notice: LintLevel,
    /// Ignore advisories for the given IDs
    #[serde(default)]
    pub ignore: Vec<Spanned<advisory::Id>>,
    /// CVSS Qualitative Severity Rating Scale threshold to alert at.
    ///
    /// Vulnerabilities with explicit CVSS info which have a severity below
    /// this threshold will be ignored.
    pub severity_threshold: Option<advisory::Severity>,
    /// Use the git executable to fetch advisory database rather than gitoxide
    pub git_fetch_with_cli: Option<bool>,
    /// If set to true, the local crates indices are not checked for yanked crates
    #[serde(default)]
    pub disable_yank_checking: bool,
    /// The maximum duration, in RFC3339 format, that an advisory database is
    /// allowed to not have been updated. This only applies when fetching advisory
    /// databases has been disabled. Defaults to 90 days.
    ///
    /// Note that if fractional units are used in the format string they must
    /// use the '.' separator instead of ',' which is used by some locales and
    /// supported in the RFC3339 format, but not by this implementation
    #[serde(default = "ninety_days")]
    pub maximum_db_staleness: Spanned<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: None,
            db_urls: Vec::new(),
            ignore: Vec::new(),
            vulnerability: LintLevel::Deny,
            unmaintained: LintLevel::Warn,
            unsound: LintLevel::Warn,
            yanked: yanked(),
            notice: LintLevel::Warn,
            severity_threshold: None,
            git_fetch_with_cli: None,
            disable_yank_checking: false,
            maximum_db_staleness: ninety_days(),
        }
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId, diags: &mut Vec<Diagnostic>) -> Self::ValidCfg {
        let mut ignored: Vec<_> = self.ignore.into_iter().map(AdvisoryId::from).collect();
        ignored.sort();

        let mut db_urls: Vec<_> = self
            .db_urls
            .into_iter()
            .filter_map(|dburl| match crate::cfg::parse_url(cfg_file, dburl) {
                Ok(u) => Some(u),
                Err(diag) => {
                    diags.push(diag);
                    None
                }
            })
            .collect();

        db_urls.sort();

        // Warn about duplicates before removing them so the user can cleanup their config
        if db_urls.len() > 1 {
            for window in db_urls.windows(2) {
                if window[0] == window[1] {
                    diags.push(
                        Diagnostic::warning()
                            .with_message("duplicate advisory database url detected")
                            .with_labels(vec![
                                Label::secondary(cfg_file, window[0].span.clone()),
                                Label::secondary(cfg_file, window[1].span.clone()),
                            ]),
                    );
                }
            }
        }

        db_urls.dedup();

        // Require that each url has a valid domain name for when we splat it to a local path
        for url in &db_urls {
            if url.value.domain().is_none() {
                diags.push(
                    Diagnostic::error()
                        .with_message("advisory database url doesn't have a domain name")
                        .with_labels(vec![Label::secondary(cfg_file, url.span.clone())]),
                );
            }
        }

        let maximum_db_staleness = match parse_rfc3339_duration(&self.maximum_db_staleness.value) {
            Ok(mds) => mds,
            Err(err) => {
                diags.push(
                    Diagnostic::error()
                        .with_message("failed to parse RFC3339 duration")
                        .with_labels(vec![Label::secondary(
                            cfg_file,
                            self.maximum_db_staleness.span.clone(),
                        )])
                        .with_notes(vec![err.to_string()]),
                );
                // Use the 90 days default as a fallback
                time::Duration::seconds_f64(90. * 24. * 60. * 60. * 60.)
            }
        };

        ValidConfig {
            file_id: cfg_file,
            db_path: self.db_path,
            db_urls,
            ignore: ignored,
            vulnerability: self.vulnerability,
            unmaintained: self.unmaintained,
            unsound: self.unsound,
            yanked: self.yanked,
            notice: self.notice,
            severity_threshold: self.severity_threshold,
            git_fetch_with_cli: self.git_fetch_with_cli.unwrap_or_default(),
            disable_yank_checking: self.disable_yank_checking,
            maximum_db_staleness,
        }
    }
}

pub(crate) type AdvisoryId = Spanned<advisory::Id>;

pub struct ValidConfig {
    pub file_id: FileId,
    pub db_path: Option<PathBuf>,
    pub db_urls: Vec<Spanned<Url>>,
    pub(crate) ignore: Vec<AdvisoryId>,
    pub vulnerability: LintLevel,
    pub unmaintained: LintLevel,
    pub unsound: LintLevel,
    pub yanked: Spanned<LintLevel>,
    pub notice: LintLevel,
    pub severity_threshold: Option<advisory::Severity>,
    pub git_fetch_with_cli: bool,
    pub disable_yank_checking: bool,
    pub maximum_db_staleness: time::Duration,
}

/// We need to implement this ourselves since time doesn't support it
/// <https://github.com/time-rs/time/issues/571>
///
/// ```text
/// dur-second        = 1*DIGIT "S"
/// dur-minute        = 1*DIGIT "M" [dur-second]
/// dur-hour          = 1*DIGIT "H" [dur-minute]
/// dur-time          = "T" (dur-hour / dur-minute / dur-second)
/// dur-day           = 1*DIGIT "D"
/// dur-week          = 1*DIGIT "W"
/// dur-month         = 1*DIGIT "M" [dur-day]
/// dur-year          = 1*DIGIT "Y" [dur-month]
/// dur-date          = (dur-day / dur-month / dur-year) [dur-time]
///
/// duration          = "P" (dur-date / dur-time / dur-week)
/// ```
fn parse_rfc3339_duration(value: &str) -> anyhow::Result<time::Duration> {
    use anyhow::Context as _;

    let mut value = value
        .strip_prefix('P')
        .context("duration requires 'P' prefix")?;

    // The units that are allowed in the format, in the exact order they must be
    // in, ie it is invalid to specify a unit that is lower in this order than
    // one that has already been parsed
    const UNITS: &[(char, f64)] = &[
        ('D', 24. * 60. * 60.),
        // We calculate the length of the month by just getting the mean of all
        // the months, and use 28.25 for February
        ('M', 30.43 * 24. * 60. * 60.),
        // Years we just use the standard 365 days and ignore leap years
        ('Y', 365. * 24. * 60. * 60.),
        ('W', 7. * 24. * 60. * 60.),
        ('H', 60. * 60.),
        ('M', 60.),
        ('S', 1.),
        ('W', 7. * 24. * 60. * 60.),
    ];

    // Validate the string only contains valid characters to simplify the rest
    // of the function
    for c in value.chars() {
        if c == ',' {
            anyhow::bail!("'{c}' is valid in the RFC-3339 duration format but not supported by this implementation, use '.' instead");
        }

        if c != '.' && c != 'T' && !c.is_ascii_digit() && !UNITS.iter().any(|(uc, _)| c == *uc) {
            anyhow::bail!("'{c}' is not valid in the RFC-3339 duration format");
        }
    }

    #[derive(Copy, Clone, PartialEq, PartialOrd)]
    enum Unit {
        Empty,
        Day,
        Month,
        Year,
        Time,
        Hour,
        Minute,
        Second,
        Week,
    }

    impl Unit {
        #[inline]
        fn from(c: char, is_time: bool) -> Self {
            match c {
                'D' => Self::Day,
                'T' => Self::Time,
                'H' => Self::Hour,
                'M' => {
                    if is_time {
                        Self::Minute
                    } else {
                        Self::Month
                    }
                }
                'S' => Self::Second,
                'Y' => Self::Year,
                'W' => Self::Week,
                other => unreachable!("'{other}' should be impossible"),
            }
        }
    }

    let mut duration = time::Duration::new(0, 0);

    // The format requires that the units are in a specific order, but each
    // unit is optional
    let mut last_unit = Unit::Empty;
    let mut last_unitc = '_';
    let mut supplied_units = 0;
    // According to the spec, the T is required before any hour/minute/second units
    // are allowed
    let mut is_time = false;

    while !value.is_empty() {
        let unit_index = value
            .find(|c: char| c.is_ascii_uppercase())
            .context("unit not specified")?;

        let unitc = value.as_bytes()[unit_index] as char;
        let unit = Unit::from(unitc, is_time);

        anyhow::ensure!(
            unit > last_unit,
            "unit '{unitc}' cannot follow '{last_unitc}'"
        );

        if unit == Unit::Time {
            anyhow::ensure!(
                unit_index == 0,
                "unit not specified for value '{}'",
                &value[..unit_index]
            );
            is_time = true;
        } else {
            anyhow::ensure!(unit_index != 0, "value not specified for '{unitc}'");

            let uvs = &value[..unit_index];
            let unit_value: f64 = uvs
                .parse()
                .with_context(|| "failed to parse value '{uvs}' for unit '{unit}'")?;

            supplied_units += 1;

            anyhow::ensure!(
                !matches!(unit, Unit::Hour | Unit::Minute | Unit::Second) || is_time,
                "'{unitc}' must be preceded with 'T'"
            );

            // This would be nicer if 'M' couldn't mean both months and minutes :p
            let block = if is_time { &UNITS[4..] } else { &UNITS[..4] };
            let unit_to_seconds = block
                .iter()
                .find_map(|(c, uts)| (*c == unitc).then_some(*uts))
                .unwrap();

            duration += time::Duration::checked_seconds_f64(unit_value * unit_to_seconds)
                .with_context(|| format!("value '{unit_value}' for '{unitc}' is out of range"))?;
        }

        last_unitc = unitc;
        last_unit = unit;
        value = &value[unit_index + 1..];
    }

    anyhow::ensure!(supplied_units > 0, "must supply at least one time unit");

    Ok(duration)
}

#[cfg(test)]
mod test {
    use super::{parse_rfc3339_duration as dur_parse, *};
    use crate::cfg::{test::*, Fake, UnvalidatedConfig};

    #[test]
    fn deserializes_advisories_cfg() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Advisories {
            advisories: Config,
        }

        let cd: ConfigData<Advisories> = load("tests/cfg/advisories.toml");
        let mut diags = Vec::new();
        let validated = cd.config.advisories.validate(cd.id, &mut diags);
        assert!(
            !diags
                .iter()
                .any(|d| d.severity >= crate::diag::Severity::Error),
            "{diags:#?}"
        );

        assert_eq!(validated.file_id, cd.id);
        assert!(validated
            .db_path
            .iter()
            .map(|dp| dp.as_str())
            .eq(vec!["~/.cargo/advisory-dbs"]));
        assert!(validated.db_urls.iter().eq(vec![&Url::parse(
            "https://github.com/RustSec/advisory-db"
        )
        .unwrap()
        .fake()]));
        assert_eq!(validated.vulnerability, LintLevel::Deny);
        assert_eq!(validated.unmaintained, LintLevel::Warn);
        assert_eq!(validated.unsound, LintLevel::Warn);
        assert_eq!(validated.yanked, LintLevel::Warn);
        assert_eq!(validated.notice, LintLevel::Warn);
        assert_eq!(
            validated.ignore,
            vec!["RUSTSEC-0000-0000"
                .parse::<rustsec::advisory::Id>()
                .unwrap()]
        );
        assert_eq!(
            validated.severity_threshold,
            Some(rustsec::advisory::Severity::Medium)
        );
    }

    /// Validates we reject invalid formats, or at least ones we don't support
    #[test]
    fn rejects_invalid_durations() {
        const FAILURES: &[&str] = &[
            "no-P", // Format requires 'P' at the beginning
            "P", "PT", // Empty duration, must specify at least _one_ unit
            "P1H3", "P2TH3", // Number without unit specified
            "PT1HM", // Unit without number specified
            "PT1M3H", "P3Y1M", "P2W1Y", "PT2W1H", // Units in an invalid order
            "P5H", "P5S", // Time units must be preceded by T
            // We don't accept ',' as a decimal separator even though it is allowed in the spec
            "PT1,5S",
        ];

        let failures: String = FAILURES
            .iter()
            .map(|bad| format!("{:?}\n", dur_parse(bad)))
            .collect();

        insta::assert_snapshot!(failures);
    }

    /// Validates we can parse many durations.
    ///
    /// Note the values were copied from <https://ijmacd.github.io/rfc3339-iso8601/>
    /// but at least according to the grammar in the RFC...many were actually invalid :p
    #[test]
    fn parses_valid_durations() {
        const DAY: f64 = 24. * 60. * 60.;
        const MONTH: f64 = 30.43 * DAY;
        const TABLE: &[(&str, f64)] = &[
            ("P1Y", 365. * DAY),
            ("P1.5Y", 365. * 1.5 * DAY),
            ("P1M", MONTH),
            ("P2W", 7. * 2. * DAY),
            ("P3D", 3. * DAY),
            ("PT4H", 4. * 60. * 60.),
            ("PT2M", 2. * 60.),
            ("PT8S", 8.),
            ("PT8.5S", 8.5),
            ("P3M1Y", 3. * MONTH + 365. * DAY),
            ("P5D1Y", 5. * DAY + 365. * DAY),
            ("P3D4M1Y", 3. * DAY + 4. * MONTH + 365. * DAY),
            (
                "P2D3M1YT3H2M1S",
                2. * DAY + 3. * MONTH + 365. * DAY + 3. * 60. * 60. + 2. * 60. + 1.,
            ),
            ("P2DT4H", 2. * DAY + 4. * 60. * 60.),
            ("P2MT0.5M", 2. * MONTH + 0.5 * 60.),
            ("P5DT1.6M", 5. * DAY + 60. * 1.6),
            ("P1.5W", 7. * 1.5 * DAY),
            ("P3D1.5W", 3. * DAY + 7. * 1.5 * DAY),
            ("P2DT3.002S", 2. * DAY + 3.002),
            ("P2DT3.02003S", 2. * DAY + 3.02003),
            ("P2DT4H3M2.6S", 2. * DAY + 4. * 60. * 60. + 3. * 60. + 2.6),
            ("PT3H2M1.1S", 3. * 60. * 60. + 2. * 60. + 1.1),
        ];

        for (dur, secs) in TABLE {
            match dur_parse(dur) {
                Ok(parsed) => {
                    assert_eq!(
                        parsed,
                        time::Duration::seconds_f64(*secs),
                        "unexpected duration for '{dur}'"
                    );
                }
                Err(err) => {
                    panic!("failed to parse '{dur}': {err:#}");
                }
            }
        }
    }
}
