use crate::{
    cfg::{PackageSpecOrExtended, Reason, ValidationContext},
    diag::{Diagnostic, FileId, Label},
    LintLevel, PathBuf, Span, Spanned,
};
use rustsec::advisory;
use time::Duration;
use toml_span::{de_helpers::*, value::ValueInner};
use url::Url;

pub struct Config {
    /// Path to the root directory where advisory databases are stored (default: $CARGO_HOME/advisory-dbs)
    pub db_path: Option<PathBuf>,
    /// List of urls to git repositories of different advisory databases.
    pub db_urls: Vec<Spanned<Url>>,
    /// How to handle crates that have a security vulnerability
    pub vulnerability: LintLevel,
    /// How to handle crates that have been marked as unmaintained in an advisory database
    pub unmaintained: LintLevel,
    /// How to handle crates that have been marked as unsound in an advisory database
    pub unsound: LintLevel,
    /// How to handle crates that have been yanked from eg crates.io
    pub yanked: Spanned<LintLevel>,
    /// How to handle crates that have been marked with a notice in the advisory database
    pub notice: LintLevel,
    /// Ignore advisories for the given IDs
    pub ignore: Vec<AdvisoryId>,
    /// Ignore yanked crates
    pub ignore_yanked: Vec<Spanned<PackageSpecOrExtended<Reason>>>,
    /// CVSS Qualitative Severity Rating Scale threshold to alert at.
    ///
    /// Vulnerabilities with explicit CVSS info which have a severity below
    /// this threshold will be ignored.
    pub severity_threshold: Option<advisory::Severity>,
    /// Use the git executable to fetch advisory database rather than gitoxide
    pub git_fetch_with_cli: Option<bool>,
    /// If set to true, the local crates indices are not checked for yanked crates
    pub disable_yank_checking: bool,
    /// The maximum duration, in RFC3339 format, that an advisory database is
    /// allowed to not have been updated. This only applies when fetching advisory
    /// databases has been disabled. Defaults to 90 days.
    ///
    /// Note that if fractional units are used in the format string they must
    /// use the '.' separator instead of ',' which is used by some locales and
    /// supported in the RFC3339 format, but not by this implementation
    pub maximum_db_staleness: Spanned<Duration>,
    deprecated: Vec<Span>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: None,
            db_urls: Vec::new(),
            ignore: Vec::new(),
            ignore_yanked: Vec::new(),
            vulnerability: LintLevel::Deny,
            unmaintained: LintLevel::Warn,
            unsound: LintLevel::Warn,
            yanked: Spanned::new(LintLevel::Warn),
            notice: LintLevel::Warn,
            severity_threshold: None,
            git_fetch_with_cli: None,
            disable_yank_checking: false,
            maximum_db_staleness: Spanned::new(Duration::seconds_f64(NINETY_DAYS)),
            deprecated: Vec::new(),
        }
    }
}

const NINETY_DAYS: f64 = 90. * 24. * 60. * 60. * 60.;

impl<'de> toml_span::Deserialize<'de> for Config {
    fn deserialize(
        value: &mut toml_span::value::Value<'de>,
    ) -> Result<Self, toml_span::DeserError> {
        let mut th = toml_span::de_helpers::TableHelper::new(value)?;

        let db_path = th.optional::<String>("db-path").map(PathBuf::from);
        let db_urls = if let Some((_, mut urls)) = th.take("db-urls") {
            let mut u = Vec::new();

            match urls.take() {
                ValueInner::Array(urla) => {
                    for mut v in urla {
                        match parse(&mut v) {
                            Ok(url) => u.push(Spanned::with_span(url, v.span)),
                            Err(err) => th.errors.push(err),
                        }
                    }
                }
                other => {
                    th.errors.push(expected("an array", other, urls.span));
                }
            }

            u.sort();
            u
        } else {
            Vec::new()
        };

        use crate::cfg::deprecated;

        let mut fdeps = Vec::new();

        let vulnerability =
            deprecated(&mut th, "vulnerability", &mut fdeps).unwrap_or(LintLevel::Deny);
        let unmaintained =
            deprecated(&mut th, "unmaintained", &mut fdeps).unwrap_or(LintLevel::Warn);
        let unsound = deprecated(&mut th, "unsound", &mut fdeps).unwrap_or(LintLevel::Warn);
        let yanked = th
            .optional_s("yanked")
            .unwrap_or(Spanned::new(LintLevel::Warn));
        let notice = deprecated(&mut th, "notice", &mut fdeps).unwrap_or(LintLevel::Warn);
        let (ignore, ignore_yanked) = if let Some((_, mut ignore)) = th.take("ignore") {
            let mut u = Vec::new();
            let mut y = Vec::new();

            match ignore.take() {
                ValueInner::Array(ida) => {
                    for mut v in ida {
                        let inner = v.take();
                        if let ValueInner::String(s) = &inner {
                            // Attempt to parse an advisory id first, note we can't
                            // just immediately use parse as the from_str implementation
                            // for id will just blindly accept any string
                            if advisory::IdKind::detect(s.as_ref()) != advisory::IdKind::Other {
                                if let Ok(id) = s.parse::<advisory::Id>() {
                                    u.push(Spanned::with_span(id, v.span));
                                    continue;
                                }
                            }
                        }

                        let found = inner.type_str();
                        v.set(inner);

                        match PackageSpecOrExtended::deserialize(&mut v) {
                            Ok(pse) => y.push(Spanned::with_span(pse, v.span)),
                            Err(_err) => {
                                th.errors.push(toml_span::Error {
                                    kind: toml_span::ErrorKind::Wanted {
                                        expected: "an advisory id or package spec",
                                        found,
                                    },
                                    span: v.span,
                                    line_info: None,
                                });
                            }
                        }
                    }
                }
                other => {
                    th.errors.push(expected("an array", other, ignore.span));
                }
            }

            u.sort();
            (u, y)
        } else {
            (Vec::new(), Vec::new())
        };
        let st = |th: &mut TableHelper<'_>, fdeps: &mut Vec<Span>| {
            let (k, mut v) = th.take("severity-threshold")?;

            fdeps.push(k.span);
            let s = match v.take_string(Some(
                "https://docs.rs/rustsec/latest/rustsec/advisory/enum.Severity.html",
            )) {
                Ok(s) => s,
                Err(err) => {
                    th.errors.push(err);
                    return None;
                }
            };

            match s.parse() {
                Ok(st) => Some(st),
                Err(err) => {
                    th.errors.push(
                        (
                            toml_span::ErrorKind::Custom(
                                format!("failed to parse rustsec::Severity: {err}").into(),
                            ),
                            v.span,
                        )
                            .into(),
                    );
                    None
                }
            }
        };

        let severity_threshold = st(&mut th, &mut fdeps);
        let git_fetch_with_cli = th.optional("git-fetch-with-cli");
        let disable_yank_checking = th.optional("disable-yank-checking").unwrap_or_default();
        let maximum_db_staleness = if let Some((_, mut val)) = th.take("maximum-db-staleness") {
            match val.take_string(Some("an RFC3339 time duration")) {
                Ok(mds) => match parse_rfc3339_duration(&mds) {
                    Ok(mds) => Some(Spanned::with_span(mds, val.span)),
                    Err(err) => {
                        th.errors.push(
                            (
                                toml_span::ErrorKind::Custom(err.to_string().into()),
                                val.span,
                            )
                                .into(),
                        );
                        None
                    }
                },
                Err(err) => {
                    th.errors.push(err);
                    None
                }
            }
        } else {
            None
        };

        th.finalize(None)?;

        // Use the 90 days default as a fallback
        let maximum_db_staleness = maximum_db_staleness
            .unwrap_or_else(|| Spanned::new(Duration::seconds_f64(NINETY_DAYS)));

        Ok(Self {
            db_path,
            db_urls,
            vulnerability,
            unmaintained,
            unsound,
            yanked,
            notice,
            ignore,
            ignore_yanked,
            severity_threshold,
            git_fetch_with_cli,
            disable_yank_checking,
            maximum_db_staleness,
            deprecated: fdeps,
        })
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, mut ctx: ValidationContext<'_>) -> Self::ValidCfg {
        let mut ignore = self.ignore;
        let mut ignore_yanked = self.ignore_yanked;
        let mut db_urls = self.db_urls;

        ctx.dedup(&mut ignore);
        ctx.dedup(&mut ignore_yanked);
        ctx.dedup(&mut db_urls);

        // Require that each url has a valid domain name for when we splat it to a local path
        for url in &db_urls {
            if url.value.domain().is_none() {
                ctx.push(
                    Diagnostic::error()
                        .with_message("advisory database url doesn't have a domain name")
                        .with_labels(vec![Label::secondary(ctx.cfg_id, url.span)]),
                );
            }
        }

        use crate::diag::general::{Deprecated, DeprecationReason};

        // Output any deprecations, we'll remove the fields at the same time we
        // remove all the logic they drive
        for dep in self.deprecated {
            ctx.push(
                Deprecated {
                    reason: DeprecationReason::WillBeRemoved(Some(
                        "https://github.com/EmbarkStudios/cargo-deny/pull/606",
                    )),
                    key: dep,
                    file_id: ctx.cfg_id,
                }
                .into(),
            );
        }

        ValidConfig {
            file_id: ctx.cfg_id,
            db_path: self.db_path,
            db_urls,
            ignore,
            ignore_yanked: ignore_yanked
                .into_iter()
                .map(|s| crate::bans::SpecAndReason {
                    spec: s.value.spec,
                    reason: s.value.inner,
                    use_instead: None,
                    file_id: ctx.cfg_id,
                })
                .collect(),
            vulnerability: self.vulnerability,
            unmaintained: self.unmaintained,
            unsound: self.unsound,
            yanked: self.yanked,
            notice: self.notice,
            severity_threshold: self.severity_threshold,
            git_fetch_with_cli: self.git_fetch_with_cli.unwrap_or_default(),
            disable_yank_checking: self.disable_yank_checking,
            maximum_db_staleness: self.maximum_db_staleness,
        }
    }
}

pub(crate) type AdvisoryId = Spanned<advisory::Id>;

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidConfig {
    pub file_id: FileId,
    pub db_path: Option<PathBuf>,
    pub db_urls: Vec<Spanned<Url>>,
    pub(crate) ignore: Vec<AdvisoryId>,
    pub(crate) ignore_yanked: Vec<crate::bans::SpecAndReason>,
    pub vulnerability: LintLevel,
    pub unmaintained: LintLevel,
    pub unsound: LintLevel,
    pub yanked: Spanned<LintLevel>,
    pub notice: LintLevel,
    pub severity_threshold: Option<advisory::Severity>,
    pub git_fetch_with_cli: bool,
    pub disable_yank_checking: bool,
    pub maximum_db_staleness: Spanned<Duration>,
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
fn parse_rfc3339_duration(value: &str) -> anyhow::Result<Duration> {
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
        Year,
        Month,
        Day,
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

    let mut duration = Duration::new(0, 0);

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
    use crate::test_utils::{write_diagnostics, ConfigData};

    struct Advisories {
        advisories: Config,
    }

    impl<'de> toml_span::Deserialize<'de> for Advisories {
        fn deserialize(
            value: &mut toml_span::value::Value<'de>,
        ) -> Result<Self, toml_span::DeserError> {
            let mut th = toml_span::de_helpers::TableHelper::new(value)?;
            let advisories = th.required("advisories").unwrap();
            th.finalize(None)?;
            Ok(Self { advisories })
        }
    }

    #[test]
    fn deserializes_advisories_cfg() {
        let cd = ConfigData::<Advisories>::load("tests/cfg/advisories.toml");
        let validated = cd.validate_with_diags(
            |a| a.advisories,
            |files, diags| {
                let diags = write_diagnostics(files, diags.into_iter());
                insta::assert_snapshot!(diags);
            },
        );

        insta::assert_json_snapshot!(validated);
    }

    #[test]
    fn warns_on_duplicates() {
        let dupes = r#"
[advisories]
db-urls = [
    "https://github.com/rust-lang/crates.io-index",
    "https://one.reg",
    "https://one.reg",
]
ignore = [
    "RUSTSEC-0000-0001",
    { crate = "boop" },
    "RUSTSEC-0000-0001",
    "boop",
]
"#;

        let cd = ConfigData::<Advisories>::load_str("duplicates", dupes);
        let _validated = cd.validate_with_diags(
            |a| a.advisories,
            |files, diags| {
                let diags = write_diagnostics(files, diags.into_iter());
                insta::assert_snapshot!(diags);
            },
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
            "PT1M3H", "P1M3Y", "P2W1Y", "PT2W1H", // Units in an invalid order
            "P5H", "P5S", // Time units must be preceded by T
            // We don't accept ',' as a decimal separator even though it is allowed in the spec
            "PT1,5S",
        ];

        let failures: String = FAILURES.iter().fold(String::new(), |mut acc, bad| {
            use std::fmt::Write;
            writeln!(&mut acc, "{:#?}", dur_parse(bad).unwrap_err()).unwrap();
            acc
        });

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
            ("P1Y3M", 365. * DAY + 3. * MONTH),
            ("P1Y5D", 365. * DAY + 5. * DAY),
            ("P1Y4M3D", 365. * DAY + 4. * MONTH + 3. * DAY),
            (
                "P1Y3M2DT3H2M1S",
                365. * DAY + 3. * MONTH + 2. * DAY + 3. * 60. * 60. + 2. * 60. + 1.,
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
                        Duration::seconds_f64(*secs),
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
