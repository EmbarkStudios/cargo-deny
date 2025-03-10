use crate::{
    LintLevel, PathBuf, Span, Spanned,
    cfg::{PackageSpecOrExtended, Reason, Scope, ValidationContext},
    diag::{Diagnostic, FileId, Label},
    utf8path,
};
use anyhow::Context as _;
use rustsec::advisory;
use time::Duration;
use toml_span::{Deserialize, Value, de_helpers::*, value::ValueInner};
use url::Url;

pub(crate) type AdvisoryId = Spanned<advisory::Id>;

#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct IgnoreId {
    pub id: AdvisoryId,
    pub reason: Option<Reason>,
}

impl<'de> Deserialize<'de> for IgnoreId {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, toml_span::DeserError> {
        let mut th = TableHelper::new(value)?;
        let ids = th.required_s::<std::borrow::Cow<'de, str>>("id")?;
        let id = match ids.value.parse() {
            Ok(id) => Spanned::with_span(id, ids.span),
            Err(err) => {
                return Err(toml_span::Error {
                    kind: toml_span::ErrorKind::Custom(
                        format!("failed to parse advisory id: {err}").into(),
                    ),
                    span: ids.span,
                    line_info: None,
                }
                .into());
            }
        };
        let reason = th.optional_s::<String>("reason");

        th.finalize(None)?;

        Ok(Self {
            id,
            reason: reason.map(Reason::from),
        })
    }
}

impl Ord for IgnoreId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for IgnoreId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for IgnoreId {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}

impl Eq for IgnoreId {}

pub struct Config {
    /// Path to the root directory where advisory databases are stored (default: $CARGO_HOME/advisory-dbs)
    pub db_path: Option<Spanned<PathBuf>>,
    /// List of urls to git repositories of different advisory databases.
    pub db_urls: Vec<Spanned<Url>>,
    /// How to handle crates that have been yanked from eg crates.io
    pub yanked: Spanned<LintLevel>,
    /// Ignore advisories for the given IDs
    ignore: Vec<Spanned<IgnoreId>>,
    /// Whether to error on unmaintained advisories, and for what scope
    pub unmaintained: Spanned<Scope>,
    /// Ignore yanked crates
    pub ignore_yanked: Vec<Spanned<PackageSpecOrExtended<Reason>>>,
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
    deprecated_spans: Vec<Span>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: None,
            db_urls: Vec::new(),
            ignore: Vec::new(),
            unmaintained: Spanned::new(crate::cfg::Scope::All),
            ignore_yanked: Vec::new(),
            yanked: Spanned::new(LintLevel::Warn),
            git_fetch_with_cli: None,
            disable_yank_checking: false,
            maximum_db_staleness: Spanned::new(Duration::seconds_f64(NINETY_DAYS)),
            deprecated_spans: Vec::new(),
        }
    }
}

const NINETY_DAYS: f64 = 90. * 24. * 60. * 60. * 60.;

impl<'de> Deserialize<'de> for Config {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, toml_span::DeserError> {
        let mut th = TableHelper::new(value)?;

        let _version = th.optional("version").unwrap_or(1);

        let db_path = th.optional_s::<String>("db-path").map(|s| s.map());
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

        let _vulnerability = deprecated::<LintLevel>(&mut th, "vulnerability", &mut fdeps);
        let _unsound = deprecated::<LintLevel>(&mut th, "unsound", &mut fdeps);
        let _notice = deprecated::<LintLevel>(&mut th, "notice", &mut fdeps);

        let unmaintained = th.optional_s::<Scope>("unmaintained");

        let yanked = th
            .optional_s("yanked")
            .unwrap_or(Spanned::new(LintLevel::Warn));
        let (ignore, ignore_yanked) = if let Some((_, mut ignore)) = th.take("ignore") {
            let mut u = Vec::new();
            let mut y = Vec::new();

            match ignore.take() {
                ValueInner::Array(ida) => {
                    for mut v in ida {
                        match v.take() {
                            ValueInner::String(s) => {
                                // Attempt to parse an advisory id first, note we can't
                                // just immediately use parse as the from_str implementation
                                // for id will just blindly accept any string
                                if advisory::IdKind::detect(s.as_ref()) != advisory::IdKind::Other {
                                    if let Ok(id) = s.parse::<advisory::Id>() {
                                        u.push(Spanned::with_span(
                                            IgnoreId {
                                                id: Spanned::with_span(id, v.span),
                                                reason: None,
                                            },
                                            v.span,
                                        ));
                                        continue;
                                    }
                                }

                                v.set(ValueInner::String(s));
                            }
                            ValueInner::Table(tab) => {
                                if tab.contains_key("id") {
                                    v.set(ValueInner::Table(tab));
                                    match IgnoreId::deserialize(&mut v) {
                                        Ok(iid) => u.push(Spanned::with_span(iid, v.span)),
                                        Err(mut err) => {
                                            th.errors.append(&mut err.errors);
                                        }
                                    }
                                    continue;
                                }

                                v.set(ValueInner::Table(tab));
                            }
                            other => {
                                th.errors.push(toml_span::Error {
                                    kind: toml_span::ErrorKind::Wanted {
                                        expected: "an advisory id or package spec",
                                        found: other.type_str(),
                                    },
                                    span: v.span,
                                    line_info: None,
                                });
                                continue;
                            }
                        }

                        match PackageSpecOrExtended::deserialize(&mut v) {
                            Ok(pse) => y.push(Spanned::with_span(pse, v.span)),
                            Err(mut err) => {
                                th.errors.append(&mut err.errors);
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

            match s.parse::<advisory::Severity>() {
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

        let _severity_threshold = st(&mut th, &mut fdeps);
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
            yanked,
            ignore,
            unmaintained: unmaintained.unwrap_or(Spanned::new(Scope::All)),
            ignore_yanked,
            git_fetch_with_cli,
            disable_yank_checking,
            maximum_db_staleness,
            deprecated_spans: fdeps,
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

        let db_path = if let Some(root) = self.db_path {
            let exp_result;

            // When testing we use a specific default otherwise it gets redacted by insta
            #[cfg(test)]
            {
                exp_result = shellexpand(root, ctx.cfg_id, |exp| match exp {
                    Expand::Home => Ok(Some("/home/you".into())),
                    Expand::Var(var) => {
                        unreachable!("unexpected expansion request for '{var}'")
                    }
                });
            }
            #[cfg(not(test))]
            {
                exp_result = shellexpand(root, ctx.cfg_id, normal_expand);
            }

            match exp_result {
                Ok(expanded) => Some(expanded),
                Err(err) => {
                    ctx.diagnostics.push(err);
                    None
                }
            }
        } else {
            fn def_path() -> anyhow::Result<PathBuf> {
                utf8path(
                    home::cargo_home()
                        .context("failed to resolve CARGO_HOME or HOME")?
                        .join("advisory-dbs"),
                )
            }

            match def_path() {
                Ok(pb) => Some(pb),
                Err(err) => {
                    ctx.diagnostics.push(Diagnostic::error()
                        .with_message(format!("unable to obtain default advisory-dbs directory: {err:#}"))
                        .with_notes(vec!["the default directory is determined by $CARGO_HOME -> $HOME/.cargo".into()]));
                    None
                }
            }
        };

        use crate::diag::general::{Deprecated, DeprecationReason};

        // Output any deprecations, we'll remove the fields at the same time we
        // remove all the logic they drive
        for dep in self.deprecated_spans {
            ctx.push(
                Deprecated {
                    reason: DeprecationReason::Removed(
                        "https://github.com/EmbarkStudios/cargo-deny/pull/611",
                    ),
                    key: dep,
                    file_id: ctx.cfg_id,
                }
                .into(),
            );
        }

        ValidConfig {
            file_id: ctx.cfg_id,
            db_path: db_path.unwrap_or_default(), // If we failed to get a path the default won't be used since errors will have occurred
            db_urls,
            ignore: ignore.into_iter().map(|s| s.value).collect(),
            unmaintained: self.unmaintained,
            ignore_yanked: ignore_yanked
                .into_iter()
                .map(|s| crate::bans::SpecAndReason {
                    spec: s.value.spec,
                    reason: s.value.inner,
                    use_instead: None,
                    file_id: ctx.cfg_id,
                })
                .collect(),
            yanked: self.yanked,
            git_fetch_with_cli: self.git_fetch_with_cli.unwrap_or_default(),
            disable_yank_checking: self.disable_yank_checking,
            maximum_db_staleness: self.maximum_db_staleness,
        }
    }
}

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidConfig {
    pub file_id: FileId,
    pub db_path: PathBuf,
    pub db_urls: Vec<Spanned<Url>>,
    pub(crate) ignore: Vec<IgnoreId>,
    pub(crate) unmaintained: Spanned<Scope>,
    pub(crate) ignore_yanked: Vec<crate::bans::SpecAndReason>,
    pub yanked: Spanned<LintLevel>,
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
            anyhow::bail!(
                "'{c}' is valid in the RFC-3339 duration format but not supported by this implementation, use '.' instead"
            );
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

/// We could just hardcode these, but this makes testing easier
enum Expand<'v> {
    Home,
    Var(&'v str),
}

#[cfg_attr(test, allow(dead_code))]
fn normal_expand(exp: Expand<'_>) -> anyhow::Result<Option<String>> {
    match exp {
        Expand::Home => {
            let hd =
                home::home_dir().context("HOME directory could not be obtained from the OS")?;
            let uhd = utf8path(hd)?;
            Ok(Some(uhd.into()))
        }
        // We treat this one variable specially
        Expand::Var("CARGO_HOME") => Ok(Some(
            utf8path(home::cargo_home().context("unable to determine CARGO_HOME")?)?.into(),
        )),
        Expand::Var(var_name) => match std::env::var(var_name) {
            Ok(vv) => Ok(Some(vv)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(original)) => {
                anyhow::bail!("'{original:?}' is not utf-8")
            }
        },
    }
}

/// This is a _basic_ shell expander, it's not meant to be fully featured, just
/// support the basic options a user would normally use, namely `~` expansion
/// and `$VAR_NAME` || `${VAR_NAME(?::-(default_value))?}` expansion
fn shellexpand(
    to_expand: Spanned<PathBuf>,
    cfg_id: FileId,
    expand: impl Fn(Expand<'_>) -> anyhow::Result<Option<String>>,
) -> Result<PathBuf, Diagnostic> {
    let span = to_expand.span;
    let original = to_expand.value;
    let te = original.as_str();

    if !te.contains('~') && !te.contains('$') {
        return Ok(original);
    }

    let mut exp = String::new();

    let mut cursor = 0;

    if te.starts_with('~') {
        exp.push_str(
            &expand(Expand::Home)
                .map_err(|err| {
                    Diagnostic::error()
                        .with_message(format!("unable to obtain $HOME: {err:#}"))
                        .with_labels(vec![Label::primary(cfg_id, span.start..span.start + 1)])
                })?
                .expect("this either fails or returns a path"),
        );
        cursor += 1;
    }

    while let Some(ind) = te[cursor..].find('$') {
        exp.push_str(&te[cursor..cursor + ind]);
        let sspan = span.start + cursor + ind;
        cursor += ind;

        let mut default = None;
        let (var_name, next) = if te[cursor..].starts_with("${") {
            let end = te[cursor..].find('}').ok_or_else(|| {
                Diagnostic::error()
                    .with_message("opening `{` is unbalanced")
                    .with_labels(vec![Label::primary(cfg_id, sspan..span.end)])
            })?;

            // Check if a default value is available
            let vname = if let Some((vname, def)) = te[cursor + 2..cursor + end].split_once(":-") {
                default = Some(def);
                vname
            } else {
                &te[cursor + 2..cursor + end]
            };

            // Ensure the variable name is valid so we can give a better error
            // other than always failing to find a variable that can never exist
            if vname
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .is_some()
            {
                return Err(Diagnostic::error()
                    .with_message("variable name is invalid")
                    .with_labels(vec![Label::primary(
                        cfg_id,
                        sspan..span.start + cursor + end + 1,
                    )]));
            }

            (vname, cursor + end + 1)
        } else {
            cursor += 1;
            if let Some(end) = te[cursor..].find(|c: char| !(c.is_alphanumeric() || c == '_')) {
                (&te[cursor..cursor + end], cursor + end)
            } else {
                (&te[cursor..], te.len())
            }
        };

        if var_name.is_empty() {
            return Err(Diagnostic::error()
                .with_message("variable name cannot be empty")
                .with_labels(vec![Label::primary(cfg_id, sspan..span.start + next)]));
        }

        match expand(Expand::Var(var_name)) {
            Ok(Some(vv)) => {
                exp.push_str(&vv);
            }
            Err(err) => {
                return Err(Diagnostic::error()
                    .with_message(format!("failed to expand variable: {err:#}"))
                    .with_labels(vec![Label::primary(cfg_id, sspan..span.start + next)]));
            }
            Ok(None) => {
                if let Some(default) = default {
                    exp.push_str(default);
                } else {
                    return Err(Diagnostic::error()
                        .with_message("failed to find variable")
                        .with_labels(vec![Label::primary(cfg_id, sspan..span.start + next)]));
                }
            }
        }

        cursor = next;
    }

    exp.push_str(&te[cursor..]);

    Ok(exp.into())
}

#[cfg(test)]
mod test {

    use super::{parse_rfc3339_duration as dur_parse, *};
    use crate::test_utils::{ConfigData, write_diagnostics};

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

    #[cfg(unix)]
    #[test]
    fn expands_path() {
        use super::Expand;
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

        // Überraschung in ISO_8859_15
        const SURPRISE: &[u8] = &[220, 98, 101, 114, 114, 97, 115, 99, 104, 117, 110, 103];

        macro_rules! expand {
            ($expand:expr, $expected:literal, $value:expr) => {
                if let Expand::Var(vn) = $expand {
                    assert_eq!(vn, $expected);
                    $value
                } else {
                    unreachable!("expected a variable name");
                }
            };
        }

        // These closurs need to be kept aligned with the toml array below
        #[allow(clippy::type_complexity)]
        let expanders: [Option<Box<dyn Fn(Expand<'_>) -> anyhow::Result<Option<String>>>>;
            16] = [
            Some(Box::new(|exp| {
                if let Expand::Home = exp {
                    anyhow::bail!("HOME directory could not be obtained from the OS");
                } else {
                    panic!("unexpected request")
                }
            })),
            Some(Box::new(|exp| {
                if let Expand::Home = exp {
                    utf8path(std::ffi::OsStr::from_bytes(SURPRISE).into())?;
                    unreachable!();
                } else {
                    panic!("unexpected request")
                }
            })),
            Some(Box::new(|exp| {
                if let Expand::Home = exp {
                    Ok(Some("/this-home".into()))
                } else {
                    panic!("unexpected request")
                }
            })),
            Some(Box::new(|exp| {
                expand!(exp, "CARGO_HOME", Ok(Some("/default/.works".into())))
            })),
            Some(Box::new(|exp| {
                expand!(exp, "CARGO_HOME2", Ok(Some("/this-also/.works".into())))
            })),
            None,
            Some(Box::new(|exp| expand!(exp, "NOPE", Ok(None)))),
            Some(Box::new(|exp| {
                expand!(
                    exp,
                    "NON_UTF8",
                    anyhow::bail!("'{:?}' is not utf-8", OsStr::from_bytes(SURPRISE))
                )
            })),
            None,
            None,
            Some(Box::new(|exp| {
                expand!(exp, "TRAILING", Ok(Some("trail".into())))
            })),
            Some(Box::new(|exp| {
                expand!(exp, "WINDOWS", Ok(Some("windows".into())))
            })),
            None,
            None,
            Some(Box::new(|exp| {
                expand!(exp, "IN_MID", Ok(Some("in-the-middle".into())))
            })),
            Some(Box::new(|exp| {
                if matches!(exp, Expand::Var("FIRST")) {
                    expand!(exp, "FIRST", Ok(Some("first".into())))
                } else {
                    expand!(exp, "SECOND", Ok(Some("second".into())))
                }
            })),
        ];

        let toml = r#"
expansions = [
    "~/nope", # can't find $HOME
    "~/not-utf8", # $HOME is not a utf-8 path
    "~/works", # expands to /this-home/works
    "$CARGO_HOME/advisory-dbs", # expands to /default/.works/advisory-dbs
    "${CARGO_HOME2}/advisory-dbs", # expands to /this-also/.works/advisory-dbs
    "${no-end", # fails due to unclosed {
    "/missing/${NOPE:-but i have a default}/", # expands to /missing/but i have a default/
    "/non-utf8/$NON_UTF8", # fails due to NON_UTF8
    "$/empty", # fails due to empty variable
    "/also-empty/${}", # ditto
    "/has-trailing/$TRAILING", # expands to /has-trailing/trail
    "C:/Users/me/$WINDOWS/works", # expands to C:/Users/me/windows/works
    "$!", # fails due to empty variable name
    "${!}", # fails due to invalid character in variable name
    "/expands/stuff-${IN_MID}-like-this", # /expands/stuff-in-the-middle-like-this
    "/expands/$FIRST-item/${SECOND}-item/multiple", # /expands/first-item/second-item/multiple
]
"#;
        let mut tv = toml_span::parse(toml).unwrap();
        let toml_span::value::ValueInner::Table(mut tab) = tv.take() else {
            unreachable!()
        };
        let mut expansions = tab.remove("expansions").unwrap();
        let toml_span::value::ValueInner::Array(exp) = expansions.take() else {
            unreachable!()
        };

        use toml_span::Deserialize as _;

        let mut files = crate::diag::Files::new();
        let cfg_id = files.add("expansions.toml", toml);

        let mut output = String::new();

        for (mut expansion, expander) in exp.into_iter().zip(expanders.into_iter()) {
            let expansion = toml_span::Spanned::<String>::deserialize(&mut expansion)
                .unwrap()
                .map();

            let expander = expander.unwrap_or_else(|| {
                Box::new(|_exp| {
                    unreachable!("this should not be called");
                })
            });

            match super::shellexpand(expansion, cfg_id, expander) {
                Ok(pb) => output.push_str(pb.as_str()),
                Err(err) => {
                    let ds = crate::test_utils::write_diagnostics(&files, std::iter::once(err));
                    output.push_str(&ds);
                }
            }

            output.push('\n');
        }

        insta::assert_snapshot!(output);
    }
}
