use crate::{Krate, Krates, Path, PathBuf, advisories::model};
use anyhow::Context as _;
use log::{debug, info};
use rayon::{
    iter::{ParallelBridge, ParallelIterator},
    prelude::IntoParallelRefIterator,
};
use semver::VersionReq;
use std::{fmt, fs, process::Command};
use url::Url;

/// The default, official, rustsec advisory database
const DEFAULT_URL: &str = "https://github.com/RustSec/advisory-db";

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    AllowWithGitCli,
    Disallow(std::time::Duration),
}

pub struct AdvisoryDb {
    /// Remote url of the database
    pub url: Url,
    /// The deserialized collection of advisories
    pub db: Database,
    /// The path to the backing repository
    pub path: PathBuf,
    /// The time of the last fetch of the db
    pub fetch_time: jiff::Timestamp,
}

impl fmt::Debug for AdvisoryDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdvisoryDb")
            .field("url", &self.url)
            .field("path", &self.path)
            .finish()
    }
}

/// A collection of [`Database`]s that is used to query advisories
/// in many different databases.
///
/// [`Database`]: https://docs.rs/rustsec/latest/rustsec/database/struct.Database.html
pub struct DbSet {
    pub dbs: Vec<AdvisoryDb>,
    pub lock: Option<tame_index::utils::flock::FileLock>,
}

impl DbSet {
    pub fn load(root: PathBuf, mut urls: Vec<Url>, fetch: Fetch) -> anyhow::Result<Self> {
        if urls.is_empty() {
            info!("No advisory database configured, falling back to default '{DEFAULT_URL}'");
            urls.push(Url::parse(DEFAULT_URL).unwrap());
        }

        // Acquire an exclusive lock, even if we aren't fetching, to prevent
        // other cargo-deny processes from performing mutations
        let lock_path = root.join("db.lock");
        let lock = tame_index::utils::flock::LockOptions::new(&lock_path)
            .exclusive(false)
            .lock(|path| {
                log::info!("waiting on advisory db lock '{path}'");
                Some(std::time::Duration::from_secs(60))
            })
            .context("failed to acquire advisory database lock")?;

        use rayon::prelude::*;
        let mut dbs = Vec::with_capacity(urls.len());
        urls.into_par_iter()
            .map(|url| load_db(url, root.clone(), fetch))
            .collect_into_vec(&mut dbs);

        Ok(Self {
            dbs: dbs.into_iter().collect::<Result<Vec<_>, _>>()?,
            lock: Some(lock),
        })
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &AdvisoryDb> {
        self.dbs.iter()
    }

    #[inline]
    pub fn has_advisory(&self, id: &str) -> bool {
        self.dbs
            .iter()
            .any(|adb| adb.db.advisories.contains_key(id))
    }
}

impl fmt::Debug for DbSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbSet").field("dbs", &self.dbs).finish()
    }
}

/// Convert an advisory url to a directory underneath a specified root
///
/// This uses a similar, but different, scheme to how cargo names eg. index
/// directories, we take the path portion of the url and use that as a friendly
/// identifier, but then hash the url as the user provides it to ensure the
/// directory name is unique
fn url_to_db_path(mut db_path: PathBuf, url: &Url) -> anyhow::Result<PathBuf> {
    let url = Url::parse(&url.as_str().to_lowercase())?;
    let name = url
        .path_segments()
        .and_then(|mut ps| ps.next_back())
        .unwrap_or("empty_");

    let hash = twox_hash::XxHash64::oneshot(0xca80de71, url.as_str().as_bytes());
    db_path.push(format!("{name}-{hash:016x}"));

    Ok(db_path)
}

fn load_db(url: Url, root_db_path: PathBuf, fetch: Fetch) -> anyhow::Result<AdvisoryDb> {
    let db_url = &url;
    let db_path = url_to_db_path(root_db_path, db_url)?;

    let fetch_start = std::time::Instant::now();
    match fetch {
        Fetch::Allow | Fetch::AllowWithGitCli => {
            debug!("Fetching advisory database with git cli from '{db_url}'");

            fetch_via_cli(db_url.as_str(), &db_path)
                .with_context(|| format!("failed to fetch advisory database {db_url} with cli"))?;
        }
        Fetch::Disallow(_) => {
            debug!("Opening advisory database at '{db_path}'");
        }
    }

    // Verify that the repository is actually valid and that it is fresh
    let fetch_time = get_fetch_time(&db_path)?;

    // Ensure that the upstream repository hasn't gone stale, ie, they've
    // configured cargo-deny to not fetch the remote database(s), but they've
    // failed to update the database manually
    if let Fetch::Disallow(max_staleness) = fetch {
        anyhow::ensure!(
            fetch_time
                > jiff::Timestamp::now()
                    .checked_sub(max_staleness)
                    .context("unable to compute oldest allowable update timestamp")?,
            "repository is stale (last update: {fetch_time})"
        );
    } else {
        info!(
            "advisory database {db_url} fetched in {:?}",
            fetch_start.elapsed()
        );
    }

    debug!("loading advisory database from {db_path}");

    let res = Database::open(&db_path).context("failed to load advisory database");

    debug!("finished loading advisory database from {db_path}");

    res.map(|db| AdvisoryDb {
        url,
        db,
        path: db_path,
        fetch_time,
    })
}

fn get_fetch_time(repo: &Path) -> anyhow::Result<jiff::Timestamp> {
    let path = repo.join(".git");
    let file_timestamp = |name: &str| -> anyhow::Result<jiff::Timestamp> {
        let path = path.join(name);
        let attr =
            std::fs::metadata(path).with_context(|| format!("failed to get '{name}' metadata"))?;
        attr.modified()
            .with_context(|| format!("failed to get '{name}' modification time"))?
            .try_into()
            .with_context(|| format!("failed to convert file timestamp for '{name}'"))
    };

    let commit_timestamp = || -> anyhow::Result<jiff::Timestamp> {
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(repo)
            .args(["show", "-s", "--format=%cI", "HEAD"]);

        let ts = capture(cmd).context("failed to get HEAD timestamp")?;
        ts.trim()
            .parse()
            .with_context(|| format!("failed to parse ISO-8601 timestamp '{}'", ts.trim()))
    };

    let timestamp = match file_timestamp("FETCH_HEAD") {
        Ok(ts) => ts,
        Err(fh_err) => {
            // If we can't get the mod time of the FETCH_HEAD file, fallback
            // to getting the timestamp of the head commit. However, this
            // is not as good as FETCH_HEAD mod time since a database could
            // have been fetched within the time window, but the HEAD at that
            // time was out of the time window
            //
            // However, to mitigate this problem, we use the HEAD time if it is
            // newer than the commit time, as a fresh clone with git will NOT
            // have the FETCH_HEAD, but the fresh clone will have just written
            // HEAD and thus can be used as a fallback, but still defer to head
            // if something weird has happened
            match commit_timestamp() {
                Ok(commit_ts) => {
                    let file_head_ts = file_timestamp("HEAD").unwrap_or_default();
                    std::cmp::max(commit_ts, file_head_ts)
                }
                Err(hc_err) => {
                    return Err(hc_err).context(fh_err);
                }
            }
        }
    };

    Ok(timestamp)
}

fn capture(mut cmd: Command) -> anyhow::Result<String> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = cmd
        .spawn()
        .context("failed to spawn git")?
        .wait_with_output()
        .context("failed to wait on git output")?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .or_else(|_err| Ok("git command succeeded but gave non-utf8 output".to_owned()))
    } else {
        String::from_utf8(output.stderr)
            .map_err(|_err| anyhow::anyhow!("git command failed and gave non-utf8 output"))
    }
}

fn fetch_via_cli(url: &str, db_path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = db_path.parent() {
        if !parent.is_dir() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create advisory database directory {parent}")
            })?;
        }
    } else {
        anyhow::bail!("invalid directory: {db_path}");
    }

    let run = |args: &[&str]| {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(db_path);
        cmd.args(args);

        capture(cmd)
    };

    if db_path.exists() {
        // make sure db_path is clean
        // We don't fail if we can't reset since it _may_ still be possible to
        // clone
        match run(&["reset", "--hard"]) {
            Ok(_reset) => log::debug!("reset {url}"),
            Err(err) => log::error!("failed to reset {url}: {err}"),
        }

        // pull latest changes
        run(&["fetch"]).context("failed to fetch latest changes")?;
        log::debug!("fetched {url}");

        // reset to the remote HEAD
        run(&["reset", "--hard", "FETCH_HEAD"]).context("failed to reset to FETCH_HEAD")?;
    } else {
        // clone repository
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg(url).arg(db_path);

        capture(cmd).context("failed to clone")?;
        log::debug!("cloned {url}");
    }

    Ok(())
}

pub struct Report<'db, 'k> {
    pub advisories: Vec<(&'k Krate, &'db model::Advisory<'static>)>,
    /// For backwards compatibility with cargo-audit, we optionally serialize the
    /// reports to JSON and output them in addition to the normal cargo-deny
    /// diagnostics
    pub serialized_reports: Vec<serde_json::Value>,
}

impl<'db, 'k> Report<'db, 'k> {
    pub fn generate(
        cfg: &crate::advisories::cfg::ValidConfig,
        advisory_dbs: &'db DbSet,
        krates: &'k Krates,
        serialize_reports: bool,
    ) -> Self {
        let mut serialized_reports = Vec::with_capacity(if serialize_reports {
            advisory_dbs.dbs.len()
        } else {
            0
        });

        let mut advisories = Vec::new();

        for advisory_db in advisory_dbs.iter() {
            let mut db_advisories: Vec<_> = advisory_db
                .db
                .advisories
                .par_iter()
                .filter(|(id, entry)| {
                    let Some(wdate) = &entry.advisory.advisory.withdrawn else {
                        return true;
                    };
                    log::trace!("ignoring advisory '{id}', withdrawn {wdate}");
                    false
                })
                .flat_map(|(_id, entry)| {
                    krates
                        .krates_by_name(entry.advisory.advisory.krate)
                        .par_bridge()
                        .filter_map(move |km| {
                            let ksrc = km.krate.source.as_ref()?;

                            // Validate the crate's source is the same as the advisory
                            if !ksrc.matches_rustsec(entry.advisory.advisory.source.as_ref()) {
                                return None;
                            }

                            // Ensure the crate's version is actually affected
                            if !is_affected(&entry.advisory.versions, &km.krate.version) {
                                return None;
                            }

                            Some((km.krate, &entry.advisory))
                        })
                })
                .collect();

            if serialize_reports {
                let mut warnings =
                    std::collections::BTreeMap::<&'static str, Vec<serde_json::Value>>::new();
                let mut vulns = Vec::new();

                for (krate, adv) in &db_advisories {
                    let package = serde_json::json!({
                        "name": krate.name,
                        "version": krate.version,
                        "source": krate.source.as_ref().map(|s| s.to_string()),
                        // TODO: Get this info from the lockfile
                        "checksum": serde_json::Value::Null,
                        "dependencies": [],
                        "replace": serde_json::Value::Null,
                    });

                    if let Some(informational) = &adv.advisory.informational {
                        let kind = match informational {
                            model::Informational::Unmaintained => "unmaintained",
                            model::Informational::Unsound => "unsound",
                            model::Informational::Notice => "notice",
                            model::Informational::Other(o) => o,
                        };

                        warnings.entry(kind).or_default().push(serde_json::json!({
                            "kind": kind,
                            "package": package,
                            "advisory": adv.advisory.to_json(),
                            "affected": adv.affected.as_ref().map(|aff| aff.to_json()),
                            "versions": adv.versions.to_json(),
                        }));
                    } else {
                        vulns.push(serde_json::json!({
                            "advisory": adv.advisory.to_json(),
                            "versions": adv.versions.to_json(),
                            "affected": adv.affected.as_ref().map(|aff| aff.to_json()),
                            "package": package,
                        }));
                    }
                }

                serialized_reports.push(serde_json::json!({
                    // This is extremely cargo-audit specific, we fill it out a bit lazily
                    "settings": serde_json::json!({
                        "target_arch": [],
                        "target_os": [],
                        "severity": serde_json::Value::Null,
                        "ignore": serde_json::Value::Array(cfg.ignore.iter().map(|i| serde_json::Value::String(i.id.value.clone())).collect()),
                        "informational_warnings": [
                            "notice",
                            "unmaintained",
                            "unsound",
                        ],
                    }),
                    "lockfile": {
                        "dependency-count": krates.len(),
                    },
                    "vulnerabilities": vulns,
                    "warnings": warnings,
                }));
            }

            advisories.append(&mut db_advisories);
        }

        // We can't just sort by krate id, as then multiple advisories for the same crate could
        // ordered differently between runs
        advisories.sort_by(|a, b| {
            let c = a.0.cmp(b.0);
            if c != std::cmp::Ordering::Equal {
                c
            } else {
                a.1.advisory.id.cmp(b.1.advisory.id)
            }
        });

        Self {
            advisories,
            serialized_reports,
        }
    }
}

#[allow(dead_code)]
pub struct DbEntry {
    mmap: memmap2::Mmap,
    path: crate::PathBuf,
    advisory: model::Advisory<'static>,
}

impl DbEntry {
    #[inline]
    fn load(path: crate::PathBuf) -> anyhow::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(&path)
            .with_context(|| format!("failed to open {path}"))?;

        #[allow(unsafe_code)]
        // SAFETY: we lock to at least prevent other cargo-deny processes from
        // mutating the files on disk, though of course other processes could,
        // though the checkout directory is specific enough that that _shouldn't_
        // be an issue in normal cases
        let (mmap, advisory) = unsafe {
            let mmap =
                memmap2::Mmap::map(&file).with_context(|| format!("failed to map {path}"))?;

            let advisory = deserialize(std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()))
                .with_context(|| format!("failed to deserialize {path}"))?;

            (mmap, advisory)
        };

        Ok(Self {
            mmap,
            path,
            advisory,
        })
    }
}

#[inline]
fn deserialize(b: &'static [u8]) -> anyhow::Result<model::Advisory<'static>> {
    let s = std::str::from_utf8(b)?;

    // This should be at the start, but just in case
    let tstart = s.find("```toml`\n").context("failed to find toml block")?;
    let toml = &b[tstart..];
    let s = &s[tstart..];

    let mut start = 0;

    let mut liter = memchr::memchr_iter(b'\n', toml).peekable();

    let mut md = model::Metadata {
        id: "",
        krate: "",
        title: "",
        description: "",
        date: jiff::civil::Date::constant(0, 1, 1),
        aliases: Default::default(),
        related: Default::default(),
        categories: Default::default(),
        keywords: Default::default(),
        cvss: None,
        informational: None,
        source: None,
        references: Default::default(),
        url: None,
        withdrawn: None,
        license: Default::default(),
        expect_deleted: false,
    };
    let mut versions = None;
    let mut affected = None;

    struct ArrayIter {
        v: &'static str,
        inner: memchr::Memchr<'static>,
    }

    impl ArrayIter {
        fn new(v: &'static str) -> Self {
            let start = memchr::memchr(b'[', v.as_bytes()).unwrap();
            let end = memchr::memrchr(b']', v.as_bytes()).unwrap();

            let v = &v[start..end];

            Self {
                v,
                inner: memchr::memchr_iter(b'"', v.as_bytes()),
            }
        }
    }

    impl Iterator for ArrayIter {
        type Item = &'static str;

        #[allow(clippy::question_mark)]
        fn next(&mut self) -> Option<Self::Item> {
            let Some(start) = self.inner.next() else {
                return None;
            };
            let Some(end) = self.inner.next() else {
                return None;
            };

            Some(&self.v[start..end])
        }
    }

    let parse_advisory = |liter: &mut std::iter::Peekable<memchr::Memchr<'static>>,
                          start: &mut usize,
                          md: &mut model::Metadata<'static>|
     -> anyhow::Result<()> {
        while let Some(end) = liter.peek() {
            let line = &s[*start..*end];

            if line.starts_with('[') || line == "```" {
                return Ok(());
            }

            *start = *end + 1;
            liter.next();

            if line.trim().is_empty() {
                continue;
            }

            let (field, value) = line
                .split_once(" = ")
                .with_context(|| format!("line `{line}` did not follow expected format"))?;

            let string = || -> &'static str { &value[1..value.len() - 1] };

            match field {
                "id" => md.id = string(),
                "package" => md.krate = string(),
                "aliases" => {
                    for alias in ArrayIter::new(value) {
                        md.aliases.push(alias);
                    }
                }
                "related" => {
                    for id in ArrayIter::new(value) {
                        md.related.push(id);
                    }
                }
                "cvss" => md.cvss = Some(string()),
                "date" => md.date = string().parse().context("failed to parse `date`")?,
                "url" => md.url = Some(string()),
                "informational" => {
                    md.informational = Some(match string() {
                        "unmaintained" => model::Informational::Unmaintained,
                        "unsound" => model::Informational::Unsound,
                        "notice" => model::Informational::Notice,
                        other => model::Informational::Other(other),
                    });
                }
                "categories" => {
                    for alias in ArrayIter::new(value) {
                        md.categories.push(alias);
                    }
                }
                "keywords" => {
                    for kw in ArrayIter::new(value) {
                        md.keywords.push(kw);
                    }
                }
                "references" => {
                    for r in ArrayIter::new(value) {
                        md.references.push(r);
                    }
                }
                "withdrawn" => {
                    md.withdrawn = Some(string().parse().context("failed to parse `withdrawn`")?);
                }
                "license" => {
                    md.license = model::AdvisoryLicense(string());
                }
                "source" => {
                    md.source = Some(
                        crate::Source::from_metadata(value.to_owned(), None)
                            .with_context(|| "failed to parse `source` field '{value}'")?,
                    );
                }
                "expect-deleted" => {
                    md.expect_deleted = value == "true";
                }
                unknown => {
                    log::warn!("unknown advisory field '{unknown}'");
                }
            }
        }

        Ok(())
    };

    let parse_versions =
        |liter: &mut std::iter::Peekable<memchr::Memchr<'static>>,
         start: &mut usize|
         -> anyhow::Result<model::Versions> {
            let mut v = model::Versions {
                patched: Default::default(),
                unaffected: Default::default(),
            };

            while let Some(end) = liter.peek() {
                let line = &s[*start..*end];

                if line.starts_with('[') || line == "```" {
                    return Ok(v);
                }

                *start = *end + 1;
                liter.next();

                if line.trim().is_empty() {
                    continue;
                }

                let (field, value) = line
                    .split_once(" = ")
                    .with_context(|| format!("line `{line}` did not follow expected format"))?;

                match field {
                    "patched" => {
                        for vr in ArrayIter::new(value) {
                            v.patched.push(vr.parse().with_context(|| {
                                format!("failed to parse patched version '{vr}'")
                            })?);
                        }
                    }
                    "unaffected" => {
                        for vr in ArrayIter::new(value) {
                            v.unaffected.push(vr.parse().with_context(|| {
                                format!("failed to parse unaffected version '{vr}'")
                            })?);
                        }
                    }
                    unknown => anyhow::bail!("unknown versions field '{unknown}'"),
                }
            }

            Ok(v)
        };

    let parse_affected = |liter: &mut std::iter::Peekable<memchr::Memchr<'static>>,
                          start: &mut usize,
                          first: &'static str|
     -> anyhow::Result<Option<model::Affected<'static>>> {
        let mut affected = model::Affected {
            functions: Default::default(),
            os: Default::default(),
            arch: Default::default(),
        };

        let parse_function_table = |liter: &mut std::iter::Peekable<memchr::Memchr<'static>>,
                                    start: &mut usize,
                                    funcs: &mut std::collections::BTreeMap<
            &'static str,
            Vec<VersionReq>,
        >| {
            while let Some(end) = liter.peek() {
                let line = &s[*start..*end];

                if line.starts_with('[') || line == "```" {
                    return;
                }

                *start = *end + 1;
                liter.next();

                if line.trim().is_empty() {
                    continue;
                }

                let Some((field, _value)) = line.split_once(" = ") else {
                    continue;
                };

                let key = field.trim_matches('"');
                let mut val = Vec::new();

                for vr in ArrayIter::new(line) {
                    match vr.parse() {
                        Ok(vr) => val.push(vr),
                        Err(error) => {
                            log::error!(
                                "failed to parse version requirement for function '{key}': {error}"
                            );
                        }
                    }
                }

                funcs.insert(key, val);
            }
        };

        if first == "[affected]" {
            while let Some(end) = liter.peek() {
                let line = &s[*start..*end];

                if line == "```" || line.starts_with('[') {
                    if line == "[affected.functions]" {
                        *start = *end + 1;
                        liter.next();

                        parse_function_table(liter, start, &mut affected.functions);
                    }

                    break;
                }

                let (field, value) = line
                    .split_once(" = ")
                    .with_context(|| format!("line `{line}` did not follow expected format"))?;

                match field {
                    "functions" => {
                        let Some(start) = memchr::memchr(b'{', value.as_bytes()) else {
                            continue;
                        };
                        let Some(end) = memchr::memrchr(b'}', value.as_bytes()) else {
                            continue;
                        };

                        let mut map = &value[start..end];

                        while let Some((key, value)) = map.split_once(" = ") {
                            let key = key.trim_matches('"');
                            let mut val = Vec::new();

                            for vr in ArrayIter::new(value) {
                                match vr.parse() {
                                    Ok(vr) => val.push(vr),
                                    Err(error) => {
                                        log::error!(
                                            "failed to parse version requirement for function '{key}': {error}"
                                        );
                                    }
                                }
                            }

                            affected.functions.insert(key, val);

                            let vend = memchr::memchr(b']', value.as_bytes()).unwrap();

                            let Some(start) = memchr::memchr(b'"', &value.as_bytes()[vend..])
                            else {
                                break;
                            };

                            map = &map[vend + start..];
                        }
                    }
                    "os" => {
                        for os in ArrayIter::new(value) {
                            affected
                                .os
                                .push(cfg_expr::targets::Os(std::borrow::Cow::Borrowed(os)));
                        }
                    }
                    "arch" => {
                        for arch in ArrayIter::new(value) {
                            affected
                                .arch
                                .push(cfg_expr::targets::Arch(std::borrow::Cow::Borrowed(arch)));
                        }
                    }
                    unknown => {
                        log::warn!("unknown `affected` field '{unknown}'");
                    }
                }
            }
        } else if first == "[affected.functions]" {
            parse_function_table(liter, start, &mut affected.functions);
        }

        if affected.functions.is_empty() && affected.os.is_empty() && affected.arch.is_empty() {
            Ok(None)
        } else {
            Ok(Some(affected))
        }
    };

    while let Some(end) = liter.next() {
        let line = &s[start..end];
        start = end + 1;

        match line {
            "[advisory]" => {
                parse_advisory(&mut liter, &mut start, &mut md)?;
            }
            "[versions]" => {
                versions = Some(parse_versions(&mut liter, &mut start)?);
            }
            aff if line.starts_with("[affected") => {
                affected = parse_affected(&mut liter, &mut start, line)?;
            }
            "```" => {
                break;
            }
            unknown => {
                log::warn!("unknown toml table '{unknown}'");
            }
        }
    }

    for end in liter {
        let line = &s[start..end];
        start = end + 1;

        if let Some(title) = line.strip_prefix("# ") {
            md.title = title;
            break;
        }
    }

    md.description = s[start..].trim();

    Ok(model::Advisory {
        advisory: md,
        affected,
        versions: versions.unwrap_or(model::Versions {
            patched: Vec::new(),
            unaffected: Vec::new(),
        }),
    })
}

pub struct Database {
    pub advisories: std::collections::BTreeMap<&'static str, DbEntry>,
}

impl Database {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let root = path.join("crates");

        anyhow::ensure!(root.exists(), "failed to find expected `crates` directory");

        let mut advisories = std::collections::BTreeMap::new();

        for entry in walkdir::WalkDir::new(&root) {
            match entry {
                Ok(entry) => {
                    if !entry.file_type().is_file() {
                        continue;
                    }

                    let Ok(path) = crate::PathBuf::from_path_buf(entry.into_path()) else {
                        // It's incredibly unlikely that a database would have non-utf8 paths
                        log::debug!("skipping non-utf8 path");
                        continue;
                    };

                    if path.extension() != Some("md") {
                        continue;
                    }

                    match DbEntry::load(path) {
                        Ok(entry) => {
                            advisories.insert(entry.advisory.advisory.id, entry);
                        }
                        Err(error) => {
                            log::error!("failed to load advisory: {error}");
                        }
                    }
                }
                Err(error) => {
                    log::warn!("failed to read directory entry: {error}");
                }
            }
        }

        anyhow::ensure!(
            !advisories.is_empty(),
            "failed to load any advisories in the database"
        );

        Ok(Self { advisories })
    }
}

/// A much simpler version of the [`Versions::is_vulnerable`](https://github.com/rustsec/rustsec/blob/cf93efe036c112c5b2737857b991d12c15f43951/rustsec/src/advisory/versions.rs#L22)
/// method
///
/// Rustsec does a bunch of error checking, whereas we assume that an advisory can't enter the database if it has malformed
/// (ie overlapping) version ranges, though this may need to change if someone uses cargo-deny for a non-rustsec db that
/// they introduce bad advisories into. It also essentially does a negation to conform with <https://github.com/google/osv.dev>
/// which is not interesting for this crate
fn is_affected(versions: &model::Versions, version: &semver::Version) -> bool {
    if versions.patched.is_empty() && versions.unaffected.is_empty() {
        return true;
    }

    fn check(reqs: &[semver::VersionReq], vers: &semver::Version) -> bool {
        // We can't just blindly use semver's requirement checking here due to https://github.com/dtolnay/semver/issues/172
        if vers.pre.is_empty() {
            return reqs.iter().any(|req| req.matches(vers));
        }

        reqs.iter().any(|req| {
            // rustsec only allows up to 2 comparators https://github.com/rustsec/rustsec/blob/cf93efe036c112c5b2737857b991d12c15f43951/rustsec/src/osv/unaffected_range.rs#L116-L121
            req.comparators.iter().all(|comp| {
                use semver::Op;
                use std::cmp::Ordering as Or;

                let exact = || {
                    comp.major == vers.major
                        && comp.minor.is_none_or(|m| m == vers.minor)
                        && comp.patch.is_none_or(|p| p == vers.patch)
                        && comp.pre == vers.pre
                };

                let greater = || match comp.major.cmp(&vers.major) {
                    Or::Equal => {
                        let Some(minor) = comp.minor else {
                            return false;
                        };

                        match minor.cmp(&vers.minor) {
                            Or::Equal => {
                                let Some(patch) = comp.patch else {
                                    return false;
                                };

                                patch != vers.patch
                            }
                            Or::Greater => false,
                            Or::Less => true,
                        }
                    }
                    Or::Greater => false,
                    Or::Less => true,
                };

                let lesser = || match comp.major.cmp(&vers.major) {
                    Or::Equal => {
                        let Some(minor) = comp.minor else {
                            return false;
                        };

                        match minor.cmp(&vers.minor) {
                            Or::Equal => {
                                let Some(patch) = comp.patch else {
                                    return false;
                                };

                                patch != vers.patch
                            }
                            Or::Greater => true,
                            Or::Less => false,
                        }
                    }
                    Or::Greater => true,
                    Or::Less => false,
                };

                match comp.op {
                    Op::Greater => greater(),
                    Op::GreaterEq => greater() || exact(),
                    Op::Less => lesser(),
                    Op::LessEq => lesser() || exact(),
                    Op::Exact => exact(),
                    Op::Caret => {
                        if comp.major != vers.major {
                            return false;
                        }

                        let Some(minor) = comp.minor else {
                            return true;
                        };

                        let Some(patch) = comp.patch else {
                            if comp.major > 0 {
                                return vers.minor >= minor;
                            } else {
                                return vers.minor == minor;
                            }
                        };

                        if comp.major > 0 {
                            if vers.minor != minor {
                                return vers.minor > minor;
                            } else if vers.patch != patch {
                                return vers.patch > patch;
                            }
                        } else if minor > 0 {
                            if vers.minor != minor {
                                return false;
                            } else if vers.patch != patch {
                                return vers.patch > patch;
                            }
                        } else if vers.minor != minor || vers.patch != patch {
                            return false;
                        }

                        true
                    }
                    Op::Tilde => {
                        if comp.major != vers.major {
                            return false;
                        }

                        if let Some(minor) = comp.minor
                            && minor != vers.minor
                        {
                            return false;
                        }

                        if let Some(patch) = comp.patch
                            && patch != vers.patch
                        {
                            return patch < vers.patch;
                        }

                        true
                    }
                    _ => unreachable!("fucking non-exhaustive"),
                }
            })
        })
    }

    !(check(&versions.patched, version) || check(&versions.unaffected, version))
}
