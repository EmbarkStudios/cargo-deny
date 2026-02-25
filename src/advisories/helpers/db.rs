use crate::{Krate, Krates, Path, PathBuf};
use anyhow::Context as _;
use log::{debug, info};
pub use rustsec::{Database, advisory::Id};
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
#[derive(Debug)]
pub struct DbSet {
    pub dbs: Vec<AdvisoryDb>,
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
        let _lock = tame_index::utils::flock::LockOptions::new(&lock_path)
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
        })
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &AdvisoryDb> {
        self.dbs.iter()
    }

    #[inline]
    pub fn has_advisory(&self, id: &Id) -> bool {
        self.dbs.iter().any(|adb| adb.db.get(id).is_some())
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

    let res = Database::open(db_path.as_std_path()).context("failed to load advisory database");

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
    pub advisories: Vec<(&'k Krate, &'db rustsec::Advisory)>,
    /// For backwards compatibility with cargo-audit, we optionally serialize the
    /// reports to JSON and output them in addition to the normal cargo-deny
    /// diagnostics
    pub serialized_reports: Vec<serde_json::Value>,
}

impl<'db, 'k> Report<'db, 'k> {
    pub fn generate(advisory_dbs: &'db DbSet, krates: &'k Krates, serialize_reports: bool) -> Self {
        let mut serialized_reports = Vec::with_capacity(if serialize_reports {
            advisory_dbs.dbs.len()
        } else {
            0
        });

        // We just use rustsec::Report directly to avoid divergence with cargo-audit,
        // but since we operate differently we need to do shenanigans
        let fake_lockfile = serialize_reports.then(|| {
            // This is really gross, but the only field is private :p
            let lfi: rustsec::report::LockfileInfo = serde_json::from_value(serde_json::json!({
                "dependency-count": krates.len()
            }))
            .expect("check the definition of rustsec::report::LockfileInfo, it's been changed");

            lfi
        });

        let mut advisories = Vec::new();
        use rayon::prelude::{ParallelBridge, ParallelIterator};

        for advisory_db in advisory_dbs.iter() {
            // Ugh, db exposes advisories as a slice iter which rayon doesn't have an impl for :(
            let mut db_advisories: Vec<_> = advisory_db
                .db
                .iter()
                .par_bridge()
                .filter(|advisory| {
                    if let Some(wdate) = &advisory.metadata.withdrawn {
                        log::trace!(
                            "ignoring advisory '{}', withdrawn {wdate}",
                            advisory.metadata.id
                        );
                        return false;
                    }

                    // TODO: Support Rust std/core advisories at some point, but
                    // AFAIK rustsec/cargo-audit doesn't support checking for them either
                    advisory
                        .metadata
                        .collection
                        .is_none_or(|c| c == rustsec::Collection::Crates)
                })
                .flat_map(|advisory| {
                    krates
                        .krates_by_name(advisory.metadata.package.as_str())
                        .par_bridge()
                        .filter_map(move |km| {
                            let ksrc = km.krate.source.as_ref()?;

                            // Validate the crate's source is the same as the advisory
                            if !ksrc.matches_rustsec(advisory.metadata.source.as_ref()) {
                                return None;
                            }

                            // Ensure the crate's version is actually affected
                            if !advisory.versions.is_vulnerable(&km.krate.version) {
                                return None;
                            }

                            Some((km.krate, advisory))
                        })
                })
                .collect();

            if let Some(lockfile) = fake_lockfile.clone() {
                let mut warnings = std::collections::BTreeMap::<_, Vec<rustsec::Warning>>::new();
                let mut vulns = Vec::new();

                for (krate, advisory) in &db_advisories {
                    let package = rustsec::package::Package {
                        // :(
                        name: krate.name.parse().unwrap(),
                        version: krate.version.clone(),
                        source: krate.source.as_ref().map(|s| s.to_rustsec()),
                        // TODO: Get this info from the lockfile
                        checksum: None,
                        dependencies: Vec::new(),
                        replace: None,
                    };

                    if let Some(kind) = advisory
                        .metadata
                        .informational
                        .as_ref()
                        .and_then(|i| i.warning_kind())
                    {
                        let warning = rustsec::Warning {
                            kind,
                            package,
                            advisory: Some(advisory.metadata.clone()),
                            versions: Some(advisory.versions.clone()),
                            affected: advisory.affected.clone(),
                        };

                        if let Some(v) = warnings.get_mut(&kind) {
                            v.push(warning);
                        } else {
                            warnings.insert(kind, vec![warning]);
                        }
                    } else {
                        // Note we don't use new here since it takes references and just clones :p
                        vulns.push(rustsec::Vulnerability {
                            advisory: advisory.metadata.clone(),
                            versions: advisory.versions.clone(),
                            affected: advisory.affected.clone(),
                            package,
                        });
                    }
                }

                use rustsec::advisory::Informational;
                let rep = rustsec::Report {
                    settings: rustsec::report::Settings {
                        // We already prune packages we don't care about, so don't filter
                        // any here
                        target_arch: Vec::new(),
                        target_os: Vec::new(),
                        // We handle the severity ourselves
                        severity: None,
                        // We handle the ignoring of particular advisory ids ourselves
                        ignore: Vec::new(),
                        informational_warnings: vec![
                            Informational::Notice,
                            Informational::Unmaintained,
                            Informational::Unsound,
                            //Informational::Other("*"),
                        ],
                    },
                    lockfile,
                    vulnerabilities: rustsec::report::VulnerabilityInfo::new(vulns),
                    warnings,
                };

                match serde_json::to_value(&rep) {
                    Ok(val) => serialized_reports.push(val),
                    Err(err) => {
                        log::error!(
                            "Failed to serialize report for database '{}': {err}",
                            advisory_db.url
                        );
                    }
                }
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
                a.1.id().cmp(b.1.id())
            }
        });

        Self {
            advisories,
            serialized_reports,
        }
    }
}
