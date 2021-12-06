use crate::{Krate, Krates};
use anyhow::{Context, Error};
use log::{debug, info};
pub use rustsec::{advisory::Id, lockfile::Lockfile, Database, Vulnerability};
use std::path::{Path, PathBuf};
use url::Url;

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    Disallow,
}

/// A collection of [`Database`]s that is used to query advisories
/// in many different databases.
///
/// [`Database`]: https://docs.rs/rustsec/0.21.0/rustsec/database/struct.Database.html
pub struct DbSet {
    dbs: Vec<(Url, Database)>,
}

impl DbSet {
    pub fn load(
        root: Option<impl AsRef<Path>>,
        mut urls: Vec<Url>,
        fetch: Fetch,
    ) -> Result<Self, Error> {
        let root_db_path = match root {
            Some(root) => {
                let user_root = root.as_ref();
                if user_root.starts_with("~") {
                    match home::home_dir() {
                        Some(home) => home.join(user_root.strip_prefix("~").unwrap()),
                        None => {
                            log::warn!(
                                "unable to resolve path '{}', falling back to the default advisory path",
                                user_root.display()
                            );

                            // This would only succeed of CARGO_HOME was explicitly set
                            home::cargo_home()
                                .context("failed to resolve CARGO_HOME")?
                                .join("advisory-dbs")
                        }
                    }
                } else {
                    user_root.to_owned()
                }
            }
            None => home::cargo_home()
                .context("failed to resolve CARGO_HOME")?
                .join("advisory-dbs"),
        };

        if urls.is_empty() {
            info!(
                "No advisory database configured, falling back to default '{}'",
                rustsec::repository::git::DEFAULT_URL
            );
            urls.push(Url::parse(rustsec::repository::git::DEFAULT_URL).unwrap());
        }

        use rayon::prelude::*;
        let mut dbs = Vec::with_capacity(urls.len());
        urls.into_par_iter()
            .map(|url| load_db(&url, root_db_path.clone(), fetch).map(|db| (url, db)))
            .collect_into_vec(&mut dbs);

        Ok(Self {
            dbs: dbs.into_iter().collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &(Url, Database)> {
        self.dbs.iter()
    }

    pub fn has_advisory(&self, id: &Id) -> bool {
        self.dbs.iter().any(|db| db.1.get(id).is_some())
    }
}

/// Convert an advisory url to a directory underneath a specified root
fn url_to_path(mut db_path: PathBuf, url: &Url) -> Result<PathBuf, Error> {
    let (ident, _) = crate::index::url_to_local_dir(url.as_str())?;
    db_path.push(ident);

    Ok(db_path)
}

fn load_db(db_url: &Url, root_db_path: PathBuf, fetch: Fetch) -> Result<Database, Error> {
    use rustsec::repository::git::Repository;
    let db_path = url_to_path(root_db_path, db_url)?;

    let db_repo = match fetch {
        Fetch::Allow => {
            debug!("Fetching advisory database from '{}'", db_url);

            Repository::fetch(db_url.as_str(), &db_path, true /* ensure_fresh */)
                .context("failed to fetch advisory database")?
        }
        Fetch::Disallow => {
            debug!("Opening advisory database at '{}'", db_path.display());

            Repository::open(&db_path).context("failed to open advisory database")?
        }
    };

    debug!("loading advisory database from {}", db_path.display());

    let res = Database::load_from_repo(&db_repo).context("failed to load advisory database");

    debug!(
        "finished loading advisory database from {}",
        db_path.display()
    );

    res
}

pub fn load_lockfile(path: &krates::Utf8Path) -> Result<Lockfile, Error> {
    let mut lockfile = Lockfile::load(path)?;

    // Remove the metadata as it is irrelevant
    lockfile.metadata = Default::default();

    Ok(lockfile)
}

pub struct PrunedLockfile(pub(crate) Lockfile);

impl PrunedLockfile {
    pub fn prune(mut lf: Lockfile, krates: &Krates) -> Self {
        // Remove any packages from the rustsec's view of the lockfile that we
        // have filtered out of the graph we are actually checking
        lf.packages
            .retain(|pkg| krate_for_pkg(krates, pkg).is_some());

        Self(lf)
    }
}

#[inline]
pub(crate) fn krate_for_pkg<'a>(
    krates: &'a Krates,
    pkg: &rustsec::package::Package,
) -> Option<(krates::NodeId, &'a Krate)> {
    krates
        .krates_by_name(pkg.name.as_str())
        .find(|(_, kn)| {
            pkg.version == kn.krate.version
                && match (&pkg.source, &kn.krate.source) {
                    (Some(psrc), Some(ksrc)) => psrc == ksrc,
                    (None, None) => true,
                    _ => false,
                }
        })
        .map(|(ind, krate)| (ind, &krate.krate))
}

pub use rustsec::warning::{Kind, Warning};

pub struct Report {
    pub vulnerabilities: Vec<Vulnerability>,
    pub notices: Vec<Warning>,
    pub unmaintained: Vec<Warning>,
    pub unsound: Vec<Warning>,
    /// For backwards compatiblity with cargo-audit, we optionally serialize the
    /// reports to JSON and output them in addition to the normal cargo-deny
    /// diagnostics
    pub serialized_reports: Vec<serde_json::Value>,
}

impl Report {
    pub fn generate(
        advisory_dbs: &DbSet,
        lockfile: &PrunedLockfile,
        serialize_reports: bool,
    ) -> Self {
        use rustsec::advisory::Informational;

        let settings = rustsec::report::Settings {
            // We already prune packages we don't care about, so don't filter
            // any here
            target_arch: None,
            target_os: None,
            package_scope: None,
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
        };

        let mut vulnerabilities = Vec::new();
        let mut notices = Vec::new();
        let mut unmaintained = Vec::new();
        let mut unsound = Vec::new();
        let mut serialized_reports = Vec::with_capacity(if serialize_reports {
            advisory_dbs.dbs.len()
        } else {
            0
        });

        for (url, db) in advisory_dbs.iter() {
            let mut rep = rustsec::Report::generate(db, &lockfile.0, &settings);

            if serialize_reports {
                match serde_json::to_value(&rep) {
                    Ok(val) => serialized_reports.push(val),
                    Err(err) => {
                        log::error!("Failed to serialize report for database '{}': {}", url, err);
                    }
                }
            }

            vulnerabilities.append(&mut rep.vulnerabilities.list);

            for (kind, mut wi) in rep.warnings {
                if wi.is_empty() {
                    continue;
                }

                match kind {
                    Kind::Notice => notices.append(&mut wi),
                    Kind::Unmaintained => unmaintained.append(&mut wi),
                    Kind::Unsound => unsound.append(&mut wi),
                    _ => unreachable!(),
                }
            }
        }

        Self {
            vulnerabilities,
            notices,
            unmaintained,
            unsound,
            serialized_reports,
        }
    }

    pub fn iter_warnings(&self) -> impl Iterator<Item = (Kind, &Warning)> {
        self.notices
            .iter()
            .map(|wi| (Kind::Notice, wi))
            .chain(self.unmaintained.iter().map(|wi| (Kind::Unmaintained, wi)))
            .chain(self.unsound.iter().map(|wi| (Kind::Unsound, wi)))
    }
}

#[cfg(test)]
mod test {
    use super::url_to_path;
    use url::Url;

    #[test]
    fn converts_url_to_path() {
        let root_path = std::env::current_dir().unwrap();

        {
            let url = Url::parse("https://github.com/RustSec/advisory-db").unwrap();
            assert_eq!(
                url_to_path(root_path.clone(), &url).unwrap(),
                root_path.join("github.com-2f857891b7f43c59")
            );
        }

        {
            let url = Url::parse("https://bare.com").unwrap();
            assert_eq!(
                url_to_path(root_path.clone(), &url).unwrap(),
                root_path.join("bare.com-9c003d1ed306b28c")
            );
        }

        {
            let url = Url::parse("https://example.com/countries/việt nam").unwrap();
            assert_eq!(
                url_to_path(root_path.clone(), &url).unwrap(),
                root_path.join("example.com-1c03f84825fb7438")
            );
        }
    }
}
