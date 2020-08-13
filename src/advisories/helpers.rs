use crate::{Krate, Krates};
use anyhow::{Context, Error};
use log::{debug, info};
pub use rustsec::{advisory::Id, lockfile::Lockfile, Database, Vulnerability};
use std::path::{Path, PathBuf};
use url::Url;

const ADVISORY_DB_ROOT: &str = "~/.cargo/advisory-dbs";

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
        let root = root
            .as_ref()
            .map(AsRef::as_ref)
            .unwrap_or_else(|| Path::new(ADVISORY_DB_ROOT));

        let root_db_path = if root.starts_with("~") {
            match home::home_dir() {
                Some(home) => home.join(root.strip_prefix("~").unwrap()),
                None => {
                    log::warn!(
                        "unable to resolve path '{}', falling back to the default advisory path",
                        root.display()
                    );

                    home::cargo_home().context("failed to resolve CARGO_HOME")?
                }
            }
        } else {
            root.to_owned()
        };

        if urls.is_empty() {
            info!(
                "No advisory database configured, falling back to default '{}'",
                rustsec::repository::DEFAULT_URL
            );
            urls.push(Url::parse(rustsec::repository::DEFAULT_URL).unwrap());
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
}

/// Convert an advisory url to a directory underneath a specified root
fn url_to_path(mut db_path: PathBuf, url: &Url) -> Result<PathBuf, Error> {
    // Take the domain and path portion of the url to ensure we have a unique directory
    // for each unique url
    db_path.push(
        url.domain()
            .with_context(|| format!("Advisory url '{}' has no domain name", url))?,
    );

    for ps in url.path_segments().with_context(|| {
        format!(
            "Advisory db url '{}' is invalid as it cannot be a base",
            url
        )
    })? {
        let segment = percent_encoding::percent_decode_str(ps)
            .decode_utf8()
            .with_context(|| {
                format!("failed to decode path segment '{}' from url '{}'", ps, url)
            })?;
        db_path.push(segment.as_ref());
    }

    Ok(db_path)
}

fn load_db(db_url: &Url, root_db_path: PathBuf, fetch: Fetch) -> Result<Database, Error> {
    use rustsec::Repository;
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

    let res = Database::load(&db_repo).context("failed to load advisory database");

    debug!(
        "finished loading advisory database from {}",
        db_path.display()
    );

    res
}

pub fn load_lockfile(path: &Path) -> Result<Lockfile, Error> {
    let mut lockfile = Lockfile::load(path)?;

    // Remove the metadata as it is irrelevant
    lockfile.metadata = Default::default();

    Ok(lockfile)
}

pub struct PrunedLockfile(pub(crate) Lockfile);

impl PrunedLockfile {
    pub fn prune(mut lf: Lockfile, krates: &Krates) -> Self {
        // Remove any packages from the rustsec's view of the lockfile that we have
        // filtered out of the graph we are actually checking
        lf.packages
            .retain(|pkg| krate_for_pkg(krates, pkg).is_some());

        Self(lf)
    }
}

#[inline]
pub(crate) fn krate_for_pkg<'a>(
    krates: &'a Krates,
    pkg: &rustsec::package::Package,
) -> Option<(usize, &'a Krate)> {
    krates
        .krates_by_name(pkg.name.as_str())
        .find(|(_, kn)| {
            // Temporary hack due to cargo-lock using an older version of semver
            let pkg_version: Result<semver::Version, _> = pkg.version.to_string().parse();

            if let Ok(pkg_version) = pkg_version {
                pkg_version == kn.krate.version
                    && match (&pkg.source, &kn.krate.source) {
                        (Some(psrc), Some(ksrc)) => psrc == ksrc,
                        (None, None) => true,
                        _ => false,
                    }
            } else {
                false
            }
        })
        .map(|(ind, krate)| (ind.index(), &krate.krate))
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
        use rustsec::advisory::informational::Informational;

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

    pub fn gather_patches(&self, krates: &Krates) -> PatchSet<'_> {
        use krates::petgraph as pg;
        use pg::Direction;

        let graph = krates.graph();

        let index = crates_index::new_cargo_default();

        for vuln in &self.vulnerabilities {
            index.crate_(

            let (ind, vuln_krate) = krate_for_pkg(krates, &vuln.package).unwrap();

            
        }
    }
}

fn get_patches(vuln_id: usize, ) {
    // 1. Get the package with the vulnerability
    // 2. Recursively walk up the dependency chain until we've reach all roots
    // (workspace crates) that depend on the vulnerable crate version
    // 3. For each crate in the chain, check to see if has a version
    // available that ultimately includes a patched version of the vulnerable crate
    let mut krate_stack = vec![(vuln_id, )];

    while let Some((nid, )) = krate_stack.pop() {
        for edge in graph.edges_directed(nid, Direction::Incoming) {
    
        }
    }

}

enum PatchLink<'a> {}

pub struct Patch<'a> {
    /// The vulnerability the patch is attempting to address
    pub vuln: &'a Vulnerability,
    /// The vulnerable crate
    pub krate: &'a Krate,
}

pub struct PatchSet<'a> {
    patches: Vec<Patch<'a>>,
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
                root_path.join("github.com/RustSec/advisory-db")
            );
        }

        {
            let url = Url::parse("https://bare.com").unwrap();
            assert_eq!(
                url_to_path(root_path.clone(), &url).unwrap(),
                root_path.join("bare.com")
            );
        }

        {
            let url = Url::parse("https://example.com/countries/việt nam").unwrap();
            assert_eq!(
                url_to_path(root_path.clone(), &url).unwrap(),
                root_path.join("example.com/countries/việt nam")
            );
        }
    }
}
