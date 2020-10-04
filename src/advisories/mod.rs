pub mod cfg;

use crate::{
    diag::{self, Check, Diagnostic, Label, Severity},
    Krate, Krates, LintLevel,
};
use anyhow::{Context, Error};
use log::debug;
pub use rustsec::{advisory::Id, lockfile::Lockfile, Database};
use rustsec::{
    database::{scope::Package, Query},
    repository as repo, Advisory, Repository, Vulnerability,
};
use std::path::{Path, PathBuf};

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    Disallow,
}

/// A collection of [`Database`]s that is used to query advisories
/// in many different databases.
///
/// It mirrors the API of a single [`Database`], but will query all databases.
///
/// [`Database`]: https://docs.rs/rustsec/0.21.0/rustsec/database/struct.Database.html
pub struct DatabaseCollection {
    dbs: Vec<Database>,
}

impl DatabaseCollection {
    pub fn new(dbs: Vec<Database>) -> Self {
        Self { dbs }
    }

    pub fn get(&self, id: &Id) -> Option<&Advisory> {
        self.dbs.iter().flat_map(|db| db.get(id)).next()
    }

    pub fn query(&self, query: &Query) -> Vec<&Advisory> {
        let mut results = self
            .dbs
            .iter()
            .flat_map(|db| db.query(query))
            .collect::<Vec<_>>();
        results.dedup();
        results
    }

    pub fn query_vulnerabilities(
        &self,
        lockfile: &Lockfile,
        query: &Query,
        package_scope: impl Into<Package>,
    ) -> Vec<Vulnerability> {
        let package_scope = package_scope.into();
        let mut results = self
            .dbs
            .iter()
            .flat_map(|db| db.query_vulnerabilities(lockfile, query, package_scope.clone()))
            .collect::<Vec<_>>();
        results.dedup();
        results
    }

    pub fn vulnerabilities(&self, lockfile: &Lockfile) -> Vec<Vulnerability> {
        let mut results = self
            .dbs
            .iter()
            .flat_map(|db| db.vulnerabilities(lockfile))
            .collect::<Vec<_>>();
        results.dedup();
        results
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Database> {
        self.dbs.iter()
    }
}

pub fn load_dbs(
    mut db_urls: Vec<&str>,
    mut db_paths: Vec<PathBuf>,
    fetch: Fetch,
) -> Result<DatabaseCollection, Error> {
    db_urls.dedup();
    if db_urls.is_empty() {
        db_urls.push(repo::DEFAULT_URL);
    }

    db_paths.dedup();
    if db_paths.is_empty() {
        db_paths.push(Repository::default_path());
    }

    let dbs = db_urls
        .into_iter()
        .zip(db_paths)
        .map(|(url, path)| load_db(&url, path, fetch))
        .collect::<Result<Vec<_>, Error>>()?;

    Ok(DatabaseCollection::new(dbs))
}

fn load_db(
    advisory_db_url: &str,
    advisory_db_path: PathBuf,
    fetch: Fetch,
) -> Result<Database, Error> {
    let advisory_db_path = if advisory_db_path.starts_with("~") {
        match home::home_dir() {
            Some(home) => home.join(advisory_db_path.strip_prefix("~").unwrap()),
            None => {
                log::warn!(
                    "unable to resolve path '{}', falling back to the default advisory path",
                    advisory_db_path.display()
                );
                Repository::default_path()
            }
        }
    } else {
        advisory_db_path
    };

    let advisory_db_repo = match fetch {
        Fetch::Allow => {
            debug!("Fetching advisory database from '{}'", advisory_db_url);

            Repository::fetch(
                advisory_db_url,
                &advisory_db_path,
                true, /* ensure_fresh */
            )
            .context("failed to fetch advisory database")?
        }
        Fetch::Disallow => {
            debug!(
                "Opening advisory database at '{}'",
                advisory_db_path.display()
            );

            Repository::open(&advisory_db_path).context("failed to open advisory database")?
        }
    };

    debug!(
        "loading advisory database from {}",
        advisory_db_path.display()
    );

    let res = Database::load(&advisory_db_repo).context("failed to load advisory database");

    debug!(
        "finished loading advisory database from {}",
        advisory_db_path.display()
    );

    res
}

pub fn load_lockfile(path: &Path) -> Result<Lockfile, Error> {
    let mut lockfile = Lockfile::load(path)?;

    // Remove the metadata as it is irrelevant
    lockfile.metadata = Default::default();

    Ok(lockfile)
}

#[inline]
fn krate_for_pkg<'a>(
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

/// Check crates against the advisory database to detect vulnerabilities or
/// unmaintained crates
pub fn check(
    ctx: crate::CheckCtx<'_, cfg::ValidConfig>,
    advisory_dbs: &DatabaseCollection,
    mut lockfile: rustsec::lockfile::Lockfile,
    sender: crossbeam::channel::Sender<diag::Pack>,
) {
    use rustsec::{
        advisory::{informational::Informational, metadata::Metadata},
        package::Package,
    };

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
            //Informational::Other("*"),
        ],
    };

    // Remove any packages from the rustsec's view of the lockfile that we have
    // filtered out of the graph we are actually checking
    lockfile
        .packages
        .retain(|pkg| krate_for_pkg(&ctx.krates, pkg).is_some());

    let (reports, yanked) = rayon::join(
        || {
            advisory_dbs
                .iter()
                .map(|db| rustsec::Report::generate(db, &lockfile, &settings))
                .collect::<Vec<_>>()
        },
        || {
            let index = rustsec::registry::Index::open()?;
            let mut yanked = Vec::new();

            for package in &lockfile.packages {
                if let Ok(index_entry) = index.find(&package.name, &package.version) {
                    if index_entry.is_yanked {
                        yanked.push(package);
                    }
                }
            }

            Ok(yanked)
        },
    );

    // rust is having trouble doing type inference
    let yanked: Result<_, rustsec::Error> = yanked;

    use bitvec::prelude::*;
    let mut ignore_hits = bitvec![0; ctx.cfg.ignore.len()];

    let mut make_diag = |pkg: &Package, advisory: &Metadata| -> diag::Pack {
        match krate_for_pkg(&ctx.krates, pkg) {
            Some((i, krate)) => {
                let id = &advisory.id;

                let (severity, message) = {
                    let (lint_level, msg) = match &advisory.informational {
                        // Everything that isn't an informational advisory is a vulnerability
                        None => (
                            ctx.cfg.vulnerability,
                            "security vulnerability detected".to_owned(),
                        ),
                        Some(info) => match info {
                            // Security notices for a crate which are published on https://rustsec.org
                            // but don't represent a vulnerability in a crate itself.
                            Informational::Notice => {
                                (ctx.cfg.notice, "notice advisory detected".to_owned())
                            }
                            // Crate is unmaintained / abandoned
                            Informational::Unmaintained => (
                                ctx.cfg.unmaintained,
                                "unmaintained advisory detected".to_owned(),
                            ),
                            // Other types of informational advisories: left open-ended to add
                            // more of them in the future.
                            Informational::Other(_) => {
                                unreachable!("rustsec only returns these if we ask, and there are none at the moment to ask for");
                            }
                            _ => unreachable!("unknown advisory type encountered"),
                        },
                    };

                    // Ok, we found a crate whose version lies within the range of an
                    // advisory, but the user might have decided to ignore it
                    // for "reasons", but in that case we still emit it to the log
                    // so it doesn't just disappear into the aether
                    let lint_level =
                        if let Ok(index) = ctx.cfg.ignore.binary_search_by(|i| i.value.cmp(id)) {
                            ignore_hits.as_mut_bitslice().set(index, true);
                            LintLevel::Allow
                        } else if let Some(severity_threshold) = ctx.cfg.severity_threshold {
                            if let Some(advisory_severity) =
                                advisory.cvss.as_ref().map(|cvss| cvss.severity())
                            {
                                if advisory_severity < severity_threshold {
                                    LintLevel::Allow
                                } else {
                                    lint_level
                                }
                            } else {
                                lint_level
                            }
                        } else {
                            lint_level
                        };

                    (
                        match lint_level {
                            LintLevel::Warn => Severity::Warning,
                            LintLevel::Deny => Severity::Error,
                            LintLevel::Allow => Severity::Help,
                        },
                        msg,
                    )
                };

                let notes = {
                    let mut n = Vec::new();

                    n.push(advisory.description.clone());

                    if let Some(ref url) = advisory.url {
                        n.push(format!("URL: {}", url));
                    }

                    n
                };

                let mut pack = diag::Pack::with_kid(Check::Advisories, krate.id.clone());
                let diag = pack.push(
                    Diagnostic::new(severity)
                        .with_message(advisory.title.clone())
                        .with_labels(vec![ctx.label_for_span(i, message)])
                        .with_code(id.as_str().to_owned())
                        .with_notes(notes),
                );

                if ctx.serialize_extra {
                    diag.extra = serde_json::to_value(&advisory)
                        .ok()
                        .map(|v| ("advisory", v));
                }

                pack
            }
            None => {
                unreachable!(
                    "the advisory database report contained an advisory 
                    that somehow matched a crate we don't know about:\n{:#?}",
                    advisory
                );
            }
        }
    };

    // Check if any vulnerabilities were found
    if reports.iter().any(|report| report.vulnerabilities.found) {
        for vuln in reports
            .iter()
            .flat_map(|report| &report.vulnerabilities.list)
        {
            sender
                .send(make_diag(&vuln.package, &vuln.advisory))
                .unwrap();
        }
    }

    // Check for informational advisories for crates, including unmaintained
    for (_kind, warnings) in reports.iter().flat_map(|report| &report.warnings) {
        for warning in warnings {
            if let Some(advisory) = &warning.advisory {
                let diag = make_diag(&warning.package, &advisory);
                sender.send(diag).unwrap();
            }
        }
    }

    match yanked {
        Ok(yanked) => {
            for pkg in yanked {
                let diag = match krate_for_pkg(&ctx.krates, &pkg) {
                    Some((ind, krate)) => {
                        let mut pack = diag::Pack::with_kid(Check::Advisories, krate.id.clone());
                        pack.push(
                            Diagnostic::new(match ctx.cfg.yanked.value {
                                LintLevel::Allow => Severity::Help,
                                LintLevel::Deny => Severity::Error,
                                LintLevel::Warn => Severity::Warning,
                            })
                            .with_message("detected yanked crate")
                            .with_labels(vec![ctx.label_for_span(ind, "yanked version")]),
                        );

                        pack
                    }
                    None => unreachable!(
                        "the advisory database warned about yanked crate that we don't have: {:#?}",
                        pkg
                    ),
                };

                sender.send(diag).unwrap();
            }
        }
        Err(e) => {
            if ctx.cfg.yanked.value != LintLevel::Allow {
                let mut diag = diag::Pack::new(Check::Advisories);
                diag.push(
                    Diagnostic::warning()
                        .with_message(format!("unable to check for yanked crates: {}", e))
                        .with_labels(vec![Label::primary(ctx.cfg.file_id, ctx.cfg.yanked.span)
                            .with_message("lint level defined here")]),
                );
                sender.send(diag).unwrap();
            }
        }
    }

    // Check for advisory identifers that were set to be ignored, but
    // were not actually encountered, for cases where a crate, or specific
    // verison of that crate, has been removed or replaced and the advisory
    // no longer applies to it so that users can cleanup their configuration
    for ignore in ignore_hits
        .into_iter()
        .zip(ctx.cfg.ignore.into_iter())
        .filter_map(|(hit, ignore)| if !hit { Some(ignore) } else { None })
    {
        sender
            .send(
                (
                    Check::Advisories,
                    Diagnostic::warning()
                        .with_message("advisory was not encountered")
                        .with_labels(vec![Label::primary(ctx.cfg.file_id, ignore.span)
                            .with_message("no crate matched advisory criteria")]),
                )
                    .into(),
            )
            .unwrap();
    }
}
