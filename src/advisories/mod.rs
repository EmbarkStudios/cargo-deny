pub mod cfg;

use crate::{
    cm,
    diag::{self, Diagnostic, Label, Severity},
    Krates, LintLevel,
};
use anyhow::{Context, Error};
use log::info;
pub use rustsec::{advisory::Id, lockfile::Lockfile, Database};
use rustsec::{repository as repo, Repository};
use std::path::{Path, PathBuf};

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    Disallow,
}

pub fn load_db(
    db_url: Option<&str>,
    db_path: Option<PathBuf>,
    fetch: Fetch,
) -> Result<Database, Error> {
    let advisory_db_url = db_url.unwrap_or(repo::DEFAULT_URL);
    let advisory_db_path = db_path
        .and_then(|path| {
            if path.starts_with("~") {
                match home::home_dir() {
                    Some(home) => Some(home.join(path.strip_prefix("~").unwrap())),
                    None => {
                        log::warn!(
                            "unable to resolve path '{}', falling back to the default advisory path",
                            path.display()
                        );
                        None
                    }
                }
            } else {
                Some(path)
            }
        })
        .unwrap_or_else(Repository::default_path);

    let advisory_db_repo = match fetch {
        Fetch::Allow => {
            info!("Fetching advisory database from '{}'", advisory_db_url);

            Repository::fetch(
                advisory_db_url,
                &advisory_db_path,
                true, /* ensure_fresh */
            )
            .context("failed to fetch advisory database")?
        }
        Fetch::Disallow => {
            info!(
                "Opening advisory database at '{}'",
                advisory_db_path.display()
            );

            Repository::open(&advisory_db_path).context("failed to open advisory database")?
        }
    };

    info!(
        "loading advisory database from {}",
        advisory_db_path.display()
    );
    Ok(Database::load(&advisory_db_repo).context("failed to load advisory database")?)
}

pub fn load_lockfile(path: &Path) -> Result<Lockfile, Error> {
    let mut lockfile = Lockfile::load(path)?;

    // Remove the metadata as it is irrelevant
    lockfile.metadata = Default::default();

    Ok(lockfile)
}

/// Generates rustsec::lockfile::Lockfile from the crates gathered via cargo_metadata,
/// rather than deserializing them from the lockfile again
pub fn generate_lockfile(krates: &Krates) -> Lockfile {
    use rustsec::{
        cargo_lock::{dependency::Dependency, package::Source},
        package::Package,
    };

    let mut packages = Vec::with_capacity(krates.len());

    fn im_so_sorry(s: &cm::Source) -> Source {
        // cargo_metadata::Source(String) doesn't have as_str()/as_ref()/into() :(
        let oh_no = format!("{}", s);

        // cargo_lock::package::Source(String) doesn't have from()/new() :(
        oh_no.parse().expect("guess this is no longer infallible")
    }

    for (nid, krate) in krates
        .krates()
        .map(|kn| (krates.nid_for_kid(&kn.id).unwrap(), &kn.krate))
    {
        let mut dependencies: Vec<_> = krates
            .get_deps(nid)
            .map(|(dep, _)| {
                let dep = &dep.krate;
                Dependency {
                    // This will hide errors if the FromStr implementation
                    // begins to fail at some point, but right now it is infallible
                    name: dep.name.parse().unwrap(),
                    version: Some(dep.version.clone()),
                    // This will hide errors if the FromStr implementation
                    // begins to fail at some point, but right now it is infallible
                    source: dep.source.as_ref().map(|s| im_so_sorry(s)),
                }
            })
            .collect();

        use std::cmp::Ordering;

        // Sort the dependencies as they would be in the Cargo.lock
        dependencies.sort_by(|a, b| match a.name.cmp(&b.name) {
            Ordering::Equal => match a.version.cmp(&b.version) {
                Ordering::Equal => a.source.cmp(&b.source),
                other => other,
            },
            other => other,
        });

        // Remove duplicates, this can occur if there are eg a normal and build dependency
        // on the same crate, Cargo.lock only records unique crates once
        dependencies.dedup();

        packages.push(Package {
            // This will hide errors if the FromStr implementation
            // begins to fail at some point, but right now it is infallible
            name: krate.name.parse().unwrap(),
            version: krate.version.clone(),
            // This will hide errors if the FromStr implementation
            // begins to fail at some point, but right now it is infallible
            source: krate.source.as_ref().map(|s| im_so_sorry(s)),
            dependencies,
        });
    }

    Lockfile {
        packages,
        metadata: Default::default(),
    }
}

/// Check crates against the advisory database to detect vulnerabilities or
/// unmaintained crates
pub fn check(
    ctx: crate::CheckCtx<'_, cfg::ValidConfig>,
    advisory_db: &Database,
    lockfile: &rustsec::lockfile::Lockfile,
    sender: crossbeam::channel::Sender<diag::Pack>,
) {
    use rustsec::{
        advisory::{informational::Informational, metadata::Metadata},
        package::Package,
    };

    let settings = rustsec::report::Settings {
        target_arch: None,
        target_os: None,
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

    let report = rustsec::Report::generate(&advisory_db, &lockfile, &settings);

    use bitvec::prelude::*;
    let mut ignore_hits = bitvec![0; ctx.cfg.ignore.len()];

    let mut make_diag = |pkg: &Package, advisory: &Metadata| -> diag::Pack {
        match ctx
            .krates
            .krates_by_name(pkg.name.as_str())
            .find(|(_, kn)| pkg.version == kn.krate.version)
        {
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
                                //(cfg.other, format!("{} advisory detected", kind))
                            }
                        },
                    };

                    // Ok, we found a crate whose version lies within the range of an
                    // advisory, but the user might have decided to ignore it
                    // for "reasons", but in that case we still emit it to the log
                    // so it doesn't just disappear into the aether
                    let lint_level =
                        if let Ok(index) = ctx.cfg.ignore.binary_search_by(|i| i.item.cmp(id)) {
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
                            LintLevel::Allow => Severity::Note,
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

                let mut pack = diag::Pack::with_kid(krate.id.clone());
                pack.push(
                    Diagnostic::new(
                        severity,
                        advisory.title.clone(),
                        ctx.label_for_span(i.index(), message),
                    )
                    .with_code(id.as_str().to_owned())
                    .with_notes(notes),
                );

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
    if report.vulnerabilities.found {
        for vuln in &report.vulnerabilities.list {
            sender
                .send(make_diag(&vuln.package, &vuln.advisory))
                .unwrap();
        }
    }

    // Check for informational advisories for crates, including unmaintained
    for warning in report.warnings {
        sender
            .send(make_diag(&warning.package, &warning.advisory))
            .unwrap();
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
                Diagnostic::new(
                    Severity::Warning,
                    "advisory was not encountered",
                    Label::new(
                        ctx.cfg.file_id,
                        ignore.span,
                        "no crate matched advisory criteria",
                    ),
                )
                .into(),
            )
            .unwrap();
    }
}
