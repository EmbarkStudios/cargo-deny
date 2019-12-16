pub mod cfg;

use crate::{
    diag::{self, Diagnostic, Label, Severity},
    LintLevel,
};
use anyhow::{Context, Error};
use log::info;
pub use rustsec::{advisory::Id, lockfile::Lockfile, Database};
use rustsec::{repository as repo, Repository};
use std::path::Path;

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    Disallow,
}

pub fn load_db(cfg: &cfg::ValidConfig, fetch: Fetch) -> Result<Database, Error> {
    let advisory_db_url = cfg
        .db_url
        .as_ref()
        .map(AsRef::as_ref)
        .unwrap_or(repo::DEFAULT_URL);

    let advisory_db_path = cfg
        .db_path
        .as_ref()
        .cloned()
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

    Ok(Database::load(&advisory_db_repo).context("failed to load advisory database")?)
}

pub fn load_lockfile(path: &Path) -> Result<Lockfile, Error> {
    Ok(Lockfile::load(path)?)
}

/// Check crates against the advisory database to detect vulnerabilities or
/// unmaintained crates
pub fn check(
    cfg: cfg::ValidConfig,
    krates: &crate::Krates,
    (krate_spans, spans_id): (&diag::KrateSpans, codespan::FileId),
    advisory_db: Database,
    lockfile: rustsec::lockfile::Lockfile,
    sender: crossbeam::channel::Sender<diag::Pack>,
) {
    use rustsec::{
        advisory::{informational::Informational, metadata::Metadata},
        package::Package,
    };

    let settings = rustsec::report::Settings {
        target_arch: None,
        target_os: None,
        severity: cfg.severity_threshold,
        // We handle the ignoring of particular advisory ids ourselves
        ignore: Vec::new(),
        informational_warnings: vec![
            Informational::Notice,
            Informational::Unmaintained,
            //Informational::Other("*"),
        ],
    };

    let report = rustsec::Report::generate(&advisory_db, &lockfile, &settings);

    let make_diag = |pkg: &Package, advisory: &Metadata| -> diag::Pack {
        match krates.search_name(pkg.name.as_str()) {
            Ok(rng) => {
                for i in rng {
                    let krate = &krates.krates[i];
                    if pkg.version != krate.version {
                        continue;
                    }

                    let id = &advisory.id;

                    let (severity, message) = {
                        let (lint_level, msg) = match &advisory.informational {
                            // Everything that isn't an informational advisory is a vulnerability
                            None => (
                                cfg.vulnerability,
                                "security vulnerability detected".to_owned(),
                            ),
                            Some(info) => match info {
                                // Security notices for a crate which are published on https://rustsec.org
                                // but don't represent a vulnerability in a crate itself.
                                Informational::Notice => {
                                    (cfg.notice, "notice advisory detected".to_owned())
                                }
                                // Crate is unmaintained / abandoned
                                Informational::Unmaintained => (
                                    cfg.unmaintained,
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
                        let severity = if cfg.ignore.binary_search(id).is_ok() {
                            Severity::Note
                        } else {
                            match lint_level {
                                LintLevel::Warn => Severity::Warning,
                                LintLevel::Deny => Severity::Error,
                                LintLevel::Allow => Severity::Note,
                            }
                        };

                        (severity, msg)
                    };

                    let notes = {
                        let mut n = Vec::new();

                        n.push(advisory.description.clone());

                        if let Some(ref url) = advisory.url {
                            n.push(format!("URL: {}", url));
                        }

                        n
                    };

                    return diag::Pack {
                        krate_id: Some(krate.id.clone()),
                        diagnostics: vec![Diagnostic::new(
                            severity,
                            advisory.title.clone(),
                            Label::new(spans_id, krate_spans[i].clone(), message),
                        )
                        .with_code(id.as_str().to_owned())
                        .with_notes(notes)],
                    };
                }

                unreachable!(
                    "the advisory database report contained an advisory 
                    that somehow matched a crate we don't know about:\n{:#?}",
                    advisory
                );
            }
            Err(_) => {
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
}
