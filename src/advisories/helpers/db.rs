use crate::{utf8path, Krate, Krates, Path, PathBuf};
use anyhow::Context as _;
use log::{debug, info};
pub use rustsec::{advisory::Id, Database, Lockfile, Vulnerability};
use std::fmt;
use url::Url;

// The default, official, rustsec advisory database
const DEFAULT_URL: &str = "https://github.com/RustSec/advisory-db";

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    AllowWithGitCli,
    Disallow(time::Duration),
}

pub struct AdvisoryDb {
    /// Remote url of the database
    pub url: Url,
    /// The deserialized collection of advisories
    pub db: Database,
    /// The path to the backing repository
    pub path: PathBuf,
    /// The time of the last fetch of the db
    pub fetch_time: time::OffsetDateTime,
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
/// [`Database`]: https://docs.rs/rustsec/0.25.0/rustsec/database/struct.Database.html
#[derive(Debug)]
pub struct DbSet {
    pub dbs: Vec<AdvisoryDb>,
}

impl DbSet {
    pub fn load(
        root: Option<impl AsRef<Path>>,
        mut urls: Vec<Url>,
        fetch: Fetch,
    ) -> anyhow::Result<Self> {
        let root_db_path = match root {
            Some(root) => {
                let user_root = root.as_ref();
                if let Ok(user_root) = user_root.strip_prefix("~") {
                    if let Some(home) = home::home_dir() {
                        utf8path(home.join(user_root))?
                    } else {
                        log::warn!(
                            "unable to resolve path '{user_root}', falling back to the default advisory path"
                        );

                        // This would only succeed of CARGO_HOME was explicitly set
                        utf8path(
                            home::cargo_home()
                                .context("failed to resolve CARGO_HOME")?
                                .join("advisory-dbs"),
                        )?
                    }
                } else {
                    user_root.to_owned()
                }
            }
            None => utf8path(
                home::cargo_home()
                    .context("failed to resolve CARGO_HOME")?
                    .join("advisory-dbs"),
            )?,
        };

        if urls.is_empty() {
            info!("No advisory database configured, falling back to default '{DEFAULT_URL}'");
            urls.push(Url::parse(DEFAULT_URL).unwrap());
        }

        use rayon::prelude::*;
        let mut dbs = Vec::with_capacity(urls.len());
        urls.into_par_iter()
            .map(|url| load_db(url, root_db_path.clone(), fetch))
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
fn url_to_db_path(mut db_path: PathBuf, url: &Url) -> anyhow::Result<PathBuf> {
    let local_dir = tame_index::utils::url_to_local_dir(url.as_str())?;
    db_path.push(local_dir.dir_name);

    Ok(db_path)
}

fn load_db(url: Url, root_db_path: PathBuf, fetch: Fetch) -> anyhow::Result<AdvisoryDb> {
    let db_url = &url;
    let db_path = url_to_db_path(root_db_path, db_url)?;

    match fetch {
        Fetch::Allow => {
            debug!("Fetching advisory database from '{db_url}'");
            fetch_via_gix(db_url, &db_path)
                .with_context(|| format!("failed to fetch advisory database {db_url}"))?;
        }
        Fetch::AllowWithGitCli => {
            debug!("Fetching advisory database with git cli from '{db_url}'");

            fetch_via_cli(db_url.as_str(), &db_path)
                .with_context(|| format!("failed to fetch advisory database {db_url} with cli"))?;
        }
        Fetch::Disallow(_) => {
            debug!("Opening advisory database at '{db_path}'");
        }
    }

    // Verify that the repository is actually valid and that it is fresh
    let repo = gix::open(&db_path).context("failed to open advisory database")?;

    let fetch_time = get_fetch_time(&repo)?;

    // Ensure that the upstream repository hasn't gone stale, ie, they've
    // configured cargo-deny to not fetch the remote database(s), but they've
    // failed to update the database manually
    if let Fetch::Disallow(max_staleness) = fetch {
        anyhow::ensure!(
            fetch_time
                > time::OffsetDateTime::now_utc()
                    .checked_sub(max_staleness)
                    .context("unable to compute oldest allowable update timestamp")?,
            "repository is stale (last update: {fetch_time})"
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

const DIR: gix::remote::Direction = gix::remote::Direction::Fetch;

fn get_fetch_time(repo: &gix::Repository) -> anyhow::Result<time::OffsetDateTime> {
    let file_timestamp = |name: &str| -> anyhow::Result<time::OffsetDateTime> {
        let path = repo.path().join(name);
        let attr =
            std::fs::metadata(path).with_context(|| format!("failed to get '{name}' metadata"))?;
        Ok(attr
            .modified()
            .with_context(|| format!("failed to get '{name}' modification time"))?
            .into())
    };

    let commit_timestamp = || -> anyhow::Result<time::OffsetDateTime> {
        let commit = repo.head_commit().context("failed to get HEAD commit")?;
        let time = commit.time().context("failed to get HEAD commit time")?;

        // Copy what gix does, unfortunately it's not public
        // <https://github.com/Byron/gitoxide/blob/5af2cf368dcd05fe4dffbd675cffe6bafec127e7/gix-date/src/time/format.rs#L83C1-L87>

        let ts = time::OffsetDateTime::from_unix_timestamp(time.seconds)
            .context("unix timestamp for HEAD was out of range")?
            .to_offset(
                time::UtcOffset::from_whole_seconds(time.offset)
                    .context("timestamp offset for HEAD was out of range")?,
            );

        Ok(ts)
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
                    let file_head_ts =
                        file_timestamp("HEAD").unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
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

fn get_remote_head(
    repo: &gix::Repository,
    fetch_response: &gix::remote::fetch::Outcome,
) -> anyhow::Result<(gix::ObjectId, gix::bstr::BString)> {
    let remote = repo
        .head()
        .context("failed to get HEAD")?
        .into_remote(DIR)
        .map(|r| r.context("failed to get remote for HEAD"))
        .or_else(|| {
            repo.find_default_remote(DIR)
                .map(|r| r.context("failed to find default remote"))
        })
        .context("failed to find appropriate remote to fetch from")??;

    let remote_head = format!(
        "refs/remotes/{}/HEAD",
        remote
            .name()
            .map(|s| s.as_bstr())
            .context("remote name hasn't been persisted to disk")?
    );

    // Find the commit id of the remote's HEAD
    let (remote_head_id, remote_ref_target) = fetch_response
        .ref_map
        .mappings
        .iter()
        .find_map(|mapping| {
            let gix::remote::fetch::Source::Ref(rref) = &mapping.remote else { return None; };

            if mapping.local.as_deref()? != remote_head.as_bytes() {
                return None;
            }

            let gix::protocol::handshake::Ref::Symbolic {
            full_ref_name,
            object,
            target,
        } = rref else { return None; };

            (full_ref_name == "HEAD").then(|| (*object, target.clone()))
        })
        .context("failed to locate remote HEAD")?;

    Ok((remote_head_id, remote_ref_target))
}

/// Perform a fetch + checkout of the latest remote HEAD -> local HEAD
///
/// Note this function is a bit involved as, either I'm dumb and can't figure out
/// how to do it, or else gix has support for updating HEAD and checking it out
/// when doing a clone, but if you are performing a fetch on an existing repo
/// ...you have to do that all yourself, which is pretty tedious
fn fetch_and_checkout(repo: &mut gix::Repository) -> anyhow::Result<()> {
    // In a normal case there will be only one remote, called origin, but try
    // and be robust about it
    let mut remote = repo
        .head()
        .context("failed to get HEAD")?
        .into_remote(DIR)
        .map(|r| r.context("failed to get remote for HEAD"))
        .or_else(|| {
            repo.find_default_remote(DIR)
                .map(|r| r.context("failed to find default remote"))
        })
        .context("failed to find appropriate remote to fetch from")??;

    let remote_head = format!(
        "refs/remotes/{}/HEAD",
        remote
            .name()
            .map(|s| s.as_bstr())
            .context("remote name hasn't been persisted to disk")?
    );

    remote
        .replace_refspecs(Some(format!("HEAD:{remote_head}").as_str()), DIR)
        .expect("valid statically known refspec");

    // Perform the actual fetch
    let fetch_response: gix::remote::fetch::Outcome = remote
        .connect(DIR)?
        .prepare_fetch(&mut gix::progress::Discard, Default::default())
        .context("failed to prepare fetch")?
        .receive(
            &mut gix::progress::Discard,
            &std::sync::atomic::AtomicBool::default(),
        )
        .context("failed to fetch")?;

    use gix::refs::{transaction as tx, Target};
    let (remote_head_id, _remote_ref_target) = get_remote_head(repo, &fetch_response)?;

    // In all (hopefully?) cases HEAD is a symbolic reference to
    // refs/heads/<branch> which is a peeled commit id, if that's the case
    // we update it to the new commit id, otherwise we just set HEAD
    // directly
    use gix::head::Kind;
    let edit = match repo.head()?.kind {
        Kind::Symbolic(sref) => {
            // Update our local HEAD to the remote HEAD
            if let Target::Symbolic(name) = sref.target {
                Some(tx::RefEdit {
                    change: tx::Change::Update {
                        log: tx::LogChange {
                            mode: tx::RefLog::AndReference,
                            force_create_reflog: false,
                            message: "".into(),
                        },
                        expected: tx::PreviousValue::MustExist,
                        new: gix::refs::Target::Peeled(remote_head_id),
                    },
                    name,
                    deref: true,
                })
            } else {
                None
            }
        }
        Kind::Unborn(_) | Kind::Detached { .. } => None,
    };

    let edit = edit.unwrap_or_else(|| tx::RefEdit {
        change: tx::Change::Update {
            log: tx::LogChange {
                mode: tx::RefLog::AndReference,
                force_create_reflog: false,
                message: "".into(),
            },
            expected: tx::PreviousValue::Any,
            new: gix::refs::Target::Peeled(remote_head_id),
        },
        name: "HEAD".try_into().unwrap(),
        deref: true,
    });

    // We're updating the reflog which requires a committer be set, which might
    // not be the case, particular in a CI environment, but also would default
    // the the git config for the current directory/global, which on a normal
    // user machine would show the user was the one who updated the database which
    // is kind of misleading, so we just override the config for this operation
    let repo = {
        let mut config = repo.config_snapshot_mut();
        config
            .set_raw_value("committer", None, "name", "cargo-deny")
            .context("failed to set committer.name")?;
        // Note we _have_ to set the email as well, but luckily gix does not actually
        // validate if it's a proper email or not :)
        config
            .set_raw_value("committer", None, "email", "")
            .context("failed to set committer.email")?;

        config
            .commit_auto_rollback()
            .context("failed to create auto rollback")?
    };

    repo.edit_reference(edit).context("failed to update HEAD")?;

    // Sanity check that the local HEAD points to the same commit
    // as the remote HEAD
    anyhow::ensure!(
        remote_head_id == repo.head_commit()?.id,
        "failed to update HEAD to remote HEAD"
    );

    use gix::prelude::FindExt;

    // Now that we've updated HEAD, do the actual checkout
    let workdir = repo
        .work_dir()
        .context("unable to checkout, repository is bare")?;
    let root_tree = repo
        .head()?
        .peel_to_id_in_place()
        .transpose()?
        .context("unable to peel HEAD")?
        .object()
        .context("HEAD commit not downloaded from remote")?
        .peel_to_tree()
        .context("unable to peel HEAD to tree")?
        .id;

    let index = gix::index::State::from_tree(&root_tree, |oid, buf| {
        repo.objects.find_tree_iter(oid, buf).ok()
    })
    .with_context(|| format!("failed to create index from tree '{root_tree}'"))?;
    let mut index = gix::index::File::from_state(index, repo.index_path());

    let opts = gix::worktree::checkout::Options {
        destination_is_initially_empty: false,
        overwrite_existing: true,
        ..Default::default()
    };

    gix::worktree::checkout(
        &mut index,
        workdir,
        {
            let objects = repo.objects.clone().into_arc()?;
            move |oid, buf| objects.find_blob(oid, buf)
        },
        &mut gix::progress::Discard,
        &mut gix::progress::Discard,
        &std::sync::atomic::AtomicBool::default(),
        opts,
    )
    .context("failed to checkout")?;

    index
        .write(Default::default())
        .context("failed to write index")?;

    // Now that we've checked out everything write FETCH_HEAD
    write_fetch_head(&repo, &fetch_response)?;

    Ok(())
}

/// The format of `FETCH_HEAD` is a bit different from other refs, and
/// we don't write it the same as git does, as it includes the tips
/// of _all_ active remote branches, and we don't care about anything
/// except the branch with HEAD
///
/// `<commit_oid>\t\tbranch '<name>' of '<remote>'`
fn write_fetch_head(
    repo: &gix::Repository,
    fetch: &gix::remote::fetch::Outcome,
) -> anyhow::Result<()> {
    let fetch_head_path = repo.path().join("FETCH_HEAD");

    let (remote_head_id, remote_ref_target) = get_remote_head(repo, fetch)?;

    let remote_head = remote_head_id.to_hex();
    // At least for the official rustsec repo, the default branch is 'main', so
    // we default to that if the target is invalid utf8 or empty
    let remote_ref_target = String::try_from(remote_ref_target).ok();
    let remote_branch_name = remote_ref_target
        .as_deref()
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("main");

    let remote = repo
        .head()
        .context("failed to get HEAD")?
        .into_remote(DIR)
        .map(|r| r.context("failed to get remote for HEAD"))
        .or_else(|| {
            repo.find_default_remote(DIR)
                .map(|r| r.context("failed to find default remote"))
        })
        .context("failed to find appropriate remote to fetch from")??;

    // This _should_ be impossible if we got here...
    let remote_url: String = remote
        .url(DIR)
        .context("fetch url is not available for remote")?
        .to_bstring()
        .try_into()
        .context("remote url is not valid utf-8")?;

    std::fs::write(
        &fetch_head_path,
        format!("{remote_head}\t\tbranch '{remote_branch_name}' of {remote_url}"),
    )
    .with_context(|| format!("failed to write {fetch_head_path:?}"))?;

    Ok(())
}

fn fetch_via_gix(url: &Url, db_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        url.scheme() == "https" || url.scheme() == "ssh",
        "expected '{}' to be an `https` or `ssh` url",
        url
    );

    // Ensure the parent directory chain is created, git2 won't do it for us
    {
        let parent = db_path
            .parent()
            .with_context(|| format!("invalid directory: {db_path}"))?;

        if !parent.is_dir() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Avoid errors in the case the directory exists but is otherwise empty.
    // See: https://github.com/RustSec/cargo-audit/issues/32
    // (not sure if this is needed with gix)
    if db_path.is_dir() && std::fs::read_dir(db_path)?.next().is_none() {
        std::fs::remove_dir(db_path)?;
    }

    let (mut repo, cloned) = gix::open(db_path)
        .map(|repo| (repo, false))
        .or_else(|err| {
            if matches!(err, gix::open::Error::NotARepository { .. }) {
                let (mut checkout, out) = gix::prepare_clone(url.as_str(), db_path)
                    .context("failed to prepare clone")?
                    .fetch_then_checkout(
                        gix::progress::Discard,
                        &std::sync::atomic::AtomicBool::default(),
                    )
                    .context("failed to fetch")?;

                let repo = checkout
                    .main_worktree(
                        gix::progress::Discard,
                        &std::sync::atomic::AtomicBool::default(),
                    )
                    .context("failed to checkout")?
                    .0;

                write_fetch_head(&repo, &out)?;

                Ok((repo, true))
            } else {
                Err(err).context("unable to open repository")
            }
        })
        .with_context(|| format!("failed to open git repository at '{db_path}'"))?;

    // If we didn't open a fresh repo we need to peform a fetch ourselves, and
    // do the work of updating the HEAD to point at the latest remote HEAD, which
    // gix doesn't currently do.
    //
    // Gix also doesn't write the FETCH_HEAD, which we rely on for staleness
    // checking, so we write it ourselves to keep identical logic between gix
    // and git/git2
    if !cloned {
        fetch_and_checkout(&mut repo)?;
    }

    Ok(())
}

fn fetch_via_cli(url: &str, db_path: &Path) -> anyhow::Result<()> {
    use std::{fs, process::Command};

    if let Some(parent) = db_path.parent() {
        if !parent.is_dir() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create advisory database directory {parent}")
            })?;
        }
    } else {
        anyhow::bail!("invalid directory: {db_path}");
    }

    let capture = |mut cmd: Command| -> anyhow::Result<String> {
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
    };

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

pub use rustsec::{Warning, WarningKind};

pub struct Report<'db, 'k> {
    pub advisories: Vec<(&'k Krate, krates::NodeId, &'db rustsec::Advisory)>,
    /// For backwards compatiblity with cargo-audit, we optionally serialize the
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
                        .map_or(true, |c| c == rustsec::Collection::Crates)
                })
                .flat_map(|advisory| {
                    krates
                        .krates_by_name(advisory.metadata.package.as_str())
                        .par_bridge()
                        .filter_map(move |(nid, krate)| {
                            let ksrc = krate.source.as_ref()?;

                            // Validate the crate's source is the same as the advisory
                            if !ksrc.matches_rustsec(advisory.metadata.source.as_ref()) {
                                return None;
                            }

                            // Ensure the crate's version is actually affected
                            if !advisory.versions.is_vulnerable(&krate.version) {
                                return None;
                            }

                            Some((krate, nid, advisory))
                        })
                })
                .collect();

            if let Some(lockfile) = fake_lockfile.clone() {
                let mut warnings = std::collections::BTreeMap::<_, Vec<rustsec::Warning>>::new();
                let mut vulns = Vec::new();

                for (krate, _nid, advisory) in &db_advisories {
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
                        target_arch: None,
                        target_os: None,
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

        Self {
            advisories,
            serialized_reports,
        }
    }
}

#[cfg(test)]
mod test {
    use super::url_to_db_path;
    use url::Url;

    #[test]
    fn converts_url_to_path() {
        let root_path = crate::utf8path(std::env::current_dir().unwrap()).unwrap();

        {
            let url = Url::parse("https://github.com/RustSec/advisory-db").unwrap();
            assert_eq!(
                url_to_db_path(root_path.clone(), &url).unwrap(),
                root_path.join("github.com-a946fc29ac602819")
            );
        }

        {
            let url = Url::parse("https://bare.com").unwrap();
            assert_eq!(
                url_to_db_path(root_path.clone(), &url).unwrap(),
                root_path.join("bare.com-9c003d1ed306b28c")
            );
        }

        {
            let url = Url::parse("https://example.com/countries/việt nam").unwrap();
            assert_eq!(
                url_to_db_path(root_path.clone(), &url).unwrap(),
                root_path.join("example.com-1c03f84825fb7438")
            );
        }
    }
}
