//! Functionality for cloning, fetching and getting timestamps via `git`
//!
//! We explicitly use `git` since it's almost certainly available on the machine running cargo-deny, and the usage isn't
//! enough to warrant pulling in a library dependency
//!
//! - `git2`
//!   - C/unsafe/etc
//!   - large
//!   - slow compile time
//! - `gix`
//!   - extremely frequent version bumps
//!   - very large with many sub-crates, many dependencies, often brings in multiple versions
//!   - slow compile time

use crate::Path;
use anyhow::Context;
use std::{fs, process::Command};

/// Runs a git command, capturing its output
pub fn capture(mut cmd: Command) -> anyhow::Result<String> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = cmd
        // We need to clear the environment to avoid things like pre-commit hooks influencing where the advisory db
        // is located https://git-scm.com/book/en/v2/Git-Internals-Environment-Variables
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .spawn()
        .context("failed to spawn git")?
        .wait_with_output()
        .context("failed to wait on git output")?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .or_else(|_err| Ok("git command succeeded but gave non-utf8 output".to_owned()))
    } else {
        let args: Vec<_> = cmd.get_args().collect();
        match String::from_utf8(output.stderr) {
            Ok(err) => {
                anyhow::bail!("{args:?}\n{err}");
            }
            Err(_err) => {
                anyhow::bail!("{args:?}\ngit command failed and gave non-utf8 output");
            }
        }
    }
}

/// Attempts to determine the timestamp of the last fetch (`FETCH_HEAD`)
///
/// If unavailable, attempts to fallback to the timestamp of `HEAD`
pub fn get_fetch_time(repo: &Path) -> anyhow::Result<jiff::Timestamp> {
    let path = repo.join(".git");
    let file_timestamp = |name: &str| -> anyhow::Result<jiff::Timestamp> {
        let path = path.join(name);
        let attr =
            fs::metadata(path).with_context(|| format!("failed to get '{name}' metadata"))?;
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

pub enum FetchResult {
    /// The repo was fetched
    Fetched,
    /// The repo was cloned
    Cloned,
}

impl std::fmt::Display for FetchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetched => f.write_str("fetched"),
            Self::Cloned => f.write_str("cloned"),
        }
    }
}

/// Attempts to clone or fetch a remote repo into the specified path
pub fn fetch_repo(url: &str, repo_path: &Path, branch: &str) -> anyhow::Result<FetchResult> {
    if let Some(parent) = repo_path.parent() {
        if !parent.is_dir() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create advisory database directory {parent}")
            })?;
        }
    } else {
        anyhow::bail!("invalid directory: {repo_path}");
    }

    let run = |args: &[&str]| {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(repo_path);
        cmd.args(args);

        capture(cmd)
    };

    if repo_path.exists() {
        // make sure the path is clean
        // We don't fail if we can't reset since it _may_ still be possible to
        // clone
        match run(&["reset", "--hard"]) {
            Ok(_reset) => log::debug!("reset {url}"),
            Err(err) => log::error!("failed to reset {url}: {err}"),
        }

        let rspec = format!("+{branch}:{branch}");

        // pull latest changes
        run(&["fetch", "--depth=1", "-u", "origin", &rspec])
            .context("failed to fetch latest changes")?;

        // reset to the remote HEAD
        run(&["reset", "--hard", "FETCH_HEAD"]).context("failed to reset to FETCH_HEAD")?;

        Ok(FetchResult::Fetched)
    } else {
        let mut cmd = Command::new("git");
        cmd.args(["clone", "--depth=1", "--branch", branch])
            .arg(url)
            .arg(repo_path);

        capture(cmd).context("failed to clone")?;

        Ok(FetchResult::Cloned)
    }
}
