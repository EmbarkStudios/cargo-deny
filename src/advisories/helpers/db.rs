use crate::{utf8path, Krate, Krates, Path, PathBuf};
use anyhow::Context as _;
use log::{debug, info};
pub use rustsec::{advisory::Id, Database, Lockfile, Vulnerability};
use url::Url;

// The default, official, rustsec advisory database
const DEFAULT_URL: &str = "https://github.com/RustSec/advisory-db";

/// Whether the database will be fetched or not
#[derive(Copy, Clone)]
pub enum Fetch {
    Allow,
    AllowWithGitCli,
    Disallow,
}

/// A collection of [`Database`]s that is used to query advisories
/// in many different databases.
///
/// [`Database`]: https://docs.rs/rustsec/0.25.0/rustsec/database/struct.Database.html
pub struct DbSet {
    dbs: Vec<(Url, Database)>,
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
            .map(|url| load_db(&url, root_db_path.clone(), fetch).map(|db| (url, db)))
            .collect_into_vec(&mut dbs);

        Ok(Self {
            dbs: dbs.into_iter().collect::<Result<Vec<_>, _>>()?,
        })
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &(Url, Database)> {
        self.dbs.iter()
    }

    #[inline]
    pub fn has_advisory(&self, id: &Id) -> bool {
        self.dbs.iter().any(|db| db.1.get(id).is_some())
    }
}

/// Convert an advisory url to a directory underneath a specified root
fn url_to_db_path(mut db_path: PathBuf, url: &Url) -> anyhow::Result<PathBuf> {
    let (ident, _) = super::url_to_local_dir(url.as_str())?;
    db_path.push(ident);

    Ok(db_path)
}

fn load_db(db_url: &Url, root_db_path: PathBuf, fetch: Fetch) -> anyhow::Result<Database> {
    let db_path = url_to_db_path(root_db_path, db_url)?;

    match fetch {
        Fetch::Allow => {
            debug!("Fetching advisory database from '{db_url}'");
            fetch_via_git(db_url, &db_path)
                .with_context(|| format!("failed to fetch advisory database {db_url}"))?;
        }
        Fetch::AllowWithGitCli => {
            debug!("Fetching advisory database with git cli from '{db_url}'");

            fetch_via_cli(db_url.as_str(), &db_path)
                .with_context(|| format!("failed to fetch advisory database {db_url} with cli"))?;
        }
        Fetch::Disallow => {
            debug!("Opening advisory database at '{db_path}'");
        }
    }

    // Verify that the repository is actually valid
    git2::Repository::open(&db_path).context("failed to open advisory database")?;

    debug!("loading advisory database from {db_path}");

    let res = Database::open(db_path.as_std_path()).context("failed to load advisory database");

    debug!("finished loading advisory database from {db_path}");

    res
}

fn fetch_via_git(url: &Url, db_path: &Path) -> anyhow::Result<()> {
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

    // Avoid libgit2 errors in the case the directory exists but is
    // otherwise empty.
    //
    // See: https://github.com/RustSec/cargo-audit/issues/32
    if db_path.is_dir() && std::fs::read_dir(db_path)?.next().is_none() {
        std::fs::remove_dir(db_path)?;
    }

    /// Ref for the `main` branch in the local repository
    const LOCAL_REF: &str = "refs/heads/main";

    /// Ref for the `main` branch in the remote repository
    const REMOTE_REF: &str = "refs/remotes/origin/main";

    let git_config = git2::Config::new()?;

    with_authentication(url.as_str(), &git_config, |f| {
        let mut callbacks = git2::RemoteCallbacks::new();
        callbacks.credentials(f);

        let mut proxy_opts = git2::ProxyOptions::new();
        proxy_opts.auto();

        let mut fetch_opts = git2::FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);
        fetch_opts.proxy_options(proxy_opts);

        if db_path.exists() {
            let repo = git2::Repository::open(db_path)?;
            let refspec = format!("{LOCAL_REF}:{REMOTE_REF}");

            // Fetch remote packfiles and update tips
            let mut remote = repo.remote_anonymous(url.as_str())?;
            remote.fetch(&[refspec.as_str()], Some(&mut fetch_opts), None)?;

            // Get the current remote tip (as an updated local reference)
            let remote_main_ref = repo.find_reference(REMOTE_REF)?;
            let remote_target = remote_main_ref.target().unwrap();

            // Set the local main ref to match the remote
            match repo.find_reference(LOCAL_REF) {
                Ok(mut local_main_ref) => {
                    local_main_ref.set_target(
                        remote_target,
                        &format!("moving `main` to {REMOTE_REF}: {remote_target}"),
                    )?;
                }
                Err(e) if e.code() == git2::ErrorCode::NotFound => {
                    anyhow::bail!("unable to find reference '{LOCAL_REF}'");
                }
                Err(e) => {
                    return Err(e.into());
                }
            };
        } else {
            git2::build::RepoBuilder::new()
                .fetch_options(fetch_opts)
                .clone(url.as_str(), db_path.as_std_path())?;
        }

        Ok(())
    })?;

    let repo = git2::Repository::open(db_path).context("failed to open repository")?;

    // Retrieve the HEAD commit
    let head = repo.head()?;

    let oid = head
        .target()
        .with_context(|| format!("no ref target for '{db_path}'"))?;

    let commit_object = repo.find_object(oid, Some(git2::ObjectType::Commit))?;
    let commit = commit_object
        .as_commit()
        .context("HEAD OID was not a reference to a commit")?;

    // Reset the state of the repository to the latest commit
    repo.reset(&commit_object, git2::ResetType::Hard, None)?;

    let timestamp = time::OffsetDateTime::from_unix_timestamp(commit.time().seconds())
        .context("commit timestamp is invalid")?;

    // 90 days
    const MINIMUM_FRESHNESS: time::Duration = time::Duration::seconds(90 * 24 * 60 * 60);

    // Ensure that the upstream repository hasn't gone stale, ie, they've
    // configured cargo-deny to not fetch the remote database(s), but they've
    // failed to update the databases manuallly
    anyhow::ensure!(
        timestamp
            > time::OffsetDateTime::now_utc()
                .checked_sub(MINIMUM_FRESHNESS)
                .expect("this should never happen"),
        "repository is stale (last commit: {})",
        timestamp
    );

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

    if db_path.exists() {
        // make sure db_path is clean
        let mut cmd = Command::new("git");
        cmd.arg("reset").arg("--hard").current_dir(db_path);

        // We don't fail if we can't reset since it _may_ still be possible to
        // clone
        match capture(cmd) {
            Ok(_reset) => log::debug!("reset {url}"),
            Err(err) => log::error!("failed to reset {url}: {err}"),
        }

        // pull latest changes
        let mut cmd = Command::new("git");
        cmd.arg("pull").current_dir(db_path);

        capture(cmd).context("failed to pull latest changes")?;
        log::debug!("pulled {url}");
    } else {
        // clone repository
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg(url).arg(db_path);

        capture(cmd).context("failed to clone")?;
        log::debug!("cloned {url}");
    }

    Ok(())
}

/// Prepare the authentication callbacks for cloning a git repository.
///
/// The main purpose of this function is to construct the "authentication
/// callback" which is used to clone a repository. This callback will attempt to
/// find the right authentication on the system (without user input) and will
/// guide libgit2 in doing so.
///
/// The callback is provided `allowed` types of credentials, and we try to do as
/// much as possible based on that:
///
/// * Prioritize SSH keys from the local ssh agent as they're likely the most
///   reliable. The username here is prioritized from the credential
///   callback, then from whatever is configured in git itself, and finally
///   we fall back to the generic user of `git`.
///
/// * If a username/password is allowed, then we fallback to git2-rs's
///   implementation of the credential helper. This is what is configured
///   with `credential.helper` in git, and is the interface for the macOS
///   keychain, for example.
///
/// * After the above two have failed, we just kinda grapple attempting to
///   return *something*.
///
/// If any form of authentication fails, libgit2 will repeatedly ask us for
/// credentials until we give it a reason to not do so. To ensure we don't
/// just sit here looping forever we keep track of authentications we've
/// attempted and we don't try the same ones again.
pub fn with_authentication<T, F>(url: &str, cfg: &git2::Config, mut f: F) -> anyhow::Result<T>
where
    F: FnMut(&mut git2::Credentials<'_>) -> anyhow::Result<T>,
{
    let mut cred_helper = git2::CredentialHelper::new(url);
    cred_helper.config(cfg);

    let mut ssh_username_requested = false;
    let mut cred_helper_bad = None;
    let mut ssh_agent_attempts = Vec::new();
    let mut any_attempts = false;
    let mut tried_sshkey = false;

    let mut res = f(&mut |url, username, allowed| {
        any_attempts = true;
        // libgit2's "USERNAME" authentication actually means that it's just
        // asking us for a username to keep going. This is currently only really
        // used for SSH authentication and isn't really an authentication type.
        // The logic currently looks like:
        //
        //      let user = ...;
        //      if (user.is_null())
        //          user = callback(USERNAME, null, ...);
        //
        //      callback(SSH_KEY, user, ...)
        //
        // So if we're being called here then we know that (a) we're using ssh
        // authentication and (b) no username was specified in the URL that
        // we're trying to clone. We need to guess an appropriate username here,
        // but that may involve a few attempts. Unfortunately we can't switch
        // usernames during one authentication session with libgit2, so to
        // handle this we bail out of this authentication session after setting
        // the flag `ssh_username_requested`, and then we handle this below.
        if allowed.contains(git2::CredentialType::USERNAME) {
            debug_assert!(username.is_none());
            ssh_username_requested = true;
            return Err(git2::Error::from_str("gonna try usernames later"));
        }

        // An "SSH_KEY" authentication indicates that we need some sort of SSH
        // authentication. This can currently either come from the ssh-agent
        // process or from a raw in-memory SSH key. Cargo only supports using
        // ssh-agent currently.
        //
        // If we get called with this then the only way that should be possible
        // is if a username is specified in the URL itself (e.g., `username` is
        // Some), hence the unwrap() here. We try custom usernames down below.
        if allowed.contains(git2::CredentialType::SSH_KEY) && !tried_sshkey {
            // If ssh-agent authentication fails, libgit2 will keep
            // calling this callback asking for other authentication
            // methods to try. Make sure we only try ssh-agent once,
            // to avoid looping forever.
            tried_sshkey = true;
            let username = username.unwrap();
            debug_assert!(!ssh_username_requested);
            ssh_agent_attempts.push(username.to_string());
            return git2::Cred::ssh_key_from_agent(username);
        }

        // Sometimes libgit2 will ask for a username/password in plaintext. This
        // is where Cargo would have an interactive prompt if we supported it,
        // but we currently don't! Right now the only way we support fetching a
        // plaintext password is through the `credential.helper` support, so
        // fetch that here.
        //
        // If ssh-agent authentication fails, libgit2 will keep calling this
        // callback asking for other authentication methods to try. Check
        // cred_helper_bad to make sure we only try the git credential helper
        // once, to avoid looping forever.
        if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) && cred_helper_bad.is_none()
        {
            let r = git2::Cred::credential_helper(cfg, url, username);
            cred_helper_bad = Some(r.is_err());
            return r;
        }

        // I'm... not sure what the DEFAULT kind of authentication is, but seems
        // easy to support?
        if allowed.contains(git2::CredentialType::DEFAULT) {
            return git2::Cred::default();
        }

        // Whelp, we tried our best
        Err(git2::Error::from_str("no authentication available"))
    });

    // Ok, so if it looks like we're going to be doing ssh authentication, we
    // want to try a few different usernames as one wasn't specified in the URL
    // for us to use. In order, we'll try:
    //
    // * A credential helper's username for this URL, if available.
    // * This account's username.
    // * "git"
    //
    // We have to restart the authentication session each time (due to
    // constraints in libssh2 I guess? maybe this is inherent to ssh?), so we
    // call our callback, `f`, in a loop here.
    if ssh_username_requested {
        debug_assert!(res.is_err());
        let mut attempts = vec!["git".to_owned()];
        if let Ok(s) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
            attempts.push(s);
        }
        if let Some(s) = &cred_helper.username {
            attempts.push(s.clone());
        }

        while let Some(s) = attempts.pop() {
            // We should get `USERNAME` first, where we just return our attempt,
            // and then after that we should get `SSH_KEY`. If the first attempt
            // fails we'll get called again, but we don't have another option so
            // we bail out.
            let mut attempts = 0;
            res = f(&mut |_url, username, allowed| {
                if allowed.contains(git2::CredentialType::USERNAME) {
                    return git2::Cred::username(&s);
                }
                if allowed.contains(git2::CredentialType::SSH_KEY) {
                    debug_assert_eq!(Some(&s[..]), username);
                    attempts += 1;
                    if attempts == 1 {
                        ssh_agent_attempts.push(s.clone());
                        return git2::Cred::ssh_key_from_agent(&s);
                    }
                }
                Err(git2::Error::from_str("no authentication available"))
            });

            // If we made two attempts then that means:
            //
            // 1. A username was requested, we returned `s`.
            // 2. An ssh key was requested, we returned to look up `s` in the
            //    ssh agent.
            // 3. For whatever reason that lookup failed, so we were asked again
            //    for another mode of authentication.
            //
            // Essentially, if `attempts == 2` then in theory the only error was
            // that this username failed to authenticate (e.g., no other network
            // errors happened). Otherwise something else is funny so we bail
            // out.
            if attempts != 2 {
                break;
            }
        }
    }

    if res.is_ok() || !any_attempts {
        return res.map_err(From::from);
    }

    // In the case of an authentication failure (where we tried something) then
    // we try to give a more helpful error message about precisely what we
    // tried.
    let res = res.map_err(|_e| {
        let mut msg = "failed to authenticate when downloading repository".to_owned();
        if !ssh_agent_attempts.is_empty() {
            let names = ssh_agent_attempts
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ");

            use std::fmt::Write;
            let _ = write!(
                &mut msg,
                "\nattempted ssh-agent authentication, but none of the usernames {names} succeeded",
            );
        }
        if let Some(failed_cred_helper) = cred_helper_bad {
            if failed_cred_helper {
                msg.push_str(
                    "\nattempted to find username/password via \
                     git's `credential.helper` support, but failed",
                );
            } else {
                msg.push_str(
                    "\nattempted to find username/password via \
                     `credential.helper`, but maybe the found \
                     credentials were incorrect",
                );
            }
        }

        anyhow::anyhow!(msg)
    })?;

    Ok(res)
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

        for (url, db) in advisory_dbs.iter() {
            // Ugh, db exposes advisories as a slice iter which rayon doesn't have an impl for :(
            let mut db_advisories: Vec<_> = db
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
                        log::error!("Failed to serialize report for database '{url}': {err}");
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
                root_path.join("github.com-2f857891b7f43c59")
            );
        }

        {
            let url = Url::parse("https://github.com/RustSec/advisory-db").unwrap();
            assert_eq!(
                url_to_db_path(root_path.clone(), &url).unwrap(),
                root_path.join("github.com-2f857891b7f43c59")
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
