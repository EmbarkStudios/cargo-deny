use crate::{Krate, Krates};
use anyhow::{Context, Error};
use log::{debug, info};
pub use rustsec::{advisory::Id, Database, Lockfile, Vulnerability};
use std::path::{Path, PathBuf};
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
    ) -> Result<Self, Error> {
        let root_db_path = match root {
            Some(root) => {
                let user_root = root.as_ref();
                if user_root.starts_with("~") {
                    if let Some(home) = home::home_dir() {
                        home.join(user_root.strip_prefix("~").unwrap())
                    } else {
                        log::warn!(
                            "unable to resolve path '{}', falling back to the default advisory path",
                            user_root.display()
                        );

                        // This would only succeed of CARGO_HOME was explicitly set
                        home::cargo_home()
                            .context("failed to resolve CARGO_HOME")?
                            .join("advisory-dbs")
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
                DEFAULT_URL
            );
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

    pub fn iter(&self) -> impl Iterator<Item = &(Url, Database)> {
        self.dbs.iter()
    }

    pub fn has_advisory(&self, id: &Id) -> bool {
        self.dbs.iter().any(|db| db.1.get(id).is_some())
    }
}

/// Converts a full url, eg <https://github.com/rust-lang/crates.io-index>, into
/// the root directory name where cargo itself will fetch it on disk
pub(crate) fn url_to_local_dir(url: &str) -> Result<(String, String), Error> {
    fn to_hex(num: u64) -> String {
        const CHARS: &[u8] = b"0123456789abcdef";

        // Note that cargo does this as well so that the hex strings are
        // the same on big endian as well
        let bytes = num.to_le_bytes();

        let mut output = String::with_capacity(16);

        for byte in bytes {
            output.push(CHARS[(byte >> 4) as usize] as char);
            output.push(CHARS[(byte & 0xf) as usize] as char);
        }

        output
    }

    #[allow(deprecated)]
    fn hash_u64(url: &str) -> u64 {
        use std::hash::{Hash, Hasher, SipHasher};

        let mut hasher = SipHasher::new_with_keys(0, 0);
        // Registry. Note the explicit use of u64 here so that we get the same
        // hash on 32 and 64-bit arches
        2u64.hash(&mut hasher);
        // Url
        url.hash(&mut hasher);
        hasher.finish()
    }

    // Ensure we have a registry or bare url
    let (url, scheme_ind) = {
        let scheme_ind = url
            .find("://")
            .with_context(|| format!("'{}' is not a valid url", url))?;

        let scheme_str = &url[..scheme_ind];
        if let Some(ind) = scheme_str.find('+') {
            if &scheme_str[..ind] != "registry" {
                anyhow::bail!("'{}' is not a valid registry url", url);
            }

            (&url[ind + 1..], scheme_ind - ind - 1)
        } else {
            (url, scheme_ind)
        }
    };

    // Could use the Url crate for this, but it's simple enough and we don't
    // need to deal with every possible url (I hope...)
    let host = match url[scheme_ind + 3..].find('/') {
        Some(end) => &url[scheme_ind + 3..scheme_ind + 3 + end],
        None => &url[scheme_ind + 3..],
    };

    // cargo special cases github.com for reasons, so do the same
    let mut canonical = if host == "github.com" {
        url.to_lowercase()
    } else {
        url.to_owned()
    };

    // Chop off any query params/fragments
    if let Some(hash) = canonical.rfind('#') {
        canonical.truncate(hash);
    }

    if let Some(query) = canonical.rfind('?') {
        canonical.truncate(query);
    }

    let ident = to_hex(hash_u64(&canonical));

    if canonical.ends_with('/') {
        canonical.pop();
    }

    if canonical.ends_with(".git") {
        canonical.truncate(canonical.len() - 4);
    }

    Ok((format!("{}-{}", host, ident), canonical))
}

/// Convert an advisory url to a directory underneath a specified root
fn url_to_path(mut db_path: PathBuf, url: &Url) -> Result<PathBuf, Error> {
    let (ident, _) = url_to_local_dir(url.as_str())?;
    db_path.push(ident);

    Ok(db_path)
}

fn load_db(db_url: &Url, root_db_path: PathBuf, fetch: Fetch) -> Result<Database, Error> {
    let db_path = url_to_path(root_db_path, db_url)?;

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
            debug!("Opening advisory database at '{}'", db_path.display());
        }
    }

    // Verify that the repository is actually valid
    git2::Repository::open(&db_path).context("failed to open advisory database")?;

    debug!("loading advisory database from {}", db_path.display());

    let res = Database::open(&db_path).context("failed to load advisory database");

    debug!(
        "finished loading advisory database from {}",
        db_path.display()
    );

    res
}

fn fetch_via_git(url: &Url, db_path: &Path) -> Result<(), Error> {
    anyhow::ensure!(
        url.scheme() == "https" || url.scheme() == "ssh",
        "expected '{}' to be an `https` or `ssh` url",
        url
    );

    // Ensure the parent directory chain is created, git2 won't do it for us
    {
        let parent = db_path
            .parent()
            .with_context(|| format!("invalid directory: {}", db_path.display()))?;

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
                .clone(url.as_str(), db_path)?;
        }

        Ok(())
    })?;

    let repo = git2::Repository::open(db_path).context("failed to open repository")?;

    // Retrieve the HEAD commit
    let head = repo.head()?;

    let oid = head
        .target()
        .with_context(|| format!("no ref target for '{}'", db_path.display()))?;

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

fn fetch_via_cli(url: &str, db_path: &Path) -> Result<(), Error> {
    use std::{fs, process::Command};

    if let Some(parent) = db_path.parent() {
        if !parent.is_dir() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create advisory database directory {}",
                    parent.display()
                )
            })?;
        }
    } else {
        anyhow::bail!("invalid directory: {}", db_path.display());
    }

    fn capture(mut cmd: Command) -> Result<String, Error> {
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
pub fn with_authentication<T, F>(url: &str, cfg: &git2::Config, mut f: F) -> Result<T, Error>
where
    F: FnMut(&mut git2::Credentials<'_>) -> Result<T, Error>,
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

pub fn load_lockfile(path: &krates::Utf8Path) -> Result<Lockfile, Error> {
    let mut lockfile = Lockfile::load(path)?;

    // Remove the metadata as it is irrelevant
    lockfile.metadata = Default::default();

    Ok(lockfile)
}

/// A wrapper around a rustsec `Lockfile`, this is used to filter out all of
/// the crates that are not part of the crate graph for some reason, eg. a target
/// specific dependency for a target the user doesn't actually target, so that
/// any advisories that affect crates not in the graph are triggered
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
    pkg: &'a rustsec::package::Package,
) -> Option<(krates::NodeId, &'a Krate)> {
    krates
        .krates_by_name(pkg.name.as_str())
        .find(|(_, krate)| {
            pkg.version == krate.version
                && match (&pkg.source, &krate.source) {
                    (Some(psrc), Some(ksrc)) => ksrc == psrc,
                    (None, None) => true,
                    _ => false,
                }
        })
        .map(|(ind, krate)| (ind, krate))
}

pub use rustsec::{Warning, WarningKind};

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
                        log::error!("Failed to serialize report for database '{url}': {err}");
                    }
                }
            }

            vulnerabilities.append(&mut rep.vulnerabilities.list);

            for (kind, mut wi) in rep.warnings {
                if wi.is_empty() {
                    continue;
                }

                match kind {
                    WarningKind::Notice => notices.append(&mut wi),
                    WarningKind::Unmaintained => unmaintained.append(&mut wi),
                    WarningKind::Unsound => unsound.append(&mut wi),
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

    pub fn iter_warnings(&self) -> impl Iterator<Item = (WarningKind, &Warning)> {
        self.notices
            .iter()
            .map(|wi| (WarningKind::Notice, wi))
            .chain(
                self.unmaintained
                    .iter()
                    .map(|wi| (WarningKind::Unmaintained, wi)),
            )
            .chain(self.unsound.iter().map(|wi| (WarningKind::Unsound, wi)))
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
