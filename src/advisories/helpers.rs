pub(super) mod db;
//pub(super) mod index;

use anyhow::Context as _;

/// Converts a full url, eg <https://github.com/rust-lang/crates.io-index>, into
/// the root directory name where cargo itself will fetch it on disk
pub(crate) fn url_to_local_dir(url: &str) -> anyhow::Result<(String, String)> {
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
    fn hash_u64(url: &str, kind: u64) -> u64 {
        use std::hash::{Hash, Hasher, SipHasher};

        let mut hasher = SipHasher::new_with_keys(0, 0);
        kind.hash(&mut hasher);
        url.hash(&mut hasher);
        hasher.finish()
    }

    const KIND_GIT_INDEX: u64 = 2;
    const KIND_SPARSE_INDEX: u64 = 3;

    let mut is_sparse = false;

    // Ensure we have a registry or bare url
    let (url, scheme_ind) = {
        let scheme_ind = url
            .find("://")
            .with_context(|| format!("'{}' is not a valid url", url))?;

        let scheme_str = &url[..scheme_ind];
        if scheme_str.starts_with("sparse+http") {
            is_sparse = true;
            (url, scheme_ind)
        } else if let Some(ind) = scheme_str.find('+') {
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

    // Note that cargo only hashes the canonical address for git registry indices, not
    // any other registry kind
    let (ident, url) = if !is_sparse {
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

        let ident = to_hex(hash_u64(&canonical, KIND_GIT_INDEX));

        if canonical.ends_with('/') {
            canonical.pop();
        }

        if host == "github.com" && canonical.ends_with(".git") {
            canonical.truncate(canonical.len() - 4);
        }

        (ident, canonical)
    } else {
        (to_hex(hash_u64(url, KIND_SPARSE_INDEX)), url.to_owned())
    };

    Ok((format!("{host}-{ident}"), url))
}

/// Checks whether the crates.io git index should be used for the index
/// metadata for crates
pub fn allow_crates_io_git_index() -> anyhow::Result<bool> {
    use anyhow::Context as _;
    let allow = match (
        std::env::var("CARGO_REGISTRIES_CRATES_IO_PROTOCOL")
            .as_deref()
            .ok(),
        cfg!(feature = "standalone"),
    ) {
        (Some("sparse"), _) | (_, true) => false,
        (Some("git"), _) => true,
        (_, false) => {
            // Check the cargo version to detect if the sparse registry is enabled by default
            let mut cargo = std::process::Command::new(
                std::env::var("CARGO").unwrap_or_else(|_ve| "cargo".to_owned()),
            );
            cargo.arg("-V");
            cargo.stdout(std::process::Stdio::piped());
            let output = cargo
                .output()
                .context("failed to run cargo to detect version information")?;

            anyhow::ensure!(
                output.status.success(),
                "failed to get version information from cargo"
            );

            let vinfo =
                String::from_utf8(output.stdout).context("cargo version output was not utf-8")?;
            let semver = vinfo
                .split(' ')
                .nth(1)
                .context("unable to get semver from cargo output")?;
            let semver: semver::Version = semver.parse().context("unable to parse semver")?;

            semver < semver::Version::new(1, 70, 0)
        }
    };

    Ok(allow)
}
