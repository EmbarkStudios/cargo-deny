//! This is a copy of <https://github.com/frewsxcv/rust-crates-index/pull/41> so
//! that we can make releases of cargo-deny until/if it is merged and released

use super::IndexKrate;
use anyhow::{Context, Error};
use std::path::{Path, PathBuf};

pub struct BareIndex {
    path: PathBuf,
    pub url: String,
}

impl BareIndex {
    /// Creates a bare index from a provided URL, opening the same location on
    /// disk that cargo uses for that registry index.
    pub fn from_url(url: &str) -> Result<Self, Error> {
        let (dir_name, canonical_url) = super::url_to_local_dir(url)?;
        let mut path = home::cargo_home().unwrap_or_default();

        path.push("registry/index");
        path.push(dir_name);

        Ok(Self {
            path,
            url: canonical_url,
        })
    }

    /// Opens the local index, which acts as a kind of lock for source control
    /// operations
    pub fn open_or_clone(&self) -> Result<BareIndexRepo<'_>, Error> {
        BareIndexRepo::new(self)
    }
}

pub struct BareIndexRepo<'a> {
    inner: &'a BareIndex,
    repo: git2::Repository,
    tree: Option<git2::Tree<'static>>,
    head_str: String,
}

impl<'a> BareIndexRepo<'a> {
    fn new(index: &'a BareIndex) -> Result<Self, Error> {
        let exists = git2::Repository::discover(&index.path)
            .map(|repository| {
                repository
                    .find_remote("origin")
                    .ok()
                    // Cargo creates a checkout without an origin set,
                    // so default to true in case of missing origin
                    .map_or(true, |remote| {
                        remote.url().map_or(true, |url| url == index.url)
                    })
            })
            .unwrap_or(false);

        if !exists {
            git2::build::RepoBuilder::new()
                .fetch_options(fetch_opts())
                .bare(true)
                .clone(&index.url, &index.path)?;
        }

        let repo = git2::Repository::open(&index.path)?;
        let head = repo
            .refname_to_id("FETCH_HEAD")
            .or_else(|_| repo.refname_to_id("HEAD"))?;
        let head_str = head.to_string();

        let tree = {
            let commit = repo.find_commit(head)?;
            let tree = commit.tree()?;

            // TODO: Can we get rid of this transmute?
            #[allow(unsafe_code, clippy::useless_transmute)]
            unsafe {
                std::mem::transmute::<git2::Tree<'_>, git2::Tree<'static>>(tree)
            }
        };

        Ok(Self {
            inner: index,
            head_str,
            repo,
            tree: Some(tree),
        })
    }

    /// Reads a crate from the index, it will attempt to use a cached entry if
    /// one is available, otherwise it will fallback to reading the crate
    /// directly from the git blob containing the crate information.
    pub fn krate(&self, name: &str) -> Option<IndexKrate> {
        let rel_path = match crate_name_to_relative_path(name) {
            Some(rp) => rp,
            None => return None,
        };

        // Attempt to load the .cache/ entry first, this is purely an acceleration
        // mechanism and can fail for a few reasons that are non-fatal
        {
            let mut cache_path = self.inner.path.join(".cache");
            cache_path.push(&rel_path);
            if let Ok(cache_bytes) = std::fs::read(&cache_path) {
                if let Ok(krate) = IndexKrate::from_cache_slice(&cache_bytes, &self.head_str) {
                    return Some(krate);
                }
            }
        }

        // Fallback to reading the blob directly via git if we don't have a
        // valid cache entry
        self.krate_from_blob(&rel_path).ok()
    }

    fn krate_from_blob(&self, path: &str) -> Result<IndexKrate, Error> {
        let entry = self.tree.as_ref().unwrap().get_path(Path::new(path))?;
        let object = entry.to_object(&self.repo)?;
        let blob = object.as_blob().context("unable to get blob contents")?;

        IndexKrate::from_slice(blob.content())
    }
}

impl<'a> Drop for BareIndexRepo<'a> {
    fn drop(&mut self) {
        // Just be sure to drop this before our other fields
        self.tree.take();
    }
}

fn crate_name_to_relative_path(crate_name: &str) -> Option<String> {
    if !crate_name.is_ascii() {
        return None;
    }

    let name_lower = crate_name.to_ascii_lowercase();
    let mut rel_path = String::with_capacity(crate_name.len() + 6);
    match name_lower.len() {
        0 => return None,
        1 => rel_path.push('1'),
        2 => rel_path.push('2'),
        3 => {
            rel_path.push('3');
            rel_path.push(std::path::MAIN_SEPARATOR);
            rel_path.push_str(&name_lower[0..1]);
        }
        _ => {
            rel_path.push_str(&name_lower[0..2]);
            rel_path.push(std::path::MAIN_SEPARATOR);
            rel_path.push_str(&name_lower[2..4]);
        }
    };
    rel_path.push(std::path::MAIN_SEPARATOR);
    rel_path.push_str(&name_lower);

    Some(rel_path)
}

fn fetch_opts() -> git2::FetchOptions<'static> {
    let mut proxy_opts = git2::ProxyOptions::new();
    proxy_opts.auto();
    let mut fetch_opts = git2::FetchOptions::new();
    fetch_opts.proxy_options(proxy_opts);
    fetch_opts
}

#[cfg(test)]
mod test {
    const CRATES_IO_URL: &str = "https://github.com/rust-lang/crates.io-index";

    #[test]
    fn matches_cargo() {
        assert_eq!(
            crate::index::url_to_local_dir(CRATES_IO_URL).unwrap(),
            (
                "github.com-1ecc6299db9ec823".to_owned(),
                CRATES_IO_URL.to_owned()
            )
        );

        // I've confirmed this also works with a custom registry, unfortunately
        // that one includes a secret key as part of the url which would allow
        // anyone to publish to the registry, so uhh...here's a fake one instead
        assert_eq!(
            crate::index::url_to_local_dir(
                "https://dl.cloudsmith.io/aBcW1234aBcW1234/embark/rust/cargo/index.git"
            )
            .unwrap(),
            (
                "dl.cloudsmith.io-ff79e51ddd2b38fd".to_owned(),
                "https://dl.cloudsmith.io/aBcW1234aBcW1234/embark/rust/cargo/index".to_owned()
            )
        );

        // Ensure we actually strip off the irrelevant parts of a url, note that
        // the .git suffix is not part of the canonical url, but *is* used when hashing
        assert_eq!(
            crate::index::url_to_local_dir(&format!(
                "registry+{}.git?one=1&two=2#fragment",
                CRATES_IO_URL
            ))
            .unwrap(),
            (
                "github.com-c786010fb7ef2e6e".to_owned(),
                CRATES_IO_URL.to_owned()
            )
        );
    }
}
