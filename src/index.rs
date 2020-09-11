use crate::{Kid, Krate, Krates};
use anyhow::Error;
use log::{error, info};
use std::hash::{Hash, Hasher};
use url::Url;

pub struct Index {
    registries: Vec<crates_index::BareIndex>,
    opened: Vec<Option<crates_index::BareIndexRepo<'static>>>,
    cache: std::collections::HashMap<Kid, Option<crates_index::Crate>>,
}

impl Index {
    /// Loads the index for every remote registry used a source by 1 or more
    /// krates in the specified graph
    pub fn load(krates: &Krates) -> Result<Self, Error> {
        let mut urls = Vec::new();

        for node in krates.krates() {
            if let Some(src) = &node.krate.source {
                if src.is_registry() {
                    let url = src.url();
                    if !urls.contains(url) {
                        urls.push(url.clone());
                    }
                }
            }
        }

        info!("Found {} unique remote crate registries", urls.len());

        // It's either intentional or a bug, but it seems (at least today, using
        // a cloudsmith registry), that cargo actually only seems to populate
        // the actual checkout for the crates.io index, but doesn't for
        // non-crates.io indices. cargo however does keep a .cache directory in
        // the same layout as the normal cloned registry, which we use instead
        // for *all* indices so there is no need to special case between
        // crates.io and others
        let registries: Vec<_> = urls
            .into_iter()
            .filter_map(|u| match crates_index::BareIndex::from_url(u.as_str()) {
                Ok(ndex) => Some(ndex),
                Err(e) => {
                    error!("Unable to create index for {}: {}", u, e);
                    None
                }
            })
            .collect();

        let opened = registries.iter().map(|_| None).collect();

        Ok(Self {
            registries,
            opened,
            cache: std::collections::HashMap::new(),
        })
    }

    pub fn read_krate<F>(&mut self, krate: &Krate, mut func: F)
    where
        F: FnMut(Option<&crates_index::Crate>),
    {
        if !krate
            .source
            .as_ref()
            .map(|src| src.is_registry())
            .unwrap_or(false)
        {
            func(None);
            return;
        }

        let url = krate.source.as_ref().unwrap().url();
        if let Some(ind) = self
            .registries
            .iter()
            .position(|reg| reg.url == url.as_str())
        {
            if let Some(cic) = self.cache.get(&krate.id) {
                func(cic.as_ref());
                return;
            }

            if self.opened[ind].is_none() {
                match self.registries[ind].open_or_clone() {
                    Ok(bir) => {
                        let bir = unsafe {
                            std::mem::transmute::<_, crates_index::BareIndexRepo<'static>>(bir)
                        };
                        self.opened[ind] = Some(bir);
                    }
                    Err(err) => {
                        log::error!("Failed to open registry index {}: {}", url, err);
                        func(None);
                        return;
                    }
                }
            }

            let bir = self.opened[ind].as_ref().unwrap();
            let cic = bir.krate(&krate.name);

            func(cic.as_ref());

            self.cache.insert(krate.id.clone(), cic);
            return;
        }

        func(None);
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        self.opened.clear();
    }
}

fn to_hex(num: u64) -> String {
    const CHARS: &[u8] = b"0123456789abcdef";

    let bytes = &[
        num as u8,
        (num >> 8) as u8,
        (num >> 16) as u8,
        (num >> 24) as u8,
        (num >> 32) as u8,
        (num >> 40) as u8,
        (num >> 48) as u8,
        (num >> 56) as u8,
    ];

    let mut output = vec![0u8; 16];

    let mut ind = 0;

    for &byte in bytes {
        output[ind] = CHARS[(byte >> 4) as usize];
        output[ind + 1] = CHARS[(byte & 0xf) as usize];

        ind += 2;
    }

    String::from_utf8(output).expect("valid utf-8 hex string")
}

fn hash_u64<H: Hash>(hashable: H) -> u64 {
    #[allow(deprecated)]
    let mut hasher = std::hash::SipHasher::new_with_keys(0, 0);
    hashable.hash(&mut hasher);
    hasher.finish()
}

fn short_hash<H: Hash>(hashable: &H) -> String {
    to_hex(hash_u64(hashable))
}

pub struct Canonicalized(Url);

impl Hash for Canonicalized {
    fn hash<S: Hasher>(&self, into: &mut S) {
        self.0.as_str().hash(into);
    }
}

impl Canonicalized {
    pub(crate) fn ident(&self) -> String {
        // This is the same identity function used by cargo
        let ident = self
            .0
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("");

        let ident = if ident == "" { "_empty" } else { ident };

        format!("{}-{}", ident, short_hash(&self.0))
    }
}

impl AsRef<Url> for Canonicalized {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

impl Into<Url> for Canonicalized {
    fn into(self) -> Url {
        self.0
    }
}

impl std::convert::TryFrom<&Url> for Canonicalized {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        // This is the same canonicalization that cargo does, except the URLs
        // they use don't have any query params or fragments, even though
        // they do occur in Cargo.lock files

        // cannot-be-a-base-urls (e.g., `github.com:rust-lang-nursery/rustfmt.git`)
        // are not supported.
        if url.cannot_be_a_base() {
            anyhow::bail!(
                "invalid url `{}`: cannot-be-a-base-URLs are not supported",
                url
            )
        }

        let mut url_str = String::new();

        let is_github = url.host_str() == Some("github.com");

        // HACK: for GitHub URLs specifically, just lower-case
        // everything. GitHub treats both the same, but they hash
        // differently, and we're gonna be hashing them. This wants a more
        // general solution, and also we're almost certainly not using the
        // same case conversion rules that GitHub does. (See issue #84.)
        if is_github {
            url_str.push_str("https://");
        } else {
            url_str.push_str(url.scheme());
            url_str.push_str("://");
        }

        // Not handling username/password

        if let Some(host) = url.host_str() {
            url_str.push_str(host);
        }

        if let Some(port) = url.port() {
            use std::fmt::Write;
            url_str.push(':');
            write!(&mut url_str, "{}", port)?;
        }

        if is_github {
            url_str.push_str(&url.path().to_lowercase());
        } else {
            url_str.push_str(url.path());
        }

        // Strip a trailing slash.
        if url_str.ends_with('/') {
            url_str.pop();
        }

        // Repos can generally be accessed with or without `.git` extension.
        if url_str.ends_with(".git") {
            url_str.truncate(url_str.len() - 4);
        }

        let url = Url::parse(&url_str)?;

        Ok(Self(url))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;
    use url::Url;

    #[test]
    fn hashes_same_as_cargo() {
        let crates_io_index = Url::parse("https://github.com/rust-lang/crates.io-index").unwrap();

        let canon = Canonicalized::try_from(&crates_io_index).unwrap();

        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum GitReference {
            /// From a tag.
            Tag(String),

            /// From the HEAD of a branch.
            Branch(String),

            /// From a specific revision.
            Rev(String),
        }

        #[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
        enum SourceKind {
            /// A git repository.
            Git(GitReference),

            /// A local path..
            Path,

            /// A remote registry.
            Registry,

            /// A local filesystem-based registry.
            LocalRegistry,

            /// A directory-based registry.
            Directory,
        }
        struct HashMe {
            url: Url,
            canonical_url: Canonicalized,
            kind: SourceKind,
            /// For example, the exact Git revision of the specified branch for a Git Source.
            precise: Option<String>,
            /// Name of the registry source for alternative registries
            /// WARNING: this is not always set for alt-registries when the name is
            /// not known.
            name: Option<String>,
        }

        impl Hash for HashMe {
            fn hash<S: Hasher>(&self, into: &mut S) {
                match &self.kind {
                    SourceKind::Git(GitReference::Tag(a)) => {
                        0usize.hash(into);
                        0usize.hash(into);
                        a.hash(into);
                    }
                    SourceKind::Git(GitReference::Branch(a)) => {
                        0usize.hash(into);
                        1usize.hash(into);
                        a.hash(into);
                    }
                    // For now hash `DefaultBranch` the same way as `Branch("master")`,
                    // and for more details see module comments in
                    // src/cargo/sources/git/utils.rs for why `DefaultBranch`
                    // SourceKind::Git(GitReference::DefaultBranch) => {
                    //     0usize.hash(into);
                    //     1usize.hash(into);
                    //     "master".hash(into);
                    // }
                    SourceKind::Git(GitReference::Rev(a)) => {
                        0usize.hash(into);
                        2usize.hash(into);
                        a.hash(into);
                    }

                    SourceKind::Path => 1usize.hash(into),
                    SourceKind::Registry => 2usize.hash(into),
                    SourceKind::LocalRegistry => 3usize.hash(into),
                    SourceKind::Directory => 4usize.hash(into),
                }
                match self.kind {
                    SourceKind::Git(_) => self.canonical_url.hash(into),
                    _ => self.url.as_str().hash(into),
                }
            }
        }

        let hashme = HashMe {
            url: crates_io_index,
            canonical_url: canon,
            kind: SourceKind::Registry,
            precise: Some("locked".to_owned()),
            name: None,
        };

        let hashed = super::short_hash(&hashme);

        assert_eq!(
            format!("{}-{}", hashme.url.host_str().unwrap(), hashed),
            "github.com-1ecc6299db9ec823"
        );
    }

    #[test]
    fn opens_crates_io() {
        let index = crates_index::Index::new(
            "/home/jake/.cargo/registry/index/github.com-1ecc6299db9ec823/.cache",
        );

        for krate in index.crate_index_paths() {
            println!("PATH {}", krate.display());
            //println!("{} - {} version", krate.name(), krate.versions().len());
        }

        panic!("oh no");
    }
}
