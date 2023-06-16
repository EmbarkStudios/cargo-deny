#![doc = include_str!("../README.md")]

pub use semver::Version;
use std::{cmp, collections::HashMap, fmt};
use url::Url;

pub mod advisories;
pub mod bans;
mod cfg;
pub mod diag;
/// Configuration and logic for checking crate licenses
pub mod licenses;
pub mod sources;

#[doc(hidden)]
pub mod test_utils;

pub use camino::{Utf8Path as Path, Utf8PathBuf as PathBuf};
pub use cfg::{Spanned, UnvalidatedConfig};
use krates::cm;
pub use krates::{DepKind, Kid};

const CRATES_IO_SPARSE: &str = "sparse+https://index.crates.io/";
const CRATES_IO_GIT: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The possible lint levels for the various lints. These function similarly
/// to the standard [Rust lint levels](https://doc.rust-lang.org/rustc/lints/levels.html)
#[derive(serde::Deserialize, PartialEq, Eq, Clone, Copy, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum LintLevel {
    /// A debug or info diagnostic _may_ be emitted if the lint is violated
    Allow,
    /// A warning will be emitted if the lint is violated, but the command
    /// will succeed
    #[default]
    Warn,
    /// An error will be emitted if the lint is violated, and the command
    /// will fail with a non-zero exit code
    Deny,
}

const fn lint_allow() -> LintLevel {
    LintLevel::Allow
}

const fn lint_warn() -> LintLevel {
    LintLevel::Warn
}

const fn lint_deny() -> LintLevel {
    LintLevel::Deny
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SourceKind {
    /// crates.io, the boolean indicates whether it is a sparse index
    CratesIo(bool),
    /// A remote git patch
    Git(GitSpec),
    /// A remote git index
    Registry,
    /// A remote sparse index
    Sparse,
}

/// Wrapper around the original source url
#[derive(Debug, PartialEq)]
pub struct Source {
    pub kind: SourceKind,
    url: Option<url::Url>,
}

impl Source {
    fn from_metadata(urls: String) -> anyhow::Result<Self> {
        if urls == CRATES_IO_GIT {
            return Ok(Self {
                kind: SourceKind::CratesIo(false),
                url: None,
            });
        } else if urls == CRATES_IO_SPARSE {
            return Ok(Self {
                kind: SourceKind::CratesIo(true),
                url: None,
            });
        }

        use anyhow::Context as _;
        let index = urls.find('+').context("url is not a valid crate source")?;
        let mut url = Url::parse(&urls[index + 1..]).context("failed to parse url")?;

        let kind = match &urls[..index] {
            "sparse" => SourceKind::Sparse,
            "registry" => SourceKind::Registry,
            "git" => {
                let spec = normalize_git_url(&mut url);
                SourceKind::Git(spec)
            }
            unknown => anyhow::bail!("unknown source spec '{unknown}' for url {urls}"),
        };

        Ok(Self {
            kind,
            url: Some(url),
        })
    }

    #[inline]
    pub fn is_git(&self) -> bool {
        matches!(self.kind, SourceKind::Git(_))
    }

    #[inline]
    pub fn git_spec(&self) -> Option<GitSpec> {
        if let SourceKind::Git(spec) = self.kind {
            Some(spec)
        } else {
            None
        }
    }

    #[inline]
    pub fn is_registry(&self) -> bool {
        matches!(
            self.kind,
            SourceKind::CratesIo(_) | SourceKind::Registry | SourceKind::Sparse
        )
    }

    #[inline]
    pub fn is_crates_io(&self) -> bool {
        matches!(self.kind, SourceKind::CratesIo(_))
    }

    #[inline]
    pub fn url(&self) -> Option<&Url> {
        self.url.as_ref()
    }

    #[inline]
    pub fn to_rustsec(&self) -> rustsec::package::SourceId {
        use rustsec::package::SourceId;
        // TODO: Change this once rustsec supports sparse indices
        match (self.kind, &self.url) {
            (SourceKind::CratesIo(_), None) => SourceId::default(),
            (SourceKind::Registry | SourceKind::Sparse, Some(url)) => {
                SourceId::for_registry(url).unwrap()
            }
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn matches_rustsec(&self, sid: Option<&rustsec::package::SourceId>) -> bool {
        let Some(sid) = sid else { return self.is_crates_io(); };
        let Some(ksid) = &self.url else { return false; };

        if self.is_registry() && sid.is_remote_registry() {
            sid.url() == ksid
        } else {
            false
        }
    }
}

impl fmt::Display for Source {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind, self.url.as_ref()) {
            (SourceKind::CratesIo(is_sparse), None) => f.write_str(if is_sparse {
                CRATES_IO_SPARSE
            } else {
                CRATES_IO_GIT
            }),
            (SourceKind::Git(_), Some(url)) => {
                write!(f, "git+{url}")
            }
            (SourceKind::Registry, Some(url)) => {
                write!(f, "registry+{url}")
            }
            (SourceKind::Sparse, Some(url)) => {
                write!(f, "sparse+{url}")
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct Krate {
    pub name: String,
    pub id: Kid,
    pub version: Version,
    pub source: Option<Source>,
    pub authors: Vec<String>,
    pub repository: Option<String>,
    pub description: Option<String>,
    pub manifest_path: PathBuf,
    pub license: Option<String>,
    pub license_file: Option<PathBuf>,
    pub deps: Vec<cm::Dependency>,
    pub features: HashMap<String, Vec<String>>,
    pub targets: Vec<cm::Target>,
    pub publish: Option<Vec<String>>,
}

#[cfg(test)]
impl Default for Krate {
    fn default() -> Self {
        Self {
            name: "".to_owned(),
            version: Version::new(0, 1, 0),
            authors: Vec::new(),
            id: Kid {
                repr: "".to_owned(),
            },
            source: None,
            description: None,
            deps: Vec::new(),
            license: None,
            license_file: None,
            targets: Vec::new(),
            features: HashMap::new(),
            manifest_path: PathBuf::new(),
            repository: None,
            publish: None,
        }
    }
}

impl PartialOrd for Krate {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Krate {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialEq for Krate {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Krate {}

impl krates::KrateDetails for Krate {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &semver::Version {
        &self.version
    }
}

impl From<cm::Package> for Krate {
    fn from(pkg: cm::Package) -> Self {
        let source = pkg.source.and_then(|src| {
            let url = src.to_string();

            Source::from_metadata(url)
                .map_err(|err| {
                    log::warn!(
                        "unable to parse source url for {}:{}: {err}",
                        pkg.name,
                        pkg.version
                    );
                    err
                })
                .ok()
        });

        Self {
            name: pkg.name,
            id: pkg.id,
            version: pkg.version,
            authors: pkg.authors,
            repository: pkg.repository,
            source,
            targets: pkg.targets,
            license: pkg.license.map(|lf| {
                // cargo used to allow / in place of OR which is not valid
                // in SPDX expression, we force correct it here
                if lf.contains('/') {
                    lf.replace('/', " OR ")
                } else {
                    lf
                }
            }),
            license_file: pkg.license_file,
            description: pkg.description,
            manifest_path: pkg.manifest_path,
            deps: {
                let mut deps = pkg.dependencies;
                deps.sort_by(|a, b| a.name.cmp(&b.name));
                deps
            },
            features: pkg.features,
            publish: pkg.publish,
        }
    }
}

impl Krate {
    /// Returns true if the crate is marked as `publish = false`, or
    /// it is only published to the specified private registries
    pub(crate) fn is_private(&self, private_registries: &[&str]) -> bool {
        self.publish.as_ref().map_or(false, |v| {
            if v.is_empty() {
                true
            } else {
                v.iter()
                    .all(|reg| private_registries.contains(&reg.as_str()))
            }
        })
    }

    /// Determines if the specified url matches the source
    #[inline]
    pub(crate) fn matches_url(&self, url: &Url, exact: bool) -> bool {
        let Some(src) = &self.source else { return false };

        // It's irrelevant if it's sparse or not
        if src.is_crates_io() {
            return url.as_str().ends_with(&CRATES_IO_SPARSE[8..])
                || url.as_str().ends_with(&CRATES_IO_GIT[10..]);
        }

        let Some(kurl) = &src.url else { return false; };

        if kurl.scheme() != url.scheme() || kurl.host() != url.host() {
            return false;
        }

        (exact && kurl.path() == url.path()) || (!exact && kurl.path().starts_with(url.path()))
    }

    #[inline]
    pub(crate) fn is_crates_io(&self) -> bool {
        self.source.as_ref().map_or(false, |src| src.is_crates_io())
    }

    #[inline]
    pub(crate) fn is_git_source(&self) -> bool {
        self.source.as_ref().map_or(false, |src| src.is_git())
    }
}

impl fmt::Display for Krate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.version)
    }
}

pub type Krates = krates::Krates<Krate>;

#[inline]
pub fn binary_search<T, Q>(s: &[T], query: &Q) -> Result<usize, usize>
where
    T: std::borrow::Borrow<Q>,
    Q: Ord + ?Sized,
{
    s.binary_search_by(|i| i.borrow().cmp(query))
}

#[inline]
pub fn contains<T, Q>(s: &[T], query: &Q) -> bool
where
    T: std::borrow::Borrow<Q>,
    Q: Eq + ?Sized,
{
    s.iter().any(|i| i.borrow() == query)
}

#[inline]
pub fn hash(data: &[u8]) -> u32 {
    use std::hash::Hasher;
    // We use the 32-bit hash instead of the 64 even though
    // it is significantly slower due to the TOML limitation
    // if only supporting i64
    let mut xx = twox_hash::XxHash32::default();
    xx.write(data);
    xx.finish() as u32
}

/// Common context for the various checks. Some checks require additional
/// information though.
pub struct CheckCtx<'ctx, T> {
    /// The configuration for the check
    pub cfg: T,
    /// The krates graph to check
    pub krates: &'ctx Krates,
    /// The spans for each unique crate in a synthesized "lock file"
    pub krate_spans: &'ctx diag::KrateSpans,
    /// Requests for additional information the check can provide to be
    /// serialized to the diagnostic
    pub serialize_extra: bool,
    /// Allows for ANSI colorization of diagnostic content
    pub colorize: bool,
}

/// Checks if a version satisfies the specifies the specified version requirement.
/// If the requirement is `None` then it is also satisfied.
#[inline]
pub fn match_req(version: &Version, req: Option<&semver::VersionReq>) -> bool {
    req.map_or(true, |req| req.matches(version))
}

use sources::GitSpec;

#[inline]
pub(crate) fn normalize_git_url(url: &mut Url) -> GitSpec {
    // Normalizes the URL so that different representations can be compared to each other.
    // At the moment we just remove a tailing `.git` but there are more possible optimisations.
    // See https://github.com/rust-lang/cargo/blob/1f6c6bd5e7bbdf596f7e88e6db347af5268ab113/src/cargo/util/canonical_url.rs#L31-L57
    // for what cargo does
    const GIT_EXT: &str = ".git";

    let needs_chopping = url.path().ends_with(&GIT_EXT);
    if needs_chopping {
        let last = {
            let last = url.path_segments().unwrap().last().unwrap();
            last[..last.len() - GIT_EXT.len()].to_owned()
        };
        url.path_segments_mut().unwrap().pop().push(&last);
    }

    if url.path().ends_with('/') {
        url.path_segments_mut().unwrap().pop_if_empty();
    }

    let mut spec = GitSpec::Any;

    for (k, _v) in url.query_pairs() {
        spec = match k.as_ref() {
            "branch" | "ref" => GitSpec::Branch,
            "tag" => GitSpec::Tag,
            "rev" => GitSpec::Rev,
            _ => continue,
        };
    }

    if url
        .query_pairs()
        .any(|(k, v)| k == "branch" && v == "master")
    {
        if url.query_pairs().count() == 1 {
            url.set_query(None);
        } else {
            let mut nq = String::new();
            for (k, v) in url.query_pairs() {
                if k == "branch" && v == "master" {
                    continue;
                }

                use std::fmt::Write;
                write!(&mut nq, "{k}={v}&").unwrap();
            }

            nq.pop();
            url.set_query(Some(&nq));
        }
    }

    spec
}

/// Helper function to convert a std `PathBuf` to a camino one
#[inline]
#[allow(clippy::disallowed_types)]
pub fn utf8path(pb: std::path::PathBuf) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    PathBuf::try_from(pb).context("non-utf8 path")
}

#[cfg(test)]
mod test {
    use super::Source;

    #[test]
    fn parses_sources() {
        let crates_io_git = Source::from_metadata(
            "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
        )
        .unwrap();
        let crates_io_sparse =
            Source::from_metadata("sparse+https://index.crates.io/".to_owned()).unwrap();

        assert!(crates_io_git.is_registry() && crates_io_sparse.is_registry());
        assert!(crates_io_git.is_crates_io() && crates_io_sparse.is_crates_io());

        assert!(
            Source::from_metadata("registry+https://my-own-my-precious.com/".to_owned())
                .unwrap()
                .is_registry()
        );
        assert!(
            Source::from_metadata("sparse+https://my-registry.rs/".to_owned())
                .unwrap()
                .is_registry()
        );

        let src = Source::from_metadata("git+https://github.com/EmbarkStudios/wasmtime?branch=v6.0.1-profiler#84b8cacceacb585ef53774c3790b2372ba080067".to_owned()).unwrap();

        assert!(src.is_git());
    }
}
