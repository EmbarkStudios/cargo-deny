#![doc = include_str!("../README.md")]

pub use semver::Version;
use std::{cmp, collections::BTreeMap, fmt};
use url::Url;

pub mod advisories;
pub mod bans;
pub mod cfg;
pub mod diag;
/// Configuration and logic for checking crate licenses
pub mod licenses;
pub mod root_cfg;
pub mod sources;

#[doc(hidden)]
pub mod test_utils;

pub use camino::{Utf8Path as Path, Utf8PathBuf as PathBuf};
pub use cfg::UnvalidatedConfig;
use krates::cm;
pub use krates::{DepKind, Kid};
pub use toml_file::{
    span::{Span, Spanned},
    Deserialize, Error,
};

/// The possible lint levels for the various lints. These function similarly
/// to the standard [Rust lint levels](https://doc.rust-lang.org/rustc/lints/levels.html)
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, strum::VariantNames, strum::VariantArray)]
#[cfg_attr(test, derive(serde::Serialize))]
#[cfg_attr(test, serde(rename_all = "kebab-case"))]
#[strum(serialize_all = "kebab-case")]
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

#[macro_export]
macro_rules! enum_deser {
    ($enum:ty) => {
        impl<'de> toml_file::Deserialize<'de> for $enum {
            fn deserialize(
                value: &mut toml_file::value::Value<'de>,
            ) -> Result<Self, toml_file::DeserError> {
                let s = value.take_string(Some(stringify!($enum)))?;

                use strum::{VariantArray, VariantNames};

                let Some(pos) = <$enum as VariantNames>::VARIANTS
                    .iter()
                    .position(|v| *v == s.as_ref())
                else {
                    return Err(toml_file::Error::from((
                        toml_file::ErrorKind::UnexpectedValue {
                            expected: <$enum as VariantNames>::VARIANTS,
                        },
                        value.span,
                    ))
                    .into());
                };

                Ok(<$enum as VariantArray>::VARIANTS[pos])
            }
        }
    };
}

enum_deser!(LintLevel);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// crates.io, the boolean indicates whether it is a sparse index
    CratesIo(bool),
    /// A remote git patch
    Git { spec: GitSpec, url: Url },
    /// A remote git index
    Registry(Url),
    /// A remote sparse index
    Sparse(Url),
}

/// The directory name under which crates sourced from the crates.io sparse
/// registry are placed
#[cfg(target_endian = "little")]
const CRATES_IO_SPARSE_DIR: &str = "index.crates.io-6f17d22bba15001f";
#[cfg(target_endian = "big")]
const CRATES_IO_SPARSE_DIR: &str = "index.crates.io-d11c229612889eed";

impl Source {
    pub fn crates_io(is_sparse: bool) -> Self {
        Self::CratesIo(is_sparse)
    }

    /// Parses the source url to get its kind
    ///
    /// Note that the path is the path to the manifest of the package. This is
    /// used to determine if the crates.io registry is git or sparse, as, currently,
    /// cargo always uses the git registry+ url for crates.io, even if it uses the
    /// sparse registry.
    ///
    /// This method therefore assumes that the crates sources are laid out in the
    /// canonical cargo structure, though it can be rooted somewhere other than
    /// `CARGO_HOME`
    fn from_metadata(urls: String, manifest_path: &Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;

        let (kind, url_str) = urls
            .split_once('+')
            .with_context(|| format!("'{urls}' is not a valid crate source"))?;

        match kind {
            "sparse" => {
                // This code won't ever be hit in current cargo, but could in the future
                if urls == tame_index::CRATES_IO_HTTP_INDEX {
                    Ok(Self::crates_io(true))
                } else {
                    Url::parse(&urls)
                        .map(Self::Sparse)
                        .context("failed to parse url")
                }
            }
            "registry" => {
                if url_str == tame_index::CRATES_IO_INDEX {
                    // registry/src/index.crates.io-6f17d22bba15001f/crate-version/Cargo.toml
                    let is_sparse = manifest_path.ancestors().nth(2).map_or(false, |dir| {
                        dir.file_name()
                            .map_or(false, |dir_name| dir_name == CRATES_IO_SPARSE_DIR)
                    });
                    Ok(Self::crates_io(is_sparse))
                } else {
                    Url::parse(url_str)
                        .map(Self::Registry)
                        .context("failed to parse url")
                }
            }
            "git" => {
                let mut url = Url::parse(url_str).context("failed to parse url")?;
                let spec = normalize_git_url(&mut url);

                Ok(Self::Git { url, spec })
            }
            unknown => anyhow::bail!("unknown source spec '{unknown}' for url {urls}"),
        }
    }

    #[inline]
    pub fn is_git(&self) -> bool {
        matches!(self, Self::Git { .. })
    }

    #[inline]
    pub fn git_spec(&self) -> Option<GitSpec> {
        let Self::Git { spec, .. } = self else {
            return None;
        };
        Some(*spec)
    }

    #[inline]
    pub fn is_registry(&self) -> bool {
        !self.is_git()
    }

    #[inline]
    pub fn is_crates_io(&self) -> bool {
        matches!(self, Self::CratesIo(_))
    }

    #[inline]
    pub fn to_rustsec(&self) -> rustsec::package::SourceId {
        use rustsec::package::SourceId;
        // TODO: Change this once rustsec supports sparse indices
        match self {
            Self::CratesIo(_) => SourceId::default(),
            Self::Registry(url) => SourceId::for_registry(url).unwrap(),
            Self::Sparse(sparse) => {
                // There is currently no way to publicly construct a sparse registry
                // id other than this method
                SourceId::from_url(sparse.as_str()).unwrap()
            }
            Self::Git { .. } => unreachable!(),
        }
    }

    #[inline]
    pub fn matches_rustsec(&self, sid: Option<&rustsec::package::SourceId>) -> bool {
        let Some(sid) = sid else {
            return self.is_crates_io();
        };
        if !sid.is_remote_registry() {
            return false;
        }

        let (Self::Registry(url) | Self::Sparse(url)) = self else {
            return false;
        };
        sid.url() == url
    }
}

impl fmt::Display for Source {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CratesIo(_) => {
                write!(f, "registry+{}", tame_index::CRATES_IO_INDEX)
            }
            Self::Git { url, .. } => {
                write!(f, "git+{url}")
            }
            Self::Registry(url) => {
                write!(f, "registry+{url}")
            }
            Self::Sparse(url) => {
                write!(f, "{url}")
            }
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
    pub features: BTreeMap<String, Vec<String>>,
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
            id: Kid::default(),
            source: None,
            description: None,
            deps: Vec::new(),
            license: None,
            license_file: None,
            targets: Vec::new(),
            features: BTreeMap::new(),
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
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn version(&self) -> &semver::Version {
        &self.version
    }
}

impl From<cm::Package> for Krate {
    fn from(pkg: cm::Package) -> Self {
        let source = pkg.source.and_then(|src| {
            let url = src.to_string();

            Source::from_metadata(url, &pkg.manifest_path)
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
            id: pkg.id.into(),
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
        let Some(src) = &self.source else {
            return false;
        };

        let kurl = match src {
            Source::CratesIo(_is_sparse) => {
                // It's irrelevant if it's sparse or not for crates.io, they're the same
                // index, just different protocols/kinds
                return url
                    .as_str()
                    .ends_with(&tame_index::CRATES_IO_HTTP_INDEX[8..])
                    || url.as_str().ends_with(&tame_index::CRATES_IO_INDEX[10..]);
            }
            Source::Sparse(surl) | Source::Registry(surl) | Source::Git { url: surl, .. } => surl,
        };

        kurl.host() == url.host() && (exact && kurl.path() == url.path())
            || (!exact && kurl.path().starts_with(url.path()))
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

#[inline]
pub fn match_krate(krate: &Krate, pid: &cfg::PackageSpec) -> bool {
    krate.name == pid.name.value && match_req(&krate.version, pid.version_req.as_ref())
}

use sources::cfg::GitSpec;

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

/// Adds the crates.io index with the specified settings to the builder for
/// feature resolution
pub fn krates_with_index(
    kb: &mut krates::Builder,
    config_root: Option<PathBuf>,
    cargo_home: Option<PathBuf>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let crates_io = tame_index::IndexUrl::crates_io(config_root, cargo_home.as_deref(), None)
        .context("unable to determine crates.io url")?;

    let index = tame_index::index::ComboIndexCache::new(
        tame_index::IndexLocation::new(crates_io).with_root(cargo_home.clone()),
    )
    .context("unable to open local crates.io index")?;

    // Note we don't take a lock here ourselves, since we are calling cargo
    // it will take the lock and only give us results if it gets access, if we
    // took a look we would deadlock here
    let lock = tame_index::utils::flock::FileLock::unlocked();

    let index_cache_build = move |krates: std::collections::BTreeSet<String>| {
        let mut cache = std::collections::BTreeMap::new();
        for name in krates {
            let read = || -> Option<krates::index::IndexKrate> {
                let name = name.as_str().try_into().ok()?;
                let krate = index.cached_krate(name, &lock).ok()??;
                let versions = krate
                    .versions
                    .into_iter()
                    .filter_map(|kv| {
                        // The index (currently) can have both features, and
                        // features2, the features method gives us an iterator
                        // over both
                        kv.version.parse::<semver::Version>().ok().map(|version| {
                            krates::index::IndexKrateVersion {
                                version,
                                features: kv
                                    .features()
                                    .map(|(k, v)| (k.clone(), v.clone()))
                                    .collect(),
                            }
                        })
                    })
                    .collect();

                Some(krates::index::IndexKrate { versions })
            };

            let krate = read();
            cache.insert(name, krate);
        }

        cache
    };

    kb.with_crates_io_index(Box::new(index_cache_build));

    Ok(())
}

#[cfg(test)]
mod test {
    use super::Source;

    #[test]
    fn parses_sources() {
        let empty_dir = super::Path::new("");
        let crates_io_git = Source::from_metadata(
            format!("registry+{}", tame_index::CRATES_IO_INDEX),
            empty_dir,
        )
        .unwrap();
        let crates_io_sparse =
            Source::from_metadata(tame_index::CRATES_IO_HTTP_INDEX.to_owned(), empty_dir).unwrap();
        let crates_io_sparse_but_git = Source::from_metadata(
            format!("registry+{}", tame_index::CRATES_IO_INDEX),
            super::Path::new(&format!(
                "registry/src/{}/cargo-deny-0.69.0/Cargo.toml",
                super::CRATES_IO_SPARSE_DIR
            )),
        )
        .unwrap();

        assert!(
            crates_io_git.is_registry()
                && crates_io_sparse.is_registry()
                && crates_io_sparse_but_git.is_registry()
        );
        assert!(
            crates_io_git.is_crates_io()
                && crates_io_sparse.is_crates_io()
                && crates_io_sparse_but_git.is_crates_io()
        );

        assert!(Source::from_metadata(
            "registry+https://my-own-my-precious.com/".to_owned(),
            empty_dir
        )
        .unwrap()
        .is_registry());
        assert!(
            Source::from_metadata("sparse+https://my-registry.rs/".to_owned(), empty_dir)
                .unwrap()
                .is_registry()
        );

        let src = Source::from_metadata("git+https://github.com/EmbarkStudios/wasmtime?branch=v6.0.1-profiler#84b8cacceacb585ef53774c3790b2372ba080067".to_owned(), empty_dir).unwrap();

        assert!(src.is_git());
    }

    /// Sanity checks that the crates.io sparse registry still uses the same
    /// local directory. Really this should be doing a cargo invocation, but
    /// meh, we depend on tame-index to stay up to date
    #[test]
    fn validate_crates_io_sparse_dir_name() {
        assert_eq!(
            tame_index::utils::url_to_local_dir(tame_index::CRATES_IO_HTTP_INDEX)
                .unwrap()
                .dir_name,
            super::CRATES_IO_SPARSE_DIR
        );
    }
}
