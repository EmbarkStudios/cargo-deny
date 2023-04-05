#![doc = include_str!("../README.md")]

pub use semver::Version;
use std::{cmp, collections::HashMap, fmt};

pub mod advisories;
pub mod bans;
mod cfg;
pub mod diag;
/// Configuration and logic for checking crate licenses
pub mod licenses;
pub mod sources;

#[doc(hidden)]
pub mod test_utils;

pub use cfg::{Spanned, UnvalidatedConfig};
use krates::cm;
pub use krates::{DepKind, Kid, Utf8PathBuf};
pub use rustsec::package::SourceId as SecSrcId;

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

#[derive(Debug)]
pub enum SourceId {
    Sparse(url::Url),
    Rustsec(SecSrcId),
}

impl SourceId {
    #[inline]
    pub fn is_registry(&self) -> bool {
        match self {
            Self::Sparse(_) => true,
            Self::Rustsec(ssi) => ssi.is_registry(),
        }
    }

    #[inline]
    pub fn is_git(&self) -> bool {
        match self {
            Self::Sparse(_) => false,
            Self::Rustsec(ssi) => ssi.is_git(),
        }
    }

    #[inline]
    pub fn is_crates_io(&self) -> bool {
        match self {
            Self::Sparse(u) => u.as_str() == "https://index.crates.io/",
            Self::Rustsec(ssi) => ssi.is_default_registry(),
        }
    }

    #[inline]
    pub fn to_rustsec(&self) -> SecSrcId {
        match self {
            // Fake it until rustsec supports sparse indices
            Self::Sparse(u) => SecSrcId::for_registry(u).unwrap(),
            Self::Rustsec(ssi) => ssi.clone(),
        }
    }
}

impl fmt::Display for SourceId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sparse(s) => write!(f, "sparse+{s}"),
            Self::Rustsec(ssi) => write!(f, "{ssi}"),
        }
    }
}

impl std::str::FromStr for SourceId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(sparse_url) = s.strip_prefix("sparse+") {
            Ok(Self::Sparse(sparse_url.parse()?))
        } else {
            Ok(Self::Rustsec(s.parse()?))
        }
    }
}

/// Wrapper around the original source url
#[derive(Debug)]
pub struct Source {
    /// The original url obtained via cargo
    pub url: url::Url,
    /// The rustsec id, this is used to match crates in our graph with the one
    /// that rustsec uses
    pub source_id: SourceId,
}

impl Source {
    #[inline]
    pub fn is_registry(&self) -> bool {
        self.source_id.is_registry()
    }

    #[inline]
    pub fn is_git(&self) -> bool {
        self.source_id.is_git()
    }

    /// Whether the source is crates.io, regardless of whether it is using the
    /// git or HTTP sparse index
    #[inline]
    pub fn is_crates_io(&self) -> bool {
        self.source_id.is_crates_io()
    }

    #[inline]
    pub fn to_rustsec(&self) -> SecSrcId {
        self.source_id.to_rustsec()
    }
}

impl fmt::Display for Source {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source_id)
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
    pub manifest_path: Utf8PathBuf,
    pub license: Option<String>,
    pub license_file: Option<Utf8PathBuf>,
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
            manifest_path: Utf8PathBuf::new(),
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
        Self {
            name: pkg.name,
            id: pkg.id,
            version: pkg.version,
            authors: pkg.authors,
            repository: pkg.repository,
            source: {
                pkg.source.and_then(|src| {
                    let url = src.to_string();

                    match url.parse() {
                        Ok(source_id) => {
                            // Strip the leading <kind>+ from the url
                            let url = if let Some(ind) = url.find('+') {
                                url[ind + 1..].to_owned()
                            } else {
                                url
                            };

                            Some(Source {
                                url: url.parse().unwrap(),
                                source_id,
                            })
                        }
                        Err(err) => {
                            log::warn!("unable to parse source url '{url}': {err}");
                            None
                        }
                    }
                })
            },
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

    /// Returns the normalized source URL
    pub(crate) fn normalized_source_url(&self) -> Option<url::Url> {
        self.source.as_ref().map(|source| {
            let mut url = source.url.clone();
            url.set_query(None);
            url.set_fragment(None);
            crate::sources::normalize_url(&mut url);
            url
        })
    }

    #[inline]
    pub(crate) fn is_git_source(&self) -> bool {
        self.source
            .as_ref()
            .map_or(false, |src| src.source_id.is_git())
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
