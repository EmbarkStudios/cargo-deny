//! # ❌ cargo-deny
//!
//! [![Build Status](https://github.com/EmbarkStudios/cargo-deny/workflows/CI/badge.svg)](https://github.com/EmbarkStudios/cargo-deny/actions?workflow=CI)
//! [![Latest version](https://img.shields.io/crates/v/cargo-deny.svg)](https://crates.io/crates/cargo-deny)
//! [![Docs](https://img.shields.io/badge/docs-The%20Book-green.svg)](https://embarkstudios.github.io/cargo-deny/)
//! [![API Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)
//! [![SPDX Version](https://img.shields.io/badge/SPDX%20Version-3.11-blue.svg)](https://spdx.org/licenses/)
//! [![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
//! [![Embark](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](http://embark.dev)
//!
//! `cargo-deny` is a cargo plugin for linting your dependencies. See the [book 📖](https://embarkstudios.github.io/cargo-deny/) for in-depth documentation.
//!
//! ## [Quickstart](https://embarkstudios.github.io/cargo-deny/)
//!
//! ```bash
//! cargo install --locked cargo-deny && cargo deny init && cargo deny check
//! ```
//!
//! ## Usage
//!
//! ### [Install](https://embarkstudios.github.io/cargo-deny/cli/index.html) cargo-deny
//!
//! ```bash
//! cargo install --locked cargo-deny
//! ```
//!
//! ### [Initialize](https://embarkstudios.github.io/cargo-deny/cli/init.html) your project
//!
//! ```bash
//! cargo deny init
//! ```
//!
//! ### [Check](https://embarkstudios.github.io/cargo-deny/cli/check.html) your crates
//!
//! ```bash
//! cargo deny check
//! ```
//!
//! #### [Licenses](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html)
//!
//! The licenses check is used to verify that every crate you use has license terms you find acceptable.
//!
//! ```bash
//! cargo deny check licenses
//! ```
//!
//! #### [Bans](https://embarkstudios.github.io/cargo-deny/checks/bans/index.html)
//!
//! The bans check is used to deny (or allow) specific crates, as well as detect and handle multiple versions of the same crate.
//!
//! ```bash
//! cargo deny check bans
//! ```
//!
//! #### [Advisories](https://embarkstudios.github.io/cargo-deny/checks/advisories/index.html)
//!
//! The advisories check is used to detect issues for crates by looking in an advisory database.
//!
//! ```bash
//! cargo deny check advisories
//! ```
//!
//! #### [Sources](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html)
//!
//! The sources check ensures crates only come from sources you trust.
//!
//! ```bash
//! cargo deny check sources
//! ```

// BEGIN - Embark standard lints v0.3
// do not change or add/remove here, but one can add exceptions after this section
// for more info see: <https://github.com/EmbarkStudios/rust-ecosystem/issues/59>
#![deny(unsafe_code)]
#![warn(
    clippy::all,
    clippy::await_holding_lock,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::explicit_into_iter_loop,
    clippy::filter_map_next,
    clippy::fn_params_excessive_bools,
    clippy::if_let_mutex,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::large_types_passed_by_value,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::map_err_ignore,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::option_option,
    clippy::pub_enum_variant_names,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_to_string,
    clippy::suboptimal_flops,
    clippy::todo,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::verbose_file_reads,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]
// END - Embark standard lints v0.3

pub use semver::Version;
use std::{cmp, collections::HashMap, fmt};

pub mod advisories;
pub mod bans;
mod cfg;
pub mod diag;
mod index;
/// Configuration and logic for checking crate licenses
pub mod licenses;
pub mod manifest;
pub mod sources;

pub use cfg::{Spanned, UnvalidatedConfig};
use krates::cm;
pub use krates::{DepKind, Kid, Utf8PathBuf};
pub use rustsec::package::source::SourceId;

/// The possible lint levels for the various lints. These function similarly
/// to the standard [Rust lint levels](https://doc.rust-lang.org/rustc/lints/levels.html)
#[derive(serde::Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LintLevel {
    /// A debug or info diagnostic _may_ be emitted if the lint is violated
    Allow,
    /// A warning will be emitted if the lint is violated, but the command
    /// will succeed
    Warn,
    /// An error will be emitted if the lint is violated, and the command
    /// will fail with a non-zero exit code
    Deny,
}

impl Default for LintLevel {
    fn default() -> Self {
        LintLevel::Warn
    }
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
pub struct Krate {
    pub name: String,
    pub id: Kid,
    pub version: Version,
    pub source: Option<SourceId>,
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
                // rustsec's SourceId has better introspection
                pkg.source.and_then(|src| {
                    let url = format!("{}", src);
                    SourceId::from_url(&url).map_or_else(
                        |e| {
                            log::warn!("unable to parse source url '{}': {}", url, e);
                            None
                        },
                        Some,
                    )
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
}
