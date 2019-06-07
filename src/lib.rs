#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

use failure::Error;
pub use semver::Version;
use std::path::{Path, PathBuf};

pub mod ban;
pub mod licenses;

use licenses::{LicenseField, LicenseInfo};

#[derive(serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LintLevel {
    Allow,
    Warn,
    Deny,
}

impl Default for LintLevel {
    fn default() -> Self {
        LintLevel::Warn
    }
}

#[derive(Debug)]
pub struct CrateDetails {
    pub name: String,
    pub version: Version,
    pub authors: Vec<String>,
    pub repository: Option<String>,
    pub description: Option<String>,
    pub root: Option<PathBuf>,
    pub license: LicenseField,
    pub license_file: Option<PathBuf>,
}

impl Default for CrateDetails {
    fn default() -> Self {
        Self {
            name: "".to_owned(),
            version: Version::new(0, 1, 0),
            authors: Vec::new(),
            repository: None,
            description: None,
            root: None,
            license: LicenseField::default(),
            license_file: None,
        }
    }
}

impl CrateDetails {
    pub fn new(package: cargo_metadata::Package) -> Self {
        Self {
            name: package.name,
            version: package.version,
            authors: package.authors,
            repository: package.repository,
            license: package.license.map(LicenseField::new).unwrap_or_default(),
            license_file: package.license_file,
            description: package.description,
            root: {
                let mut mp = package.manifest_path;
                mp.pop();
                Some(mp)
            },
        }
    }

    pub fn licenses(&self) -> impl Iterator<Item = LicenseInfo<'_>> {
        let root = self.root.as_ref();
        let explicit = self
            .license_file
            .as_ref()
            .and_then(|lf| root.map(|r| r.join(lf)));

        // metadata licenses + inferred licenses + explicit license

        self.license.iter().map(LicenseInfo::Metadata).chain(
            find_license_files(root)
                .filter_map(move |found_path| {
                    // If the license is specified in Cargo.toml, just
                    // skip it to differentiate between what *might* be
                    // a license vs what the crate maintainer explicitly
                    // specified *is* a license
                    if let Some(ref specified) = explicit {
                        if *specified == found_path {
                            return None;
                        }
                    }

                    Some(LicenseInfo::InferredLicenseFile(found_path))
                })
                .chain(self.license_file.iter().filter_map(move |elf| {
                    root.map(|r| LicenseInfo::ExplicitLicenseFile(r.join(elf)))
                })),
        )
    }
}

fn find_license_files(dir: Option<&PathBuf>) -> Box<dyn Iterator<Item = PathBuf>> {
    if let Some(dir) = dir {
        if let Ok(entries) = std::fs::read_dir(dir) {
            return Box::new(entries.filter_map(|e| {
                e.ok().and_then(|e| {
                    let p = e.path();
                    if p.is_file()
                        && p.file_name()
                            .and_then(|name| name.to_str().map(|name| name.starts_with("LICENSE")))
                            == Some(true)
                    {
                        Some(p)
                    } else {
                        None
                    }
                })
            }));
        }
    }

    Box::new(std::iter::empty())
}

pub fn get_all_crates<P: AsRef<Path>>(root: P) -> Result<Vec<CrateDetails>, Error> {
    let cargo_toml = root.as_ref().join("Cargo.toml");
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(cargo_toml)
        .features(cargo_metadata::CargoOpt::AllFeatures)
        .exec()
        .map_err(|e| failure::format_err!("failed to fetch metadata: {}", e))?;

    let crate_infos: Vec<_> = metadata
        .packages
        .into_iter()
        .map(CrateDetails::new)
        .collect();

    Ok(crate_infos)
}

pub fn binary_search<T, Q>(s: &[T], query: &Q) -> Result<usize, usize>
where
    T: std::borrow::Borrow<Q>,
    Q: Ord + ?Sized,
{
    s.binary_search_by(|i| i.borrow().cmp(query))
}

pub fn contains<T, Q>(s: &[T], query: &Q) -> bool
where
    T: std::borrow::Borrow<Q>,
    Q: Eq + ?Sized,
{
    s.iter().any(|i| i.borrow() == query)
}

pub fn hash(data: &[u8]) -> u32 {
    use std::hash::Hasher;
    // We use the 32-bit hash instead of the 64 even though
    // it is significantly slower due to the TOML limitation
    // if only supporting i64
    let mut xx = twox_hash::XxHash32::default();
    xx.write(data);
    xx.finish() as u32
}

pub struct CrateVersion<'a>(pub &'a semver::Version);

impl<'a> slog::Value for CrateVersion<'a> {
    fn serialize(
        &self,
        _record: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self.0))
    }
}
