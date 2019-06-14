use crate::LintLevel;
use failure::Error;
use rayon::prelude::*;
use semver::{Version, VersionReq};
use serde::Deserialize;
use slog::{debug, error, trace, warn};
use std::{collections::HashMap, fmt, path::PathBuf, sync::Arc};

const LICENSE_CACHE: &[u8] = include_bytes!("../spdx_cache.bin.zstd");

const fn lint_warn() -> LintLevel {
    LintLevel::Warn
}

const fn confidence_threshold() -> f32 {
    0.8
}

#[derive(Debug)]
pub enum LicenseFieldItem<'a> {
    License(&'a str),
    Exception(&'a str),
    UnknownLicense(&'a str),
}

#[derive(Debug, Default)]
pub struct LicenseField {
    data: String,
}

impl LicenseField {
    pub fn new(lf: String) -> Self {
        let license_expr = if lf.contains('/') {
            lf.replace("/", " OR ")
        } else {
            lf
        };

        Self { data: license_expr }
    }

    pub fn iter(&self) -> impl Iterator<Item = LicenseFieldItem<'_>> {
        license_exprs::iter_expr(&self.data).filter_map(|item| {
            Some(match item {
                Ok(license_exprs::LicenseExpr::License(l)) => LicenseFieldItem::License(l),
                Ok(license_exprs::LicenseExpr::Exception(e)) => LicenseFieldItem::Exception(e),
                Err(license_exprs::ParseError::UnknownLicenseId(id)) => {
                    LicenseFieldItem::UnknownLicense(id)
                }
                _ => return None,
            })
        })
    }
}

#[derive(Debug)]
pub enum LicenseInfo<'a> {
    Metadata(LicenseFieldItem<'a>),
    ExplicitLicenseFile(PathBuf),
    InferredLicenseFile(PathBuf),
}

#[derive(Deserialize)]
pub struct LicenseFile {
    /// The crate relative path of the LICENSE file
    pub path: PathBuf,
    /// The hash of the LICENSE text, as outputted
    /// when a license file hash mismatch occurs,
    /// to detect when the text changes between versions
    /// and needs to be verified again before using
    /// the new hash
    pub hash: u32,
}

#[derive(Deserialize)]
pub struct IgnoreLicenses {
    /// The name of the crate we are ignoring
    pub name: String,
    /// The version constraints of the crate we are ignoring
    pub version: Option<VersionReq>,
    /// Ignores certain LICENSE* files when
    /// analyzing the crate
    pub license_files: Vec<LicenseFile>,
}

#[derive(Deserialize, Debug)]
pub struct SkipCrate {
    /// The name of the crate we may skip
    pub name: String,
    /// The version constraints of the crate we may skip
    pub version: Option<VersionReq>,
    /// The license configuration that are allowed to be ignored,
    /// if this differs from the state of the crate being checked
    /// it is treated as a warning and checked fully
    #[serde(default)]
    pub licenses: Vec<String>,
    /// The exceptions that are allowed to be ignored
    #[serde(default)]
    pub exceptions: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct Config {
    /// If true, will cause failures if the license is not specified
    /// for a crate
    #[serde(default = "lint_warn")]
    pub unlicensed: LintLevel,
    /// If true, will cause failures if some kind of license is specified
    /// but it is not known, ie, is not an SDPX identifier
    #[serde(default = "lint_warn")]
    pub unknown: LintLevel,
    /// The minimum confidence threshold we allow when determining the license
    /// in a text file, on a 0.0 (none) to 1.0 (maximum) scale
    #[serde(default = "confidence_threshold")]
    pub confidence_threshold: f32,
    /// The licenses or exceptions that will cause us to emit failures
    #[serde(default)]
    pub deny: Vec<String>,
    /// If specified, allows the following licenses or exceptions, if they are not
    /// otherwise denied, including "unknown" licenses eg. proprietary ones that
    /// aren't a known SPDX license
    #[serde(default)]
    pub allow: Vec<String>,
    /// If specified, allows crates to pass the license check, even
    /// if they otherwise violate one of the other constraints, eg
    /// you want to deny unlicensed by default, especially for new
    /// crates, but you've already "manually" verified 1 or more crates
    /// you already use that are unlicensed
    #[serde(default)]
    pub skip: Vec<SkipCrate>,
    /// If specified, ignores specific license files within a crate
    #[serde(default)]
    pub ignore: Vec<IgnoreLicenses>,
}

pub struct Ignored {
    version_req: VersionReq,
    licenses: Vec<LicenseFile>,
}

impl Config {
    pub fn sort(&mut self) {
        self.deny.par_sort();
        self.allow.par_sort();
        self.skip.par_sort_by(|a, b| match a.name.cmp(&b.name) {
            std::cmp::Ordering::Equal => a.version.cmp(&b.version),
            o => o,
        });
    }

    pub fn get_skipped(&self, crate_name: &str, version: &Version) -> Option<&SkipCrate> {
        self.skip
            .binary_search_by(|ic| ic.name.as_str().cmp(crate_name))
            .ok()
            .and_then(|i| {
                for sc in &self.skip[i..] {
                    if sc.name != crate_name {
                        break;
                    }

                    match sc.version {
                        Some(ref req) => {
                            if req.matches(version) {
                                return Some(sc);
                            }
                        }
                        None => return Some(sc),
                    }
                }

                None
            })
    }

    pub fn get_ignore_licenses(&mut self) -> HashMap<String, Vec<Ignored>> {
        let ignored = std::mem::replace(&mut self.ignore, Vec::new());

        ignored.into_iter().fold(HashMap::new(), |mut hm, ic| {
            let entry = hm.entry(ic.name).or_insert_with(Vec::new);

            entry.push(Ignored {
                version_req: ic.version.unwrap_or_else(VersionReq::any),
                licenses: ic.license_files,
            });

            hm
        })
    }
}

#[derive(PartialEq, Eq)]
pub struct FileSource {
    pub path: PathBuf,
    pub hash: u32,
}

impl fmt::Debug for FileSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSource")
            .field("path", &self.path)
            .field("hash", &format_args!("{:#x}", self.hash))
            .finish()
    }
}

impl slog::Value for FileSource {
    fn serialize(
        &self,
        _record: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:#?}", self))
    }
}

fn get_file_source(path: PathBuf) -> Result<(String, FileSource), (PathBuf, std::io::Error)> {
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            return Err((path, e));
        }
    };

    let fs = FileSource {
        path,
        hash: crate::hash(content.as_bytes()),
    };

    Ok((content, fs))
}

#[derive(Debug, PartialEq, Eq)]
pub enum LicenseSource {
    /// An SPDX identifier in the Cargo.toml `license` field
    Metadata,
    /// The canonical text of the license.
    Original(FileSource),
    /// A license header. There may be more than one in a `Store`.
    Header(FileSource),
    /// An alternate form of a license. This is intended to be used for
    /// alternate _formats_ of a license, not for variants where the text has
    /// different meaning. Not currently used in askalono's SPDX dataset.
    Alternate(FileSource),
}

impl fmt::Display for LicenseSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseSource::Metadata => write!(f, "metadata"),
            LicenseSource::Original(fs) => {
                write!(f, "text={},hash={:#x}", fs.path.display(), fs.hash)
            }
            LicenseSource::Header(fs) => {
                write!(f, "header={},hash={:#x}", fs.path.display(), fs.hash)
            }
            LicenseSource::Alternate(fs) => {
                write!(f, "alt-text={},hash={:#x}", fs.path.display(), fs.hash)
            }
        }
    }
}

impl slog::Value for LicenseSource {
    fn serialize(
        &self,
        _record: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

impl From<(askalono::LicenseType, FileSource)> for LicenseSource {
    fn from(lt: (askalono::LicenseType, FileSource)) -> Self {
        match lt.0 {
            askalono::LicenseType::Original => LicenseSource::Original(lt.1),
            askalono::LicenseType::Header => LicenseSource::Header(lt.1),
            askalono::LicenseType::Alternate => LicenseSource::Alternate(lt.1),
        }
    }
}

#[derive(Debug)]
pub enum Note<'a> {
    /// A valid SPDX-identifiable license
    License {
        name: license_exprs::LicenseId,
        source: LicenseSource,
    },
    /// A license with an unknown SPDX identifier was encountered
    Unknown { name: String, source: LicenseSource },
    /// The license could not be determined with high enough confidence
    LowConfidence { score: f32, source: LicenseSource },
    /// A license file was filtered out due to matching ignore criteria
    Ignored(FileSource),
    /// A license exception
    Exception(&'a str),
    /// A license file was unreadable
    UnreadableLicense { path: PathBuf, err: String },
    /// No licenses were detected in the crate
    Unlicensed,
}

impl<'a> PartialEq for Note<'a> {
    fn eq(&self, o: &'_ Self) -> bool {
        match (self, o) {
            (Note::Unlicensed, Note::Unlicensed) => true,
            (
                Note::License { name, source },
                Note::License {
                    name: name1,
                    source: source1,
                },
            ) => name == name1 && source == source1,
            (
                Note::Unknown { name, source },
                Note::Unknown {
                    name: name1,
                    source: source1,
                },
            ) => name == name1 && source == source1,
            (
                Note::LowConfidence { source, .. },
                Note::LowConfidence {
                    source: source1, ..
                },
            ) => source == source1,
            (Note::Exception(exc), Note::Exception(exc1)) => exc == exc1,
            (
                Note::UnreadableLicense { path, err },
                Note::UnreadableLicense {
                    path: path1,
                    err: err1,
                },
            ) => path == path1 && err == err1,
            (Note::Ignored(fs), Note::Ignored(fs1)) => fs == fs1,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct CrateNote<'a> {
    pub name: &'a str,
    pub version: Version,
    pub notes: Vec<Note<'a>>,
}

impl<'a> slog::Value for CrateNote<'a> {
    fn serialize(
        &self,
        _record: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}@{}", self.name, self.version))
    }
}

pub struct Summary<'a> {
    notes: Vec<CrateNote<'a>>,
    store: Arc<LicenseStore>,
}

impl<'a> Summary<'a> {
    fn new(store: Arc<LicenseStore>) -> Self {
        Self {
            notes: Vec::new(),
            store,
        }
    }

    pub fn notes(&self) -> impl Iterator<Item = &CrateNote<'_>> {
        self.notes.iter()
    }

    #[inline]
    pub fn resolve_id(id: license_exprs::LicenseId) -> &'static str {
        license_exprs::license_name(id)
    }
}

/// Store used to identify licenses from text files
pub struct LicenseStore {
    store: askalono::Store,
}

impl LicenseStore {
    pub fn from_cache() -> Result<Self, Error> {
        let store = askalono::Store::from_cache(LICENSE_CACHE)?;

        Ok(Self { store })
    }
}

impl Default for LicenseStore {
    fn default() -> Self {
        Self {
            store: askalono::Store::new(),
        }
    }
}

pub struct Gatherer {
    log: slog::Logger,
    store: Arc<LicenseStore>,
    threshold: f32,
}

impl Default for Gatherer {
    fn default() -> Self {
        Self {
            log: slog::Logger::root(slog::Discard, slog::o!()),
            store: Arc::new(LicenseStore::default()),
            threshold: 0.8,
        }
    }
}

impl Gatherer {
    pub fn new(log: slog::Logger) -> Self {
        Self {
            log,
            ..Default::default()
        }
    }

    pub fn with_store(mut self, store: Arc<LicenseStore>) -> Self {
        self.store = store;
        self
    }

    pub fn with_confidence_threshold(mut self, threshold: f32) -> Self {
        self.threshold = if threshold > 1.0 {
            1.0
        } else if threshold < 0.0 {
            0.0
        } else {
            threshold
        };
        self
    }

    pub fn gather<H: std::hash::BuildHasher>(
        self,
        crates: &[crate::CrateDetails],
        ignored: HashMap<String, Vec<Ignored>, H>,
    ) -> Summary<'_> {
        let log = self.log;
        let mut summary = Summary::new(self.store);

        let strategy = askalono::ScanStrategy::new(&summary.store.store)
            .mode(askalono::ScanMode::Elimination)
            .confidence_threshold(self.threshold) // May want to set this higher, or expose it as a config option
            .optimize(false)
            .max_passes(1);

        for crat in crates {
            let mut checked_licenses = 0;
            let mut note = CrateNote {
                name: &crat.name,
                notes: Vec::new(),
                version: crat.version.clone(),
            };

            let maybe_ignored = ignored.get(&crat.name).and_then(|ignored| {
                ignored
                    .iter()
                    .find(|ic| ic.version_req.matches(&crat.version))
            });

            let log = log.new(slog::o!("crate" => format!("{}@{}", crat.name, crat.version)));

            for license in crat.licenses() {
                checked_licenses += 1;
                match license {
                    LicenseInfo::Metadata(md) => match md {
                        LicenseFieldItem::License(l) => {
                            trace!(log, "found license in metadata"; "name" => l);

                            note.notes.push(license_exprs::license_id(l).map_or_else(
                                || Note::Unknown {
                                    name: l.to_owned(),
                                    source: LicenseSource::Metadata,
                                },
                                |id| Note::License {
                                    name: id,
                                    source: LicenseSource::Metadata,
                                },
                            ));
                        }
                        LicenseFieldItem::Exception(e) => {
                            trace!(log, "found exception in metadata"; "exc" => e);
                            note.notes.push(Note::Exception(e))
                        }
                        LicenseFieldItem::UnknownLicense(l) => {
                            trace!(log, "found unknown license in metadata"; "name" => l);

                            note.notes.push(Note::Unknown {
                                name: l.to_owned(),
                                source: LicenseSource::Metadata,
                            });
                        }
                    },
                    LicenseInfo::ExplicitLicenseFile(path)
                    | LicenseInfo::InferredLicenseFile(path) => {
                        trace!(log, "reading license from path"; "path" => path.display());

                        match get_file_source(path) {
                            Ok((license_text, fs)) => {
                                if let Some(ref ignored) = maybe_ignored {
                                    if let Some(lf) = ignored
                                        .licenses
                                        .iter()
                                        .find(|lf| lf.path.file_name() == fs.path.file_name())
                                    {
                                        if fs.hash == lf.hash {
                                            checked_licenses -= 1;
                                            note.notes.push(Note::Ignored(fs));
                                            continue;
                                        }
                                    }
                                }

                                let text = askalono::TextData::new(&license_text);
                                match strategy.scan(&text) {
                                    Ok(match_) => {
                                        let lnote = match match_.license {
                                            Some(identified) => {
                                                trace!(log, "license file identified"; "path" => fs.path.display(), "name" => identified.name);

                                                match license_exprs::license_id(identified.name) {
                                                    Some(id) => Note::License {
                                                        name: id,
                                                        source: (identified.kind, fs).into(),
                                                    },
                                                    None => Note::Unknown {
                                                        name: identified.name.to_owned(),
                                                        source: (identified.kind, fs).into(),
                                                    },
                                                }
                                            }
                                            None => Note::LowConfidence {
                                                score: match_.score,
                                                source: LicenseSource::Original(fs),
                                            },
                                        };

                                        note.notes.push(lnote);
                                    }
                                    Err(e) => {
                                        // the elimination strategy can't currently fail
                                        unimplemented!("{}", e);
                                    }
                                }
                            }
                            Err((path, err)) => {
                                note.notes.push(Note::UnreadableLicense {
                                    path,
                                    err: format!("{}", err),
                                });
                            }
                        }
                    }
                }
            }

            if checked_licenses == 0 {
                note.notes.push(Note::Unlicensed);
            }

            summary.notes.push(note);
        }

        summary
    }
}

#[allow(clippy::cognitive_complexity)]
pub fn check_licenses(log: slog::Logger, summary: Summary<'_>, cfg: &Config) -> Result<(), Error> {
    use crate::{binary_search, contains};
    let mut warnings = 0;
    let mut errors = 0;

    for crate_note in summary.notes() {
        // Check the list of crates the user wishes to skip to ensure it meets
        // the criteria, otherwise we treat it as normal
        if let Some(ic) = cfg.get_skipped(crate_note.name, &crate_note.version) {
            debug!(
                log,
                "checking skipped crate";
                "crate" => crate_note,
            );

            let missing_license = ic.licenses.iter().any(|i| {
                match crate_note.notes.iter().find(|n| match n {
                    Note::License { name, .. } => {
                        let license_name = Summary::resolve_id(*name);
                        license_name == i
                    }
                    _ => false,
                }) {
                    Some(_) => false,
                    None => {
                        warn!(
                            log,
                            "crate no longer skipped due to license not being present in the crate";
                            "crate" => crate_note,
                            "license" => i,
                        );
                        warnings += 1;
                        true
                    }
                }
            });
            let missing_exception = ic.exceptions.iter().any(|i| {
                match crate_note.notes.iter().find(|n| match n {
                    Note::Exception(e) => e == i,
                    _ => false,
                }) {
                    Some(_) => false,
                    None => {
                        warn!(
                            log,
                            "crate no longer skipped due to exception not being present in crate";
                            "crate" => crate_note,
                            "exception" => i,
                        );
                        warnings += 1;
                        true
                    }
                }
            });

            if !missing_exception && !missing_license {
                let mismatch = crate_note.notes.iter().any(|note| {
                    match note {
                        Note::License { name, source} => {
                            let license_name = Summary::resolve_id(*name);

                            if !contains(&ic.licenses, license_name) {
                                warn!(
                                    log,
                                    "crate no longer skipped due to additional license";
                                    "crate" => crate_note,
                                    "license" => license_name,
                                    "src" => source,
                                );
                                warnings += 1;
                                return true;
                            }
                        }
                        Note::Exception(e) => {
                            if !contains(&ic.exceptions, *e) {
                                warn!(
                                    log,
                                    "crate no longer skipped due to additional exception";
                                    "crate" => crate_note,
                                    "exception" => e,
                                );
                                warnings += 1;
                                return true;
                            }
                        }
                        Note::LowConfidence { source, .. } => {
                            warn!(
                                log,
                                "crate no longer skipped due to finding a license that could be identified";
                                "crate" => crate_note,
                                "src" => source,
                            );
                            warnings += 1;
                            return true;
                        }
                        Note::Unlicensed => {
                            if !ic.licenses.is_empty() || !ic.exceptions.is_empty() {
                                warn!(
                                    log,
                                    "crate no longer skipped due to no licenses or exceptions found";
                                    "crate" => crate_note,
                                );
                                warnings += 1;
                                return true;
                            }
                        }
                        _ => {}
                    };

                    false
                });

                if !mismatch {
                    debug!(
                        log,
                        "skipping crate";
                        "crate" => crate_note,
                    );
                    continue;
                }
            }
        }

        for note in &crate_note.notes {
            match note {
                Note::License { name, source } => {
                    let license_name = Summary::resolve_id(*name);

                    if binary_search(&cfg.deny, license_name).is_ok() {
                        error!(
                            log,
                            "detected a denied license";
                            "crate" => crate_note,
                            "license" => license_name,
                            "src" => source,
                        );
                        errors += 1;
                    } else if !cfg.allow.is_empty()
                        && binary_search(&cfg.allow, license_name).is_err()
                    {
                        error!(
                            log,
                            "detected a license not explicitly allowed";
                            "crate" => crate_note,
                            "license" => license_name,
                            "src" => source,
                        );
                        errors += 1;
                    }
                }
                Note::Unlicensed => {
                    match cfg.unlicensed {
                        LintLevel::Allow => continue,
                        LintLevel::Warn => {
                            warnings += 1;
                            warn!(log, "could not find any license information"; "crate" => crate_note);
                        }
                        LintLevel::Deny => {
                            errors += 1;
                            error!(log, "could not find any license information"; "crate" => crate_note);
                        }
                    };
                }
                Note::Exception(e) => {
                    if binary_search(&cfg.deny, *e).is_ok() {
                        error!(
                            log,
                            "detected a denied exception";
                            "crate" => crate_note,
                            "exception" => e,
                        );
                        errors += 1;
                    } else if !cfg.allow.is_empty() && binary_search(&cfg.allow, *e).is_err() {
                        error!(
                            log,
                            "detected an exception not explicitly allowed";
                            "crate" => crate_note,
                            "exception" => e,
                        );
                        errors += 1;
                    }
                }
                Note::Unknown { name, source } => {
                    if binary_search(&cfg.allow, name).is_ok() {
                        continue;
                    }

                    match cfg.unknown {
                        LintLevel::Allow => continue,
                        LintLevel::Warn => {
                            warnings += 1;
                            warn!(
                                log,
                                "detected an unknown license";
                                "crate" => crate_note,
                                "license" => name,
                                "src" => source,
                            );
                        }
                        LintLevel::Deny => {
                            errors += 1;
                            error!(
                                log,
                                "detected an unknown license";
                                "crate" => crate_note,
                                "license" => name,
                                "src" => source,
                            );
                        }
                    };
                }
                Note::LowConfidence { score, source } => {
                    error!(
                        log,
                        "unable to determine license with high confidence";
                        "crate" => crate_note,
                        "score" => score,
                        "src" => source,
                    );
                    errors += 1;
                }
                Note::UnreadableLicense { path, err } => {
                    error!(
                        log,
                        "license file is unreadable";
                        "crate" => crate_note,
                        "path" => path.display(),
                        "err" => err.to_string(), // io::Error makes slog sad
                    );
                    errors += 1;
                }
                Note::Ignored(fs) => {
                    debug!(
                        log,
                        "ignored license file";
                        "crate" => crate_note,
                        "src" => fs,
                    );
                }
            }
        }
    }

    if warnings > 0 {
        warn!(log, "encountered {} license warnings", warnings);
    }

    if errors > 0 {
        error!(log, "encountered {} license errors", errors);
        failure::bail!("failed license check");
    }

    Ok(())
}
