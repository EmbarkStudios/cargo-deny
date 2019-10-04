use crate::{KrateDetails, LintLevel};
use codespan_reporting::diagnostic::{Diagnostic, Label, Severity};
use failure::Error;
use rayon::prelude::*;
use semver::VersionReq;
use serde::Deserialize;
use smallvec::SmallVec;
use spdx::Licensee;
use std::{
    cmp, fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

const LICENSE_CACHE: &[u8] = include_bytes!("../spdx_cache.bin.gz");

const fn lint_deny() -> LintLevel {
    LintLevel::Deny
}

const fn confidence_threshold() -> f32 {
    0.8
}

#[derive(Deserialize)]
pub struct Clarification {
    pub name: String,
    pub version: Option<VersionReq>,
    pub expression: toml::Spanned<String>,
    #[serde(default, rename = "license-files")]
    pub license_files: Vec<FileSource>,
}

pub struct ValidClarification {
    pub name: String,
    pub version: VersionReq,
    pub expr_offset: u32,
    pub expression: spdx::Expression,
    pub license_files: Vec<FileSource>,
}

impl Ord for ValidClarification {
    fn cmp(&self, o: &Self) -> cmp::Ordering {
        match self.name.cmp(&o.name) {
            cmp::Ordering::Equal => self.version.cmp(&o.version),
            o => o,
        }
    }
}

impl PartialOrd for ValidClarification {
    fn partial_cmp(&self, o: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl PartialEq for ValidClarification {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == cmp::Ordering::Equal
    }
}

impl Eq for ValidClarification {}

#[inline]
fn iter_clarifications<'a>(
    all: &'a [ValidClarification],
    krate: &'a KrateDetails,
) -> impl Iterator<Item = &'a ValidClarification> {
    all.iter().filter(move |vc| {
        if vc.name == krate.name {
            return vc.version.matches(&krate.version);
        }

        false
    })
}

/// Allows agreement of licensing terms based on whether the license is
/// [OSI Approved](https://opensource.org/licenses) or [considered free](
/// https://www.gnu.org/licenses/license-list.en.html) by the FSF
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlanketAgreement {
    /// The license must be both OSI Approved and FSF/Free Libre
    Both,
    /// The license can be be either OSI Approved or FSF/Free Libre
    Either,
    /// The license must be OSI Approved but not FSF/Free Libre
    OsiOnly,
    /// The license must be FSF/Free Libre but not OSI Approved
    FsfOnly,
    /// The license is not regarded specially
    Neither,
}

impl Default for BlanketAgreement {
    fn default() -> Self {
        BlanketAgreement::Neither
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Determines what happens when license information cannot be
    /// determined for a crate
    #[serde(default = "lint_deny")]
    pub unlicensed: LintLevel,
    /// Agrees to licenses based on whether they are OSI Approved
    /// or FSF/Free Libre
    #[serde(default)]
    pub allow_osi_fsf_free: BlanketAgreement,
    /// The minimum confidence threshold we allow when determining the license
    /// in a text file, on a 0.0 (none) to 1.0 (maximum) scale
    #[serde(default = "confidence_threshold")]
    pub confidence_threshold: f32,
    /// Licenses that will be rejected in a license expression
    #[serde(default)]
    pub deny: Vec<toml::Spanned<String>>,
    /// Licenses that will be allowed in a license expression
    #[serde(default)]
    pub allow: Vec<toml::Spanned<String>>,
    /// Overrides the license expression used for a particular crate as long as it
    /// exactly matches the specified license files and hashes
    #[serde(default)]
    pub clarify: Vec<Clarification>,
}

impl Config {
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
    ) -> Result<ValidConfig, Vec<codespan_reporting::diagnostic::Diagnostic>> {
        let mut diagnostics = Vec::new();

        let mut parse_license =
            |l: &toml::Spanned<String>, v: &mut Vec<Licensee>| match Licensee::parse(l.get_ref()) {
                Ok(l) => v.push(l),
                Err(pe) => {
                    let offset = (l.start() + 1) as u32;
                    let span = pe.span.start as u32 + offset..pe.span.end as u32 + offset;
                    let diag = Diagnostic::new_error(
                        "invalid licensee",
                        Label::new(cfg_file, span, format!("{}", pe.reason)),
                    );

                    diagnostics.push(diag);
                }
            };

        let mut denied = Vec::with_capacity(self.deny.len());
        for d in &self.deny {
            parse_license(d, &mut denied);
        }

        let mut allowed: Vec<Licensee> = Vec::with_capacity(self.allow.len());
        for a in &self.allow {
            parse_license(a, &mut allowed);
        }

        denied.par_sort();
        allowed.par_sort();

        // Ensure the config doesn't contain the same exact license as
        // both denied and allowed, that's confusing and probably
        // not intended, so they should pick one
        for (di, d) in denied.iter().enumerate() {
            if let Ok(ai) = allowed.binary_search(&d) {
                let dlabel = Label::new(
                    cfg_file,
                    self.deny[di].start() as u32..self.deny[di].end() as u32,
                    "marked as `deny`",
                );
                let alabel = Label::new(
                    cfg_file,
                    self.allow[ai].start() as u32..self.allow[ai].end() as u32,
                    "marked as `allow`",
                );

                // Put the one that occurs last as the primary label to make it clear
                // that the first one was "ok" until we noticed this other one
                let diag = if dlabel.span.start() > alabel.span.start() {
                    Diagnostic::new_error(
                        "a license id was specified in both `allow` and `deny`",
                        dlabel,
                    )
                    .with_secondary_labels(std::iter::once(alabel))
                } else {
                    Diagnostic::new_error(
                        "a license id was specified in both `allow` and `deny`",
                        alabel,
                    )
                    .with_secondary_labels(std::iter::once(dlabel))
                };

                diagnostics.push(diag);
            }
        }

        let mut clarifications = Vec::with_capacity(self.clarify.len());
        for c in self.clarify {
            let expr = match spdx::Expression::parse(c.expression.get_ref()) {
                Ok(validated) => validated,
                Err(err) => {
                    let offset = (c.expression.start() + 1) as u32;
                    let expr_span = offset + err.span.start as u32..offset + err.span.end as u32;

                    diagnostics.push(Diagnostic::new_error(
                        "unable to parse license expression",
                        Label::new(cfg_file, expr_span, format!("{}", err.reason)),
                    ));

                    continue;
                }
            };

            let mut license_files = c.license_files;
            license_files.sort_by(|a, b| a.path.cmp(&b.path));

            clarifications.push(ValidClarification {
                name: c.name,
                version: c.version.unwrap_or_else(VersionReq::any),
                expr_offset: (c.expression.start() + 1) as u32,
                expression: expr,
                license_files,
            });
        }

        clarifications.par_sort();

        if !diagnostics.is_empty() {
            Err(diagnostics)
        } else {
            Ok(ValidConfig {
                file_id: cfg_file,
                unlicensed: self.unlicensed,
                allow_osi_fsf_free: self.allow_osi_fsf_free,
                confidence_threshold: self.confidence_threshold,
                clarifications,
                denied,
                allowed,
            })
        }
    }
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,
    pub unlicensed: LintLevel,
    pub allow_osi_fsf_free: BlanketAgreement,
    pub confidence_threshold: f32,
    pub denied: Vec<Licensee>,
    pub allowed: Vec<Licensee>,
    pub clarifications: Vec<ValidClarification>,
}

#[derive(PartialEq, Eq, Deserialize)]
pub struct FileSource {
    /// The crate relative path of the LICENSE file
    pub path: PathBuf,
    /// The hash of the LICENSE text
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

fn find_license_files(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let entries = std::fs::read_dir(dir)?;
    Ok(entries
        .filter_map(|e| {
            e.ok().and_then(|e| {
                let p = e.path();
                let file_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if p.is_file() && file_name.starts_with("LICENSE") {
                    Some(p)
                } else {
                    None
                }
            })
        })
        .collect())
}

fn get_file_source(path: PathBuf) -> PackFile {
    use std::io::BufRead;

    // Normalize on plain newlines to handle terrible Windows conventions
    let content = {
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                return PackFile {
                    path,
                    data: PackFileData::Bad(e),
                }
            }
        };

        let mut s =
            String::with_capacity(file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0));

        let mut br = std::io::BufReader::new(file);
        let mut min = 0;

        while let Ok(read) = br.read_line(&mut s) {
            if read == 0 {
                break;
            }

            let keep = std::cmp::max(s.trim_end_matches(|p| p == '\r' || p == '\n').len(), min);
            s.truncate(keep);
            s.push('\n');

            min = keep + 1;
        }

        s
    };

    let hash = crate::hash(content.as_bytes());
    PackFile {
        path,
        data: PackFileData::Good(LicenseFile { hash, content }),
    }
}

struct LicenseFile {
    hash: u32,
    content: String,
}

enum PackFileData {
    Good(LicenseFile),
    Bad(std::io::Error),
}

struct PackFile {
    path: PathBuf,
    data: PackFileData,
}

struct LicensePack {
    license_files: Vec<PackFile>,
    err: Option<std::io::Error>,
}

impl LicensePack {
    fn read(krate: &KrateDetails) -> Self {
        let root_path = krate.manifest_path.parent().unwrap();

        let mut lic_paths = match find_license_files(root_path) {
            Ok(paths) => paths,
            Err(e) => {
                return Self {
                    license_files: Vec::new(),
                    err: Some(e),
                }
            }
        };

        // Add the explicitly specified license if it wasn't
        // already found in the root directory
        if let Some(ref lf) = krate.license_file {
            if lic_paths.iter().find(|l| l.ends_with(lf)).is_none() {
                lic_paths.push(lf.clone());
            }
        }

        let mut license_files: Vec<_> = lic_paths.into_iter().map(get_file_source).collect();

        license_files.sort_by(|a, b| a.path.cmp(&b.path));

        Self {
            license_files,
            err: None,
        }
    }

    fn matches(&self, hashes: &[FileSource]) -> bool {
        if self.license_files.len() != hashes.len() {
            return false;
        }

        for (expected, actual) in self.license_files.iter().zip(hashes.iter()) {
            if !expected.path.ends_with(&actual.path) {
                return false;
            }

            match &expected.data {
                PackFileData::Bad(_) => {
                    return false;
                }
                PackFileData::Good(lf) => {
                    if lf.hash != actual.hash {
                        return false;
                    }
                }
            }
        }

        true
    }

    fn get_expression(
        &self,
        krate: &KrateDetails,
        file: codespan::FileId,
        strat: &askalono::ScanStrategy<'_>,
        confidence: f32,
    ) -> Result<(String, spdx::Expression), (String, Vec<Label>)> {
        use std::fmt::Write;

        let mut expr = String::new();
        let mut lic_count = 0;

        let mut synth_toml = String::new();
        if let Some(ref err) = self.err {
            write!(synth_toml, "license-files = \"{}\"", err).unwrap();
            let len = synth_toml.len() as u32;
            return Err((
                synth_toml,
                vec![Label::new(
                    file,
                    17..len - 1,
                    "unable to gather license files",
                )],
            ));
        }

        let mut fails = Vec::new();
        synth_toml.push_str("license-files = [\n");

        let root_path = krate.manifest_path.parent().unwrap();

        for lic_contents in &self.license_files {
            write!(
                synth_toml,
                "    {{ path = \"{}\", ",
                lic_contents.path.strip_prefix(root_path).unwrap().display(),
            )
            .unwrap();

            match &lic_contents.data {
                PackFileData::Good(data) => {
                    write!(synth_toml, "hash = 0x{:08x}, ", data.hash).unwrap();

                    let text = askalono::TextData::new(&data.content);
                    match strat.scan(&text) {
                        Ok(lic_match) => {
                            match lic_match.license {
                                Some(identified) => {
                                    // askalano doesn't report any matches below the confidence threshold
                                    // but we want to see what it thinks the license is if the confidence
                                    // is somewhat ok at least
                                    if lic_match.score >= confidence {
                                        match spdx::license_id(&identified.name) {
                                            Some(id) => {
                                                if lic_count > 0 {
                                                    expr.push_str(" AND ");
                                                }

                                                expr.push_str(id.name);
                                                lic_count += 1;
                                            }
                                            None => {
                                                write!(
                                                    synth_toml,
                                                    "score = {:.2}",
                                                    lic_match.score
                                                )
                                                .unwrap();
                                                let start = synth_toml.len() as u32;
                                                write!(
                                                    synth_toml,
                                                    ", license = \"{}\"",
                                                    identified.name
                                                )
                                                .unwrap();
                                                let end = synth_toml.len() as u32;

                                                fails.push(Label::new(
                                                    file,
                                                    start + 13..end - 1,
                                                    "unknown SPDX identifier",
                                                ));
                                            }
                                        }
                                    } else {
                                        let start = synth_toml.len() as u32;
                                        write!(synth_toml, "score = {:.2}", lic_match.score)
                                            .unwrap();
                                        let end = synth_toml.len() as u32;
                                        write!(synth_toml, ", license = \"{}\"", identified.name)
                                            .unwrap();

                                        fails.push(Label::new(
                                            file,
                                            start + 8..end,
                                            "low confidence in the license text",
                                        ));
                                    }
                                }
                                None => {
                                    // If the license can't be matched with high enough confidence
                                    let start = synth_toml.len() as u32;
                                    write!(synth_toml, "score = {:.2}", lic_match.score).unwrap();
                                    let end = synth_toml.len() as u32;

                                    fails.push(Label::new(
                                        file,
                                        start + 8..end,
                                        "low confidence in the license text",
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            // the elimination strategy can't currently fail
                            unimplemented!(
                                "I guess askalano's elimination strategy can now fail: {}",
                                e
                            );
                        }
                    }
                }
                PackFileData::Bad(err) => {
                    let start = synth_toml.len() as u32;
                    write!(synth_toml, "err = \"{}\"", err).unwrap();
                    let end = synth_toml.len() as u32;

                    fails.push(Label::new(
                        file,
                        start + 7..end - 1,
                        "unable to read license file",
                    ));
                }
            }

            writeln!(synth_toml, " }},").unwrap();
        }

        synth_toml.push_str("]");

        if fails.is_empty() {
            Ok((synth_toml, spdx::Expression::parse(&expr).unwrap()))
        } else {
            Err((synth_toml, fails))
        }
    }
}

#[derive(Debug)]
pub struct LicenseExprInfo {
    file_id: codespan::FileId,
    offset: u32,
    pub source: LicenseExprSource,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LicenseExprSource {
    /// An SPDX expression in the Cargo.toml `license` field
    Metadata,
    /// An override in the user's deny.toml
    UserOverride,
    /// An override from an overlay
    OverlayOverride,
    /// An expression synthesized from one or more LICENSE files
    LicenseFiles,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LicenseInfo {
    /// An SPDX expression parsed or generated from the
    /// license information provided by a crate
    SPDXExpression {
        expr: spdx::Expression,
        nfo: LicenseExprInfo,
    },
    /// No licenses were detected in the crate
    Unlicensed,
}

#[derive(Debug)]
pub struct KrateLicense<'a> {
    pub krate: &'a KrateDetails,
    pub lic_info: LicenseInfo,

    // Reasons for why the license was determined (or not!) when
    // gathering the license information
    labels: SmallVec<[Label; 1]>,
}

pub struct Summary<'a> {
    store: Arc<LicenseStore>,
    pub nfos: Vec<KrateLicense<'a>>,
}

impl<'a> Summary<'a> {
    fn new(store: Arc<LicenseStore>) -> Self {
        Self {
            store,
            nfos: Vec::new(),
        }
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
    store: Arc<LicenseStore>,
    threshold: f32,
}

impl Default for Gatherer {
    fn default() -> Self {
        Self {
            store: Arc::new(LicenseStore::default()),
            threshold: 0.8,
        }
    }
}

#[inline]
fn get_toml_span(key: &'static str, content: &str) -> std::ops::Range<u32> {
    let mut offset = 0;
    let val_start = loop {
        let start = content[offset..].find('\n').unwrap() + 1;
        if content[start + offset..].starts_with(key) {
            break start + offset + key.len();
        }

        offset += start;
    };

    let val_end = content[val_start..].find("\"\n").unwrap();

    let start = val_start as u32 + 4;
    start..start + val_end as u32 - 4
}

impl Gatherer {
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

    pub fn gather<'k>(
        self,
        krates: &'k [crate::KrateDetails],
        files: &mut codespan::Files,
        cfg: Option<&ValidConfig>,
    ) -> Summary<'k> {
        let mut summary = Summary::new(self.store);

        let threshold = self.threshold;

        let strategy = askalono::ScanStrategy::new(&summary.store.store)
            .mode(askalono::ScanMode::Elimination)
            .confidence_threshold(0.5)
            .optimize(false)
            .max_passes(1);

        let files_lock = std::sync::Arc::new(std::sync::RwLock::new(files));

        // Retrieve the license expression we'll use to evaluate the user's overall
        // constraints with.
        //
        // NOTE: The reason that user/overalay overrides are prioritized over the
        // expression that may be present in the crate's `license` field itself is
        // because that expression is currently limited in functionality to basic
        // tokenization and thus might not be able to express the actual licensing
        // used by a crate, which often means the expression is either not provided
        // at all, or is actually inaccurate with regards to the actual licensing
        // terms of the crate.
        //
        // When falling back to full-text license files to obtain the possible
        // licenses used by a crate, we create a license expression where all
        // licenses found are joined with the `AND` operator, which means that
        // the user must comply with **ALL** licenses. This is the conservative
        // approach to ensure a (possibly) required license is not introduced which
        // could potentially be ignored if 1 or more other license requirements
        // were met that the user actually intended.
        //
        // 1. User overrides - If the user specifies the license expression and
        // the constraints for the package still match the current one being checked
        // 2. Overlay overrides - If the user has specified an overlay, and it contains
        // information for the crate and the constraints for the package still
        // match the current one being checked
        // 3. `license`
        // 4. `license-file` + all LICENSE(-*)? files - Due to the prevalance
        // of dual-licensing in the rust ecosystem, many people forgo setting
        // license-file, so we use it and/or any LICENSE files
        krates
            .par_iter()
            .map(|krate| {
                // Attempt an SPDX expression that we can validate the user's acceptable
                // license terms with
                let mut synth_id = None;

                let mut labels = smallvec::SmallVec::<[Label; 1]>::new();

                let mut get_span = |key: &'static str| -> (codespan::FileId, std::ops::Range<u32>) {
                    match synth_id {
                        Some(id) => {
                            let l = files_lock.read().unwrap();
                            (synth_id.unwrap(), get_toml_span(key, l.source(id)))
                        }
                        None => {
                            // Synthesize a minimal Cargo.toml for reporting diagnostics
                            // for where we retrieved license stuff
                            let synth_manifest = format!(
                                "[package]\nname = \"{}\"\nversion = \"{}\"\nlicense = \"{}\"\n",
                                krate.name,
                                krate.version,
                                krate.license.as_ref().map(|s| s.as_str()).unwrap_or(""),
                            );

                            {
                                let mut fl = files_lock.write().unwrap();
                                synth_id = Some(fl.add(krate.id.repr.clone(), synth_manifest));
                                (
                                    synth_id.unwrap(),
                                    get_toml_span(key, fl.source(synth_id.unwrap())),
                                )
                            }
                        }
                    }
                };

                let mut license_pack = None;

                // 1
                if let Some(ref cfg) = cfg {
                    for clarification in iter_clarifications(&cfg.clarifications, krate) {
                        let lp = match license_pack {
                            Some(ref lp) => lp,
                            None => {
                                license_pack = Some(LicensePack::read(krate));
                                license_pack.as_ref().unwrap()
                            }
                        };

                        // pub name: String,
                        // pub version: VersionReq,
                        // pub expression: spdx::Expression,
                        // pub license_files: Vec<FileSource>,
                        // Check to see if the clarification provided exactly matches
                        // the set of detected licenses, if they do, we use the clarification's
                        // license expression as the license requirement's for this crate
                        if lp.matches(&clarification.license_files) {
                            return KrateLicense {
                                krate,
                                lic_info: LicenseInfo::SPDXExpression {
                                    expr: clarification.expression.clone(),
                                    nfo: LicenseExprInfo {
                                        file_id: cfg.file_id,
                                        offset: clarification.expr_offset,
                                        source: LicenseExprSource::UserOverride,
                                    },
                                },
                                labels,
                            };
                        }
                    }
                }

                // 2 TODO

                // 3
                match &krate.license {
                    Some(license_field) => {
                        // Reasons this can fail:
                        // * Empty! The rust crate used to validate this field has a bug
                        // https://github.com/rust-lang-nursery/license-exprs/issues/23
                        // * It also just does basic lexing, so parens, duplicate operators,
                        // unpaired exceptions etc can all fail validation

                        match spdx::Expression::parse(license_field) {
                            Ok(validated) => {
                                let (id, span) = get_span("license");

                                return KrateLicense {
                                    krate,
                                    lic_info: LicenseInfo::SPDXExpression {
                                        expr: validated,
                                        nfo: LicenseExprInfo {
                                            file_id: id,
                                            offset: span.start,
                                            source: LicenseExprSource::Metadata,
                                        },
                                    },
                                    labels,
                                };
                            }
                            Err(err) => {
                                let (id, lic_span) = get_span("license");
                                let lic_span = lic_span.start + err.span.start as u32
                                    ..lic_span.start + err.span.end as u32;

                                labels.push(Label::new(id, lic_span, format!("{}", err.reason)));
                            }
                        }
                    }
                    None => {
                        let (id, lic_span) = get_span("license");
                        labels.push(Label::new(
                            id,
                            lic_span,
                            "license expression was not specified",
                        ));
                    }
                }

                // 4
                // We might have already loaded the licenses to check them against a clarification
                let license_pack = license_pack.unwrap_or_else(|| LicensePack::read(krate));

                if !license_pack.license_files.is_empty() {
                    let (id, _) = get_span("license");

                    match license_pack.get_expression(krate, id, &strategy, threshold) {
                        Ok((new_toml, expr)) => {
                            // Push our synthesized license files toml content to the end of
                            // the other synthesized toml then fixup all of our spans
                            let expr_offset = {
                                let mut fl = files_lock.write().unwrap();

                                let (new_source, offset) = {
                                    let source = fl.source(id);
                                    (
                                        format!(
                                            "{}files-expr = \"{}\"\n{}\n",
                                            source,
                                            expr.as_ref(),
                                            new_toml
                                        ),
                                        (source.len() + 14) as u32,
                                    )
                                };

                                fl.update(id, new_source);
                                offset
                            };

                            return KrateLicense {
                                krate,
                                lic_info: LicenseInfo::SPDXExpression {
                                    expr,
                                    nfo: LicenseExprInfo {
                                        file_id: id,
                                        offset: expr_offset,
                                        source: LicenseExprSource::LicenseFiles,
                                    },
                                },
                                labels,
                            };
                        }
                        Err((new_toml, lic_file_lables)) => {
                            // Push our synthesized license files toml content to the end of
                            // the other synthesized toml then fixup all of our spans
                            let old_end = {
                                let mut fl = files_lock.write().unwrap();

                                let (new_source, old_end) = {
                                    let source = fl.source(id);
                                    (format!("{}{}\n", source, new_toml), source.len() as u32)
                                };

                                fl.update(id, new_source);
                                old_end
                            };

                            for label in lic_file_lables {
                                let span = label.span.start().to_usize() as u32 + old_end
                                    ..label.span.end().to_usize() as u32 + old_end;
                                labels.push(Label::new(label.file_id, span, label.message));
                            }
                        }
                    }
                }

                // Just get a label for the crate name
                let (id, nspan) = get_span("name");
                labels.push(Label::new(
                    id,
                    nspan,
                    "a valid license expression could not be retrieved for the crate",
                ));

                // Well, we tried our very best. Actually that's not true, we could scan for license
                // files not prefixed by LICENSE, and recurse into subdirectories, but honestly
                // at that point it's probably better to open a PR or something because the license
                // information is not conventional and probably warrants closer inspection
                KrateLicense {
                    krate,
                    lic_info: LicenseInfo::Unlicensed,
                    labels,
                }
            })
            .collect_into_vec(&mut summary.nfos);

        summary
    }
}

pub fn check_licenses(
    summary: Summary<'_>,
    cfg: &ValidConfig,
    sender: crossbeam::channel::Sender<crate::DiagPack>,
) {
    for mut krate_lic_nfo in summary.nfos {
        let mut diagnostics = Vec::new();

        match krate_lic_nfo.lic_info {
            LicenseInfo::SPDXExpression { expr, nfo } => {
                // TODO: If an expression with the same hash is encountered
                // just use the same result as a memoized one

                #[derive(Debug)]
                enum Reason {
                    Denied,
                    NotExplicitlyAllowed,
                    IsFsfFree,
                    IsOsiApproved,
                }

                let mut fail_reasons = smallvec::SmallVec::<[Reason; 2]>::new();

                let eval_res = expr.evaluate_with_failures(|req| {
                    // 1. Licenses explicitly denied are of course hard failures,
                    // but failing one license in an expression is not necessarily
                    // going to actually ban the crate, for example, the canonical
                    // "Apache-2.0 OR MIT" used in by a lot crates means that
                    // banning Apache-2.0, but allowing MIT, will allow the crate
                    // to be used as you are upholding at least one license requirement
                    if let Ok(maybe_denied) =
                        cfg.denied.binary_search_by(|a| a.partial_cmp(req).unwrap())
                    {
                        if cfg.denied[maybe_denied].satisfies(req) {
                            fail_reasons.push(Reason::Denied);
                            return false;
                        }
                    }

                    // 2. A license that is specifically allowed will of course mean
                    // that the requirement is met.
                    if let Ok(maybe_allowed) = cfg
                        .allowed
                        .binary_search_by(|a| a.partial_cmp(req).unwrap())
                    {
                        if cfg.allowed[maybe_allowed].satisfies(req) {
                            return true;
                        }
                    }

                    // 3. If the license isn't explicitly allowed, it still may
                    // be allowed by the blanket "OSI Approved" or "FSF Free/Libre"
                    // allowances
                    if let spdx::LicenseItem::SPDX { id, .. } = req.license {
                        match cfg.allow_osi_fsf_free {
                            BlanketAgreement::Neither => {}
                            BlanketAgreement::Either => {
                                if id.is_fsf_free_libre() || id.is_osi_approved() {
                                    return true;
                                }
                            }
                            BlanketAgreement::Both => {
                                if id.is_fsf_free_libre() && id.is_osi_approved() {
                                    return true;
                                }
                            }
                            BlanketAgreement::OsiOnly => {
                                if id.is_osi_approved() {
                                    if id.is_fsf_free_libre() {
                                        fail_reasons.push(Reason::IsFsfFree);
                                        return false;
                                    } else {
                                        return true;
                                    }
                                }
                            }
                            BlanketAgreement::FsfOnly => {
                                if id.is_fsf_free_libre() {
                                    if id.is_osi_approved() {
                                        fail_reasons.push(Reason::IsOsiApproved);
                                        return false;
                                    } else {
                                        return true;
                                    }
                                }
                            }
                        }
                    }

                    // 4. Whelp, this license just won't do!
                    fail_reasons.push(Reason::NotExplicitlyAllowed);
                    false
                });

                if let Err(failed) = eval_res {
                    let mut secondary = Vec::with_capacity(fail_reasons.len());
                    for (reason, failed_req) in fail_reasons.into_iter().zip(failed.into_iter()) {
                        secondary.push(Label::new(
                            nfo.file_id,
                            nfo.offset + failed_req.span.start..nfo.offset + failed_req.span.end,
                            match reason {
                                Reason::Denied => "explicitly denied",
                                Reason::NotExplicitlyAllowed => "not explicitly allowed",
                                Reason::IsFsfFree => "license is FSF approved https://www.gnu.org/licenses/license-list.en.html",
                                Reason::IsOsiApproved => "license is OSI approved https://opensource.org/licenses",
                            },
                        ));
                    }

                    diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            "failed to satisfy license requirements",
                            Label::new(
                                nfo.file_id,
                                nfo.offset..nfo.offset + expr.as_ref().len() as u32,
                                "license expression",
                            ),
                        )
                        .with_secondary_labels(secondary),
                    );

                    diagnostics.push(
                        Diagnostic::new(
                            Severity::Note,
                            format!(
                                "license expression retrieved via {}",
                                match nfo.source {
                                    LicenseExprSource::Metadata => "Cargo.toml `license`",
                                    LicenseExprSource::UserOverride => "user override",
                                    LicenseExprSource::LicenseFiles => "LICENSE file(s)",
                                    LicenseExprSource::OverlayOverride => unreachable!(),
                                }
                            ),
                            Label::new(
                                nfo.file_id,
                                nfo.offset..nfo.offset + expr.as_ref().len() as u32,
                                "license expression",
                            ),
                        )
                        .with_secondary_labels(krate_lic_nfo.labels.iter().cloned()),
                    );
                }
            }
            LicenseInfo::Unlicensed => {
                let severity = match cfg.unlicensed {
                    LintLevel::Allow => continue,
                    LintLevel::Warn => Severity::Warning,
                    LintLevel::Deny => Severity::Error,
                };

                diagnostics.push(
                    Diagnostic::new(
                        severity,
                        format!("{} is unlicensed", krate_lic_nfo.krate.id),
                        krate_lic_nfo.labels.pop().unwrap(),
                    )
                    .with_secondary_labels(krate_lic_nfo.labels.iter().cloned()),
                );
            }
        }

        if !diagnostics.is_empty() {
            let pack = crate::DiagPack {
                krate_id: Some(krate_lic_nfo.krate.id.clone()),
                diagnostics,
            };

            sender.send(pack).unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn normalizes_line_endings() {
        let pf = super::get_file_source(std::path::PathBuf::from("./tests/LICENSE-RING"));

        let expected = {
            let text = std::fs::read_to_string("./tests/LICENSE-RING").unwrap();
            text.replace("\r\n", "\n")
        };

        let expected_hash = 0xbd0e_ed23;

        if let super::PackFileData::Good(lf) = pf.data {
            if lf.hash != expected_hash {
                eprintln!("hash: {:#x} != {:#x}", expected_hash, lf.hash);

                for (i, (a, b)) in lf.content.chars().zip(expected.chars()).enumerate() {
                    assert_eq!(a, b, "character @ {}", i);
                }
            }
        }
    }
}
