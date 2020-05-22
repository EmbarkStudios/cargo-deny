//! ## `cargo deny check licenses`
//!
//! One important aspect that one must always keep in mind when using code from
//! other people is what the licensing of that code is and whether it fits the
//! requirements of your project. Luckily, most of the crates in the Rust
//! ecosystem tend to follow the example set forth by Rust itself, namely
//! dual-license `MIT OR Apache-2.0`, but of course, that is not always the case.
//!
//! `cargo-deny` allows you to ensure that all of your dependencies have license
//! requirements that are satisfied by the licenses you choose to use for your
//! project, and notifies you via warnings or errors if the license requirements
//! for any crate aren't compatible with your configuration.
//!
//!

/// Configuration for license checking
pub mod cfg;

use crate::{diag, Krate, LintLevel};
use anyhow::Error;
use cfg::{BlanketAgreement, FileSource, ValidClarification, ValidException};
use rayon::prelude::*;
use smallvec::SmallVec;
use std::{
    cmp, fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub use cfg::{Config, ValidConfig};

const LICENSE_CACHE: &[u8] = include_bytes!("../../resources/spdx_cache.bin.zstd");

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

impl Ord for ValidException {
    fn cmp(&self, o: &Self) -> cmp::Ordering {
        match self.name.cmp(&o.name) {
            cmp::Ordering::Equal => self.version.cmp(&o.version),
            o => o,
        }
    }
}

impl PartialOrd for ValidException {
    fn partial_cmp(&self, o: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl PartialEq for ValidException {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == cmp::Ordering::Equal
    }
}

impl Eq for ValidException {}

#[inline]
fn iter_clarifications<'a>(
    all: &'a [ValidClarification],
    krate: &'a Krate,
) -> impl Iterator<Item = &'a ValidClarification> {
    all.iter().filter(move |vc| {
        if vc.name == krate.name {
            return vc.version.matches(&krate.version);
        }

        false
    })
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
    fn read(krate: &Krate) -> Self {
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
                // The `krate.license_file` is relative to the crate, while files found with
                // `find_license_files()` are absolute. We prepend the directory of the current
                // crate, to make sure all license file paths will be absolute.
                let absolute_lf = krate.manifest_path.parent().unwrap().join(lf);
                lic_paths.push(absolute_lf);
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
        krate: &Krate,
        file: codespan::FileId,
        strat: &askalono::ScanStrategy<'_>,
        confidence: f32,
    ) -> Result<(String, spdx::Expression), (String, Vec<diag::Label>)> {
        use std::fmt::Write;

        let mut expr = String::new();
        let mut lic_count = 0;

        let mut synth_toml = String::new();
        if let Some(ref err) = self.err {
            write!(synth_toml, "license-files = \"{}\"", err).unwrap();
            let len = synth_toml.len();
            return Err((
                synth_toml,
                vec![Label::secondary(file, 17..len - 1)
                    .with_message("unable to gather license files")],
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
                                                let start = synth_toml.len();
                                                write!(
                                                    synth_toml,
                                                    ", license = \"{}\"",
                                                    identified.name
                                                )
                                                .unwrap();
                                                let end = synth_toml.len();

                                                fails.push(
                                                    Label::secondary(file, start + 13..end - 1)
                                                        .with_message("unknown SPDX identifier"),
                                                );
                                            }
                                        }
                                    } else {
                                        let start = synth_toml.len();
                                        write!(synth_toml, "score = {:.2}", lic_match.score)
                                            .unwrap();
                                        let end = synth_toml.len();
                                        write!(synth_toml, ", license = \"{}\"", identified.name)
                                            .unwrap();

                                        fails.push(
                                            Label::secondary(file, start + 8..end)
                                                .with_message("low confidence in the license text"),
                                        );
                                    }
                                }
                                None => {
                                    // If the license can't be matched with high enough confidence
                                    let start = synth_toml.len();
                                    write!(synth_toml, "score = {:.2}", lic_match.score).unwrap();
                                    let end = synth_toml.len();

                                    fails.push(
                                        Label::secondary(file, start + 8..end)
                                            .with_message("low confidence in the license text"),
                                    );
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
                    let start = synth_toml.len();
                    write!(synth_toml, "err = \"{}\"", err).unwrap();
                    let end = synth_toml.len();

                    fails.push(
                        Label::secondary(file, start + 7..end - 1)
                            .with_message("unable to read license file"),
                    );
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
    offset: usize,
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
    pub krate: &'a Krate,
    pub lic_info: LicenseInfo,

    // Reasons for why the license was determined (or not!) when
    // gathering the license information
    labels: SmallVec<[diag::Label; 1]>,
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
        let store = askalono::Store::from_cache(LICENSE_CACHE)
            .map_err(|e| anyhow::anyhow!("failed to load license store: {}", e))?;

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
fn get_toml_span(key: &'static str, content: &str) -> std::ops::Range<usize> {
    let mut offset = 0;
    let val_start = loop {
        let start = content[offset..].find('\n').unwrap() + 1;
        if content[start + offset..].starts_with(key) {
            break start + offset + key.len();
        }

        offset += start;
    };

    let val_end = content[val_start..].find("\"\n").unwrap();

    let start = val_start + 4;
    start..start + val_end - 4
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
        krates: &'k crate::Krates,
        files: &mut codespan::Files<String>,
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
        summary.nfos = krates
            .krates()
            .par_bridge()
            .map(|kn| {
                let krate = &kn.krate;

                // Attempt an SPDX expression that we can validate the user's acceptable
                // license terms with
                let mut synth_id = None;

                let mut labels = smallvec::SmallVec::<[Label; 1]>::new();

                let mut get_span =
                    |key: &'static str| -> (codespan::FileId, std::ops::Range<usize>) {
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
                                krate.license.as_deref().unwrap_or_default(),
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
                                let lic_span =
                                    lic_span.start + err.span.start..lic_span.start + err.span.end;

                                labels.push(
                                    Label::secondary(id, lic_span)
                                        .with_message(format!("{}", err.reason)),
                                );
                            }
                        }
                    }
                    None => {
                        let (id, lic_span) = get_span("license");
                        labels.push(
                            Label::secondary(id, lic_span)
                                .with_message("license expression was not specified"),
                        );
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
                                        (source.len() + 14),
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
                                    (format!("{}{}\n", source, new_toml), source.len())
                                };

                                fl.update(id, new_source);
                                old_end
                            };

                            for label in lic_file_lables {
                                let span = label.range.start + old_end..label.range.end + old_end;
                                labels.push(
                                    Label::secondary(label.file_id, span)
                                        .with_message(label.message),
                                );
                            }
                        }
                    }
                }

                // Just get a label for the crate name
                let (id, nspan) = get_span("name");
                labels.push(Label::primary(id, nspan).with_message(
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
            .collect();

        summary
    }
}

use bitvec::prelude::*;
use diag::{Diagnostic, Label, Severity};

struct Hits {
    allowed: BitVec<Local, usize>,
    exceptions: BitVec<Local, usize>,
}

fn evaluate_expression(
    cfg: &ValidConfig,
    krate_lic_nfo: &KrateLicense<'_>,
    expr: &spdx::Expression,
    nfo: &LicenseExprInfo,
    hits: &mut Hits,
) -> Diagnostic {
    // TODO: If an expression with the same hash is encountered
    // just use the same result as a memoized one
    #[derive(Debug)]
    enum Reason {
        Denied,
        IsFsfFree,
        IsOsiApproved,
        IsBothFreeAndOsi,
        ExplicitAllowance,
        ExplicitException,
        IsCopyleft,
        NotExplicitlyAllowed,
        Default,
    }

    let mut reasons = smallvec::SmallVec::<[(Reason, bool); 8]>::new();

    macro_rules! deny {
        ($reason:ident) => {
            reasons.push((Reason::$reason, false));
            return false;
        };
    }

    macro_rules! allow {
        ($reason:ident) => {
            reasons.push((Reason::$reason, true));
            return true;
        };
    }

    let mut warnings = 0;

    // Check to see if the crate matches an exception, which has its own
    // allow list separate from the general allow list
    let eval_res = match cfg.exceptions.iter().position(|exc| {
        exc.name.as_ref() == &krate_lic_nfo.krate.name
            && exc.version.matches(&krate_lic_nfo.krate.version)
    }) {
        Some(ind) => {
            let exception = &cfg.exceptions[ind];

            // Note that hit the exception
            hits.exceptions.as_mut_bitslice().set(ind, true);

            expr.evaluate_with_failures(|req| {
                for allow in &exception.allowed {
                    if allow.value.satisfies(req) {
                        allow!(ExplicitException);
                    }
                }

                deny!(NotExplicitlyAllowed);
            })
        }
        None => expr.evaluate_with_failures(|req| {
            // 1. Licenses explicitly denied are of course hard failures,
            // but failing one license in an expression is not necessarily
            // going to actually ban the crate, for example, the canonical
            // "Apache-2.0 OR MIT" used in by a lot crates means that
            // banning Apache-2.0, but allowing MIT, will allow the crate
            // to be used as you are upholding at least one license requirement
            for deny in &cfg.denied {
                if deny.value.satisfies(req) {
                    deny!(Denied);
                }
            }

            // 2. A license that is specifically allowed will of course mean
            // that the requirement is met.
            for (i, allow) in cfg.allowed.iter().enumerate() {
                if allow.value.satisfies(req) {
                    hits.allowed.as_mut_bitslice().set(i, true);
                    allow!(ExplicitAllowance);
                }
            }

            // 3. If the license isn't explicitly allowed, it still may
            // be allowed by the blanket "OSI Approved" or "FSF Free/Libre"
            // allowances
            if let spdx::LicenseItem::SPDX { id, .. } = req.license {
                if id.is_copyleft() {
                    match cfg.copyleft {
                        LintLevel::Allow => {
                            allow!(IsCopyleft);
                        }
                        LintLevel::Warn => {
                            warnings += 1;
                            allow!(IsCopyleft);
                        }
                        LintLevel::Deny => {
                            deny!(IsCopyleft);
                        }
                    }
                }

                match cfg.allow_osi_fsf_free {
                    BlanketAgreement::Neither => {}
                    BlanketAgreement::Either => {
                        if id.is_osi_approved() {
                            allow!(IsOsiApproved);
                        } else if id.is_fsf_free_libre() {
                            allow!(IsFsfFree);
                        }
                    }
                    BlanketAgreement::Both => {
                        if id.is_fsf_free_libre() && id.is_osi_approved() {
                            allow!(IsBothFreeAndOsi);
                        }
                    }
                    BlanketAgreement::OsiOnly => {
                        if id.is_osi_approved() {
                            if id.is_fsf_free_libre() {
                                deny!(IsFsfFree);
                            } else {
                                allow!(IsOsiApproved);
                            }
                        }
                    }
                    BlanketAgreement::FsfOnly => {
                        if id.is_fsf_free_libre() {
                            if id.is_osi_approved() {
                                deny!(IsOsiApproved);
                            } else {
                                allow!(IsFsfFree);
                            }
                        }
                    }
                }
            }

            // 4. Whelp, this license just won't do!
            match cfg.default {
                LintLevel::Deny => {
                    deny!(Default);
                }
                LintLevel::Warn => {
                    warnings += 1;
                    allow!(Default);
                }
                LintLevel::Allow => {
                    allow!(Default);
                }
            }
        }),
    };

    let (message, severity) = match eval_res {
        Err(_) => ("failed to satisfy license requirements", Severity::Error),
        Ok(_) => (
            "license requirements satisfied",
            if warnings > 0 {
                Severity::Warning
            } else {
                Severity::Help
            },
        ),
    };

    let mut labels = Vec::with_capacity(reasons.len() + 1);

    labels.push(
        Label::secondary(nfo.file_id, nfo.offset..nfo.offset + expr.as_ref().len()).with_message(
            format!(
                "license expression retrieved via {}",
                match nfo.source {
                    LicenseExprSource::Metadata => "Cargo.toml `license`",
                    LicenseExprSource::UserOverride => "user override",
                    LicenseExprSource::LicenseFiles => "LICENSE file(s)",
                    LicenseExprSource::OverlayOverride => unreachable!(),
                }
            ),
        ),
    );

    for (reason, failed_req) in reasons.into_iter().zip(expr.requirements()) {
        labels.push(
            Label::primary(
                nfo.file_id,
                nfo.offset + failed_req.span.start as usize
                    ..nfo.offset + failed_req.span.end as usize,
            )
            .with_message(format!(
                "{}: {}",
                if reason.1 { "accepted" } else { "rejected" },
                match reason.0 {
                    Reason::Denied => "explicitly denied",
                    Reason::NotExplicitlyAllowed => "not explicitly allowed",
                    Reason::IsFsfFree =>
                        "license is FSF approved https://www.gnu.org/licenses/license-list.en.html",
                    Reason::IsOsiApproved =>
                        "license is OSI approved https://opensource.org/licenses",
                    Reason::ExplicitAllowance => "license is explicitly allowed",
                    Reason::ExplicitException => "license is explicitly allowed via an exception",
                    Reason::IsBothFreeAndOsi => "license is FSF AND OSI approved",
                    Reason::IsCopyleft => "license is considered copyleft",
                    Reason::Default => {
                        match cfg.default {
                            LintLevel::Deny => "not explicitly allowed",
                            LintLevel::Warn => "warned by default",
                            LintLevel::Allow => "allowed by default",
                        }
                    }
                }
            )),
        );
    }

    Diagnostic::new(severity)
        .with_message(message)
        .with_labels(labels)
}

pub fn check(
    ctx: crate::CheckCtx<'_, ValidConfig>,
    summary: Summary<'_>,
    sender: crossbeam::channel::Sender<crate::diag::Pack>,
) {
    let mut hits = Hits {
        allowed: bitvec![0; ctx.cfg.allowed.len()],
        exceptions: bitvec![0; ctx.cfg.exceptions.len()],
    };

    let private_registries: Vec<_> = ctx
        .cfg
        .private
        .registries
        .iter()
        .map(|s| s.as_str())
        .collect();

    for krate_lic_nfo in summary.nfos {
        let mut pack = diag::Pack::with_kid(krate_lic_nfo.krate.id.clone());

        // If the user has set this, check if it's a private workspace
        // crate and just print out a help message that we skipped it
        if ctx.cfg.private.ignore
            && ctx
                .krates
                .workspace_members()
                .any(|wm| wm.id == krate_lic_nfo.krate.id)
            && krate_lic_nfo.krate.is_private(&private_registries)
        {
            let i = ctx.krates.nid_for_kid(&krate_lic_nfo.krate.id).unwrap();
            pack.push(
                Diagnostic::help()
                    .with_message("skipping private workspace crate")
                    .with_labels(vec![ctx.label_for_span(i.index(), "workspace crate")]),
            );

            sender.send(pack).unwrap();
            continue;
        }

        match &krate_lic_nfo.lic_info {
            LicenseInfo::SPDXExpression { expr, nfo } => {
                pack.push(evaluate_expression(
                    &ctx.cfg,
                    &krate_lic_nfo,
                    &expr,
                    &nfo,
                    &mut hits,
                ));
            }
            LicenseInfo::Unlicensed => {
                let severity = match ctx.cfg.unlicensed {
                    LintLevel::Allow => Severity::Note,
                    LintLevel::Warn => Severity::Warning,
                    LintLevel::Deny => Severity::Error,
                };

                pack.push(
                    Diagnostic::new(severity)
                        .with_message(format!("{} is unlicensed", krate_lic_nfo.krate.id))
                        .with_labels(krate_lic_nfo.labels.iter().cloned().collect()),
                );
            }
        }

        if !pack.is_empty() {
            sender.send(pack).unwrap();
        }
    }

    // Print out warnings for exceptions that pertain to crates that
    // weren't actually encountered
    for exc in hits
        .exceptions
        .into_iter()
        .zip(ctx.cfg.exceptions.into_iter())
        .filter_map(|(hit, exc)| if !hit { Some(exc) } else { None })
    {
        sender
            .send(
                Diagnostic::warning()
                    .with_message("crate license exception was not encountered")
                    .with_labels(vec![Label::primary(ctx.cfg.file_id, exc.name.span)
                        .with_message("no crate source matched these criteria")])
                    .into(),
            )
            .unwrap();
    }

    // Print out warnings for allowed licenses that weren't encountered.
    // Note that we don't do the same for denied licenses
    for allowed in hits
        .allowed
        .into_iter()
        .zip(ctx.cfg.allowed.into_iter())
        .filter_map(|(hit, allowed)| if !hit { Some(allowed) } else { None })
    {
        sender
            .send(
                Diagnostic::warning()
                    .with_message("license was not encountered")
                    .with_labels(vec![Label::primary(ctx.cfg.file_id, allowed.span)
                        .with_message("no crate used this license")])
                    .into(),
            )
            .unwrap();
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
