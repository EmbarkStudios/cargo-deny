use super::cfg::{FileSource, ValidClarification, ValidConfig, ValidException};
use crate::{
    diag::{FileId, Files, Label},
    Krate,
};
use anyhow::Error;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::{
    cmp, fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

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

enum MismatchReason<'a> {
    /// The specified file was not found when gathering license files
    FileNotFound,
    /// Encountered an I/O error trying to read the file contents
    Error(&'a std::io::Error),
    /// The hash of the license file doesn't match the expected hash
    HashDiffers,
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

    fn license_files_match(&self, expected: &FileSource) -> Result<(), MismatchReason<'_>> {
        let err = match self
            .license_files
            .iter()
            .find(|lf| lf.path.ends_with(&expected.path.value))
        {
            Some(lf) => match &lf.data {
                PackFileData::Bad(e) => MismatchReason::Error(e),
                PackFileData::Good(file_data) => {
                    if file_data.hash != expected.hash {
                        MismatchReason::HashDiffers
                    } else {
                        return Ok(());
                    }
                }
            },
            None => MismatchReason::FileNotFound,
        };

        Err(err)
    }

    fn get_expression(
        &self,
        krate: &Krate,
        file: FileId,
        strat: &askalono::ScanStrategy<'_>,
        confidence: f32,
    ) -> Result<(String, spdx::Expression), (String, Vec<Label>)> {
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
    pub file_id: FileId,
    pub offset: usize,
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
    pub(crate) labels: SmallVec<[Label; 1]>,
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
        files: &mut Files,
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

                let mut get_span = |key: &'static str| -> (FileId, std::ops::Range<usize>) {
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

                        // Check to see if the clarification provided exactly matches
                        // the set of detected licenses, if they do, we use the clarification's
                        // license expression as the license requirements for this crate
                        let clarifications_match = clarification.license_files.iter().all(|clf| {
                            match lp.license_files_match(&clf) {
                                Ok(_) => true,
                                Err(reason) => {
                                    if let MismatchReason::FileNotFound = reason {
                                        labels.push(
                                            super::diags::MissingClarificationFile {
                                                expected: &clf.path,
                                                cfg_file_id: cfg.file_id,
                                            }
                                            .into(),
                                        );
                                    }

                                    false
                                }
                            }
                        });

                        if clarifications_match {
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
