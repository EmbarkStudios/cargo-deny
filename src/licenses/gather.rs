use super::cfg::{FileSource, ValidClarification, ValidConfig};
use crate::{
    Krate, Path, PathBuf,
    diag::{Diagnostic, FileId, Files, Label},
};
use rayon::prelude::*;
use smallvec::SmallVec;
use std::{fmt, sync::Arc};

const LICENSE_CACHE: &[u8] = include_bytes!("../../resources/spdx_cache.bin.zstd");

#[inline]
fn iter_clarifications<'a>(
    all: &'a [ValidClarification],
    krate: &'a Krate,
) -> impl Iterator<Item = &'a ValidClarification> {
    all.iter()
        .filter(move |vc| crate::match_krate(krate, &vc.spec))
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
                let p = match PathBuf::from_path_buf(e.path()) {
                    Ok(pb) => pb,
                    Err(e) => {
                        log::warn!("{} contains invalid utf-8, skipping", e.display());
                        return None;
                    }
                };

                if p.is_file()
                    && p.file_name()
                        .is_some_and(|f| f.starts_with("LICENSE") || f.starts_with("COPYING"))
                {
                    Some(p.strip_prefix(dir).unwrap().to_owned())
                } else {
                    None
                }
            })
        })
        .collect())
}

fn get_file_source(root: &Path, path: PathBuf) -> PackFile {
    use std::io::BufRead;

    // Normalize on plain newlines to handle terrible Windows conventions
    let content = {
        let file = match std::fs::File::open(root.join(&path)) {
            Ok(f) => f,
            Err(e) => {
                return PackFile {
                    path,
                    data: PackFileData::Bad(e),
                };
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

            let keep = std::cmp::max(s.trim_end_matches(['\r', '\n']).len(), min);
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
    /// Encountered an I/O error trying to read the file contents
    Error(&'a std::io::Error),
    /// The hash of the license file doesn't match the expected hash
    HashDiffers,
}

struct LicensePack {
    /// The license files discovered or clarified, relative to root
    license_files: Vec<PackFile>,
    /// The krate's source root
    root: PathBuf,
    err: Option<std::io::Error>,
}

struct GatheredExpr {
    synthesized_toml: String,
    failures: Vec<Label>,
    notes: Vec<String>,
    expr: spdx::Expression,
    file_sources: Vec<String>,
}

impl LicensePack {
    fn read(krate: &Krate) -> Self {
        let root = krate.manifest_path.parent().unwrap();

        let mut lic_paths = match find_license_files(root) {
            Ok(paths) => paths,
            Err(e) => {
                return Self {
                    license_files: Vec::new(),
                    root: root.to_owned(),
                    err: Some(e),
                };
            }
        };

        // Add the explicitly specified license if it wasn't
        // already found in the root directory
        if let Some(lf) = &krate.license_file
            && !lic_paths.iter().any(|l| l.ends_with(lf))
        {
            lic_paths.push(lf.clone());
        }

        let mut license_files: Vec<_> = lic_paths
            .into_iter()
            .map(|path| get_file_source(root, path))
            .collect();

        license_files.sort_by(|a, b| a.path.cmp(&b.path));

        Self {
            license_files,
            root: root.to_owned(),
            err: None,
        }
    }

    fn insert_clarification(&mut self, clarified: &FileSource) -> Result<(), MismatchReason<'_>> {
        let index = match self
            .license_files
            .binary_search_by(|lf| lf.path.cmp(&clarified.path.value))
        {
            Ok(i) => i,
            Err(i) => {
                let lf = get_file_source(&self.root, clarified.path.value.clone());

                self.license_files.insert(i, lf);
                i
            }
        };

        match &self.license_files[index].data {
            PackFileData::Bad(e) => Err(MismatchReason::Error(e)),
            PackFileData::Good(file_data) => {
                if file_data.hash != clarified.hash {
                    Err(MismatchReason::HashDiffers)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn get_expression(
        &self,
        file: FileId,
        strategy: &askalono::ScanStrategy<'_>,
        confidence: f32,
    ) -> Result<GatheredExpr, (String, Vec<Label>)> {
        use std::fmt::Write;

        let mut expr = String::new();
        let mut sources = Vec::new();

        let mut synth_toml = String::new();
        if let Some(err) = &self.err {
            write!(synth_toml, "license-files = \"{err}\"").unwrap();
            let len = synth_toml.len();
            return Err((
                synth_toml,
                vec![
                    Label::secondary(file, 17..len - 1)
                        .with_message("unable to gather license files"),
                ],
            ));
        }

        let mut failures = Vec::new();
        let mut notes = Vec::new();
        synth_toml.push_str("license-files = [\n");

        for lic_contents in &self.license_files {
            write!(
                synth_toml,
                "    {{ path = \"{}\", ",
                self.root.join(&lic_contents.path)
            )
            .unwrap();

            match &lic_contents.data {
                PackFileData::Good(data) => {
                    write!(synth_toml, "hash = 0x{:08x}, ", data.hash).unwrap();

                    let text = askalono::TextData::new(&data.content);
                    match strategy.scan(&text) {
                        Ok(lic_match) => {
                            if let Some(mut identified) = lic_match.license {
                                // See https://github.com/EmbarkStudios/cargo-deny/issues/625
                                // but the Pixar license is just a _slightly_ modified Apache-2.0 license, and since
                                // the apache 2.0 license is so common, and the modification of removing the appendix,
                                // which causes askalono to think it is pixar instead is probably common enough we need
                                // to just explicitly handle it. Really this should be fixed in askalono but that library
                                // is basically abandoned at this point and should be replaced https://github.com/EmbarkStudios/spdx/issues/67
                                if identified.name == "Pixar" {
                                    // Very loose, but just check if the title is actually for the pixar license or not
                                    if !data
                                        .content
                                        .trim_start()
                                        .starts_with("Modified Apache 2.0 License")
                                    {
                                        // emit a note about this, just in case
                                        notes.push(format!("'{}' fuzzy matched to Pixar license, but it is actually a normal Apache-2.0 license", lic_contents.path));

                                        identified.name = "Apache-2.0";
                                    }
                                }

                                // askalano doesn't report any matches below the confidence threshold
                                // but we want to see what it thinks the license is if the confidence
                                // is somewhat ok at least
                                if lic_match.score >= confidence {
                                    if let Some(id) = spdx::license_id(identified.name) {
                                        if !sources.is_empty() {
                                            expr.push_str(" AND ");
                                        }

                                        expr.push_str(id.name);
                                        sources.push(lic_contents.path.as_str().to_owned());
                                    } else {
                                        write!(synth_toml, "score = {:.2}", lic_match.score)
                                            .unwrap();
                                        let start = synth_toml.len();
                                        write!(synth_toml, ", license = \"{}\"", identified.name)
                                            .unwrap();
                                        let end = synth_toml.len();

                                        failures.push(
                                            Label::secondary(file, start + 13..end - 1)
                                                .with_message("unknown SPDX identifier"),
                                        );
                                    }
                                } else {
                                    let start = synth_toml.len();
                                    write!(synth_toml, "score = {:.2}", lic_match.score).unwrap();
                                    let end = synth_toml.len();
                                    write!(synth_toml, ", license = \"{}\"", identified.name)
                                        .unwrap();

                                    failures.push(
                                        Label::secondary(file, start + 8..end)
                                            .with_message("low confidence in the license text"),
                                    );
                                }
                            } else {
                                // If the license can't be matched with high enough confidence
                                let start = synth_toml.len();
                                write!(synth_toml, "score = {:.2}", lic_match.score).unwrap();
                                let end = synth_toml.len();

                                failures.push(
                                    Label::secondary(file, start + 8..end)
                                        .with_message("low confidence in the license text"),
                                );
                            }
                        }
                        Err(err) => {
                            panic!(
                                "askalono's elimination strategy failed (this used to be impossible): {err}"
                            );
                        }
                    }
                }
                PackFileData::Bad(err) => {
                    let start = synth_toml.len();
                    write!(synth_toml, "err = \"{err}\"").unwrap();
                    let end = synth_toml.len();

                    failures.push(
                        Label::secondary(file, start + 7..end - 1)
                            .with_message("unable to read license file"),
                    );
                }
            }

            writeln!(synth_toml, " }},").unwrap();
        }

        synth_toml.push(']');

        if failures.is_empty() || !sources.is_empty() {
            Ok(GatheredExpr {
                synthesized_toml: synth_toml,
                failures,
                notes,
                expr: spdx::Expression::parse(&expr).unwrap(),
                file_sources: sources,
            })
        } else {
            Err((synth_toml, failures))
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
    Metadata(Option<(FileId, std::ops::Range<usize>)>),
    /// An override in the user's deny.toml
    UserOverride,
    /// An override from an overlay
    OverlayOverride,
    /// An expression synthesized from one or more LICENSE files
    LicenseFiles(Vec<String>),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LicenseInfo {
    /// An SPDX expression parsed or generated from the
    /// license information provided by a crate
    SpdxExpression {
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

    pub(crate) notes: Vec<String>,

    // Reasons for why the license was determined (or not!) when
    // gathering the license information
    pub(crate) diags: SmallVec<[Diagnostic; 1]>,
}

pub struct Summary<'a> {
    store: Arc<LicenseStore>,
    pub nfos: Vec<KrateLicense<'a>>,
}

impl Summary<'_> {
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
    pub fn from_cache() -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let store =
            askalono::Store::from_cache(LICENSE_CACHE).context("failed to load license store")?;

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

const LICENSE_RX: &str = r#"license\s*=\s*["']([^"']*)["']"#;

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

    #[inline]
    pub fn with_confidence_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold.clamp(0.0, 1.0);
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

        let files_lock = std::sync::Arc::new(parking_lot::RwLock::new(files));

        // Most users will not care about licenses for dev dependencies
        let krates = if cfg.is_some_and(|cfg| cfg.include_dev) {
            krates.krates().collect()
        } else {
            krates.krates_filtered(krates::DepKind::Dev)
        };

        let lic_rx = regex::Regex::new(LICENSE_RX).expect("failed to compile regex");

        // Retrieve the license expression we'll use to evaluate the user's overall
        // constraints with.
        //
        // NOTE: The reason that user/overlay overrides are prioritized over the
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
        // 4. `license-file` + all LICENSE(-*)? files - Due to the prevalence
        // of dual-licensing in the rust ecosystem, many people forgo setting
        // license-file, so we use it and/or any LICENSE files
        summary.nfos = krates
            .into_par_iter()
            .map(|krate| {
                // Attempt an SPDX expression that we can validate the user's acceptable
                // license terms with
                let mut synth_id = None;

                let mut diags = smallvec::SmallVec::<[Diagnostic; 1]>::new();

                let mut get_span = |key: &'static str| -> (FileId, std::ops::Range<usize>) {
                    if let Some(id) = synth_id {
                        let l = files_lock.read();
                        (synth_id.unwrap(), get_toml_span(key, l.source(id)))
                    } else {
                        // Synthesize a minimal Cargo.toml for reporting diagnostics
                        // for where we retrieved license stuff
                        let synth_manifest = format!(
                            "[package]\nname = \"{}\"\nversion = \"{}\"\nlicense = \"{}\"\n",
                            krate.name,
                            krate.version,
                            krate.license.as_deref().unwrap_or_default(),
                        );

                        {
                            let mut fl = files_lock.write();
                            synth_id = Some(fl.add(
                                format!("{}-synthesized.toml", krate.id.repr),
                                synth_manifest,
                            ));
                            (
                                synth_id.unwrap(),
                                get_toml_span(key, fl.source(synth_id.unwrap())),
                            )
                        }
                    }
                };

                let mut license_pack = None;

                // 1
                if let Some(cfg) = cfg {
                    for clarification in iter_clarifications(&cfg.clarifications, krate) {
                        let lp = if let Some(lp) = &mut license_pack {
                            lp
                        } else {
                            license_pack = Some(LicensePack::read(krate));
                            license_pack.as_mut().unwrap()
                        };

                        // Check to see if the clarification provided exactly matches
                        // the set of detected licenses, if they do, we use the clarification's
                        // license expression as the license requirements for this crate
                        let clarifications_match = clarification.license_files.iter().all(|clf| {
                            match lp.insert_clarification(clf) {
                                Ok(_) => true,
                                Err(reason) => {
                                    if let MismatchReason::Error(err) = reason
                                        && err.kind() == std::io::ErrorKind::NotFound
                                    {
                                        diags.push(
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
                                lic_info: LicenseInfo::SpdxExpression {
                                    expr: clarification.expression.clone(),
                                    nfo: LicenseExprInfo {
                                        file_id: cfg.file_id,
                                        offset: clarification.expr_offset,
                                        source: LicenseExprSource::UserOverride,
                                    },
                                },
                                diags,
                                notes: Vec::new(),
                            };
                        }
                    }
                }

                // 2
                if let Some(license_field) = krate.license.as_ref().filter(|l| !l.is_empty()) {
                    let location =
                        Self::get_license_span(&lic_rx, &files_lock, &krate.manifest_path);

                    // Reasons this can fail:
                    //
                    // * Empty! The rust crate used to validate this field has a bug
                    // https://github.com/rust-lang-nursery/license-exprs/issues/23
                    // * It also just does basic lexing, so parens, duplicate operators,
                    // unpaired exceptions etc can all fail validation
                    //
                    // Note that these only apply to _old_ versions, as `spdx`
                    // is now used by crates.io to validate, but it uses lax
                    // rules to allow some license identifiers that aren't
                    // technically correct

                    const LAX: spdx::ParseMode = spdx::ParseMode {
                        allow_slash_as_or_operator: true,
                        allow_imprecise_license_names: true,
                        allow_postfix_plus_on_gpl: true,
                        allow_deprecated: true,
                    };

                    const STRICT: spdx::ParseMode = spdx::ParseMode {
                        // Really this should be false, but / instead of OR is
                        // by _far_ the most common error in SPDX expressions,
                        // while crates.io no longer allows them, they are still
                        // in old versions, and while we could warn, realistically
                        // there is nothing the downstream user can do other than
                        // remove it or upgrade to a newer version that has a
                        // correct license expression
                        allow_slash_as_or_operator: true,
                        allow_imprecise_license_names: false,
                        allow_postfix_plus_on_gpl: false,
                        allow_deprecated: false,
                    };

                    let mut error_span = None;

                    for mode in [STRICT, LAX] {
                        match spdx::Expression::parse_mode(license_field, mode) {
                            Ok(expr) => {
                                let (file_id, offset) = location.clone().map_or_else(
                                    || {
                                        let (id, span) = get_span("license");
                                        (id, span.start)
                                    },
                                    |(file_id, range)| (file_id, range.start),
                                );

                                return KrateLicense {
                                    krate,
                                    lic_info: LicenseInfo::SpdxExpression {
                                        expr,
                                        nfo: LicenseExprInfo {
                                            file_id,
                                            offset,
                                            source: LicenseExprSource::Metadata(location),
                                        },
                                    },
                                    diags,
                                    notes: Vec::new(),
                                };
                            }
                            Err(error) => {
                                // Don't give multiple diagnostics for the same parse error
                                if let Some(es) = &error_span
                                    && es == &error.span
                                {
                                    break;
                                }

                                error_span = Some(error.span.clone());

                                let (file_id, span) =
                                    location.clone().unwrap_or_else(|| get_span("license"));

                                // let (file_id, span) = if license_field.corrected.is_some()
                                //     && let Some((file_id, span)) = location.clone()
                                // {
                                //     Self::correct_span(&license_field.original, &mut error.span);
                                //     (file_id, span)
                                // } else {
                                //     // The span we write is the corrected one, so we don't need to adjust it
                                //     get_span("license")
                                // };

                                diags.push(
                                    super::diags::ParseError {
                                        span,
                                        file_id,
                                        error,
                                    }
                                    .into(),
                                );
                            }
                        }
                    }
                } else if krate.license.as_ref().is_some_and(|l| l.is_empty())
                    && let Some((id, loc)) =
                        Self::get_license_span(&lic_rx, &files_lock, &krate.manifest_path)
                {
                    diags.push(
                        Diagnostic::warning()
                            .with_message("license field was present but empty")
                            .with_label(Label::secondary(id, loc).with_message("empty field")),
                    );
                } else {
                    diags.push(
                        Diagnostic::warning()
                            .with_message("license expression was not specified in manifest"),
                    );
                }

                // 3
                // We might have already loaded the licenses to check them against a clarification
                let license_pack = license_pack.unwrap_or_else(|| LicensePack::read(krate));

                if !license_pack.license_files.is_empty() {
                    let (id, _) = get_span("license");

                    match license_pack.get_expression(id, &strategy, threshold) {
                        Ok(GatheredExpr {
                            synthesized_toml,
                            failures,
                            notes,
                            expr,
                            file_sources,
                        }) => {
                            // Push our synthesized license files toml content to the end of
                            // the other synthesized toml then fixup all of our spans
                            let expr_offset = {
                                let mut fl = files_lock.write();

                                let (new_source, offset) = {
                                    let source = fl.source(id);
                                    (
                                        format!(
                                            "{source}files-expr = \"{expr}\"\n{synthesized_toml}\n"
                                        ),
                                        (source.len() + 14),
                                    )
                                };

                                fl.update(id, new_source);
                                offset
                            };

                            let fail_offset = expr_offset + expr.to_string().len() + 2;

                            for fail in failures {
                                let span =
                                    fail.range.start + fail_offset..fail.range.end + fail_offset;
                                diags.push(Diagnostic::warning().with_label(
                                    Label::secondary(fail.file_id, span).with_message(fail.message),
                                ));
                            }

                            return KrateLicense {
                                krate,
                                lic_info: LicenseInfo::SpdxExpression {
                                    expr,
                                    nfo: LicenseExprInfo {
                                        file_id: id,
                                        offset: expr_offset,
                                        source: LicenseExprSource::LicenseFiles(file_sources),
                                    },
                                },
                                diags,
                                notes,
                            };
                        }
                        Err((new_toml, lic_file_labels)) => {
                            // Push our synthesized license files toml content to the end of
                            // the other synthesized toml then fixup all of our spans
                            let old_end = {
                                let mut fl = files_lock.write();

                                let (new_source, old_end) = {
                                    let source = fl.source(id);
                                    (format!("{source}{new_toml}\n"), source.len())
                                };

                                fl.update(id, new_source);
                                old_end
                            };

                            diags.extend(lic_file_labels.into_iter().map(|label| {
                                Diagnostic::warning().with_label(Label {
                                    style: codespan_reporting::diagnostic::LabelStyle::Secondary,
                                    file_id: label.file_id,
                                    range: label.range.start + old_end..label.range.end + old_end,
                                    message: label.message,
                                })
                            }));
                        }
                    }
                }

                // Just get a label for the crate name
                let (id, nspan) = get_span("name");
                diags.push(
                    Diagnostic::warning()
                        .with_message(
                            "a valid license expression could not be retrieved for the crate",
                        )
                        .with_label(Label::primary(id, nspan)),
                );

                // Well, we tried our very best. Actually that's not true, we could scan for license
                // files not prefixed by LICENSE, and recurse into subdirectories, but honestly
                // at that point it's probably better to open a PR or something because the license
                // information is not conventional and probably warrants closer inspection
                KrateLicense {
                    krate,
                    lic_info: LicenseInfo::Unlicensed,
                    diags,
                    notes: Vec::new(),
                }
            })
            .collect();

        summary.nfos.par_sort_by_key(|nfo| nfo.krate);

        summary
    }

    #[inline]
    fn range(expr: &regex::Regex, manifest: &str) -> Option<std::ops::Range<usize>> {
        let cap = expr.captures(manifest)?;
        let cap = cap.get(1)?;
        Some(cap.range())
    }

    #[inline]
    pub fn correct_span(original: &str, error_span: &mut std::ops::Range<usize>) {
        let mut count = 0;

        // We adjust '/' => ' OR ' on load due to it being by
        // far the most common error in expressions and it looks
        // extremely unpleasant, but if that happens we need to adjust
        // the span if it comes after one or more /
        for (i, op) in memchr::memchr_iter(b'/', original.as_bytes()).enumerate() {
            if error_span.start < i * 3 + op {
                break;
            }

            count += 1;
        }

        error_span.start -= count * 3;
        error_span.end -= count * 3;
    }

    fn get_license_span(
        expr: &regex::Regex,
        files: &parking_lot::RwLock<&mut Files>,
        manifest_path: &Path,
    ) -> Option<(FileId, std::ops::Range<usize>)> {
        'exists: {
            let r = files.read();
            let Some(file_id) = r.id_for_path(manifest_path) else {
                break 'exists;
            };
            let manifest = r.source(file_id);
            let range = Self::range(expr, manifest)?;

            return Some((file_id, range));
        }

        let manifest = match std::fs::read_to_string(manifest_path) {
            Ok(m) => m,
            Err(error) => {
                panic!("failed to read {manifest_path}: {error}");
                return None;
            }
        };

        // We only ever load each manifest once, so it's fine if we take the
        // hit for the load but don't actually store it if we somehow
        // couldn't get the license expression
        let range = Self::range(expr, &manifest)?;

        // Unlikely/impossible, but we don't want to panic
        let mut w = files.write();
        if let Some(file_id) = w.id_for_path(manifest_path) {
            Some((file_id, range))
        } else {
            let file_id = w.add(manifest_path, manifest);
            Some((file_id, range))
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[allow(clippy::disallowed_macros)]
    fn normalizes_line_endings() {
        let pf = super::get_file_source(
            crate::Path::new("./tests/"),
            crate::PathBuf::from("LICENSE-RING"),
        );

        let expected = {
            let text = std::fs::read_to_string("./tests/LICENSE-RING").unwrap();
            text.replace("\r\n", "\n")
        };

        let expected_hash = 0xbd0e_ed23;

        if let super::PackFileData::Good(lf) = pf.data
            && lf.hash != expected_hash
        {
            eprintln!("hash: {expected_hash:#x} != {:#x}", lf.hash);

            for (i, (a, b)) in lf.content.chars().zip(expected.chars()).enumerate() {
                assert_eq!(a, b, "character @ {i}");
            }
        }
    }

    #[test]
    fn finds_and_corrects_span() {
        let cases = [
            ("MIT", None),
            ("Apache-2.0 OR MIT", None),
            ("GPL-2.0/Apache-2.0", Some("GPL-2.0 OR Apache-2.0")),
            (
                "GPL-2.0-only/GPL-3.0-only OR MIT AND ISC/GPL-3.0/Apache-2.0",
                Some("GPL-2.0-only OR GPL-3.0-only OR MIT AND ISC OR GPL-3.0 OR Apache-2.0"),
            ),
            ("MIT/GPL-3.0", Some("MIT OR GPL-3.0")),
        ];

        let rx = regex::Regex::new(super::LICENSE_RX).unwrap();

        for (original, xform) in cases {
            let manifest = format!(
                "[package]\nname = 'name-goes-here'\nversion = '0.1.0'\nlicense = '{original}'\nrepository = 'http://fake.com'"
            );

            let range = super::Gatherer::range(&rx, &manifest).unwrap();

            if let Some(xform) = xform {
                let mut err =
                    spdx::Expression::parse_mode(xform, spdx::ParseMode::STRICT).unwrap_err();

                let in_corrected = &xform[err.span.clone()];
                let uncorrected =
                    &manifest[range.start + err.span.start..range.start + err.span.end];
                super::Gatherer::correct_span(original, &mut err.span);

                let new = range.start + err.span.start..range.start + err.span.end;
                let in_manifest = &manifest[new];

                assert_eq!(
                    in_corrected, in_manifest,
                    "error was here '{in_corrected}', and we corrected it to '{in_manifest}', otherwise it would have been '{uncorrected}'"
                );
            } else {
                spdx::Expression::parse_mode(original, spdx::ParseMode::STRICT).unwrap();
            }
        }
    }
}
