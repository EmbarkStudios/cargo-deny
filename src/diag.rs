pub mod general;
mod grapher;
mod sink;

pub use grapher::{cs_diag_to_json, diag_to_json, write_graph_as_text, InclusionGrapher};
pub use sink::{DiagnosticOverrides, ErrorSink};

use std::{collections::BTreeMap, ops::Range};

use crate::{Kid, Krate, Krates, PathBuf, Span};
pub use codespan_reporting::diagnostic::Severity;

pub type FileId = usize;

pub type FilesErr = codespan_reporting::files::Error;
pub type Diagnostic = codespan_reporting::diagnostic::Diagnostic<FileId>;
pub type Label = codespan_reporting::diagnostic::Label<FileId>;

/// Channel type used to send diagnostics from checks
pub type PackChannel = crossbeam::channel::Sender<Pack>;

struct File {
    name: PathBuf,
    source: String,
    line_starts: Vec<u32>,
}

use codespan_reporting::files::Files as _;

/// Implementation of [`codespan_reporting::files::Files`], which can also query
/// [`FileId`] by path
pub struct Files {
    files: Vec<File>,
    /// Since we hand out ids we keep a mapping of path -> id for faster searching
    map: BTreeMap<PathBuf, FileId>,
}

impl Files {
    #[inline]
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            map: Default::default(),
        }
    }

    #[inline]
    pub fn source_by_path(&self, path: &crate::Path) -> Option<&str> {
        self.id_for_path(path)
            .map(|id| self.files[id].source.as_str())
    }

    #[inline]
    pub fn id_for_path(&self, path: &crate::Path) -> Option<FileId> {
        self.map.get(path).copied()
    }

    #[inline]
    pub fn add(&mut self, path: impl Into<crate::PathBuf>, source: impl Into<String>) -> FileId {
        let name = path.into();

        if let Some(id) = self.id_for_path(&name) {
            panic!("path {name}({id}) is already present");
        }

        let id = self.files.len();
        self.map.insert(name.clone(), id);
        self.files.push(File {
            name,
            source: String::new(),
            line_starts: Vec::new(),
        });

        self.update(id, source);
        id
    }

    #[inline]
    pub fn update(&mut self, id: FileId, source: impl Into<String>) {
        let file = &mut self.files[id];

        let source = source.into();

        let mut line_starts = Vec::new();
        line_starts.push(0);
        line_starts.extend(memchr::memchr_iter(b'\n', source.as_bytes()).map(|i| (i + 1) as u32));

        file.source = source;
        file.line_starts = line_starts;
    }

    pub fn location(&self, id: FileId, byte_index: u32) -> Result<codespan::Location, FilesErr> {
        let given = byte_index as usize;
        let line_index = self.line_index(id, given)?;

        let file = &self.files[id];
        let line_start = file.line_starts[line_index] as usize;

        let line_src = file.source.get(line_start..given).ok_or_else(|| {
            let max = file.source.len() - 1;
            if given > max {
                FilesErr::IndexTooLarge { given, max }
            } else {
                FilesErr::InvalidCharBoundary { given }
            }
        })?;

        Ok(codespan::Location {
            line: (line_index as u32).into(),
            column: (line_src.chars().count() as u32).into(),
        })
    }

    #[inline]
    pub fn source(&self, id: FileId) -> &str {
        &self.files[id].source
    }
}

impl<'f> codespan_reporting::files::Files<'f> for Files {
    type FileId = FileId;
    type Name = &'f crate::Path;
    type Source = &'f str;

    fn source(&'f self, id: Self::FileId) -> Result<Self::Source, FilesErr> {
        self.files
            .get(id)
            .map(|f| f.source.as_str())
            .ok_or(FilesErr::FileMissing)
    }

    fn name(&'f self, id: Self::FileId) -> Result<Self::Name, FilesErr> {
        self.files
            .get(id)
            .map(|f| f.name.as_path())
            .ok_or(FilesErr::FileMissing)
    }

    fn line_index(&'f self, id: Self::FileId, byte_index: usize) -> Result<usize, FilesErr> {
        let file = self.files.get(id).ok_or(FilesErr::FileMissing)?;

        let byte_index: u32 = byte_index
            .try_into()
            .map_err(|_e| FilesErr::IndexTooLarge {
                given: byte_index,
                max: file.line_starts.last().map_or(u32::MAX as _, |ls| *ls as _),
            })?;

        Ok(match file.line_starts.binary_search(&byte_index) {
            Ok(line) => line,
            Err(next_line) => next_line - 1,
        })
    }

    fn line_range(&'f self, id: Self::FileId, line_index: usize) -> Result<Range<usize>, FilesErr> {
        let file = self.files.get(id).ok_or(FilesErr::FileMissing)?;

        let start = *file
            .line_starts
            .get(line_index)
            .ok_or_else(|| FilesErr::LineTooLarge {
                given: line_index,
                max: file.line_starts.len(),
            })?;
        let end = if line_index + 1 < file.line_starts.len() {
            file.line_starts[line_index + 1]
        } else {
            file.source.len() as _
        };

        Ok(start as _..end as _)
    }
}

impl From<crate::LintLevel> for Severity {
    fn from(ll: crate::LintLevel) -> Self {
        match ll {
            crate::LintLevel::Warn => Severity::Warning,
            crate::LintLevel::Deny => Severity::Error,
            crate::LintLevel::Allow => Severity::Note,
        }
    }
}

pub struct GraphNode {
    pub kid: Kid,
    pub feature: Option<String>,
}

pub struct Diag {
    pub diag: Diagnostic,
    pub graph_nodes: smallvec::SmallVec<[GraphNode; 2]>,
    pub extra: Option<(&'static str, serde_json::Value)>,
    pub with_features: bool,
}

impl Diag {
    pub(crate) fn new(diag: Diagnostic) -> Self {
        Self {
            diag,
            graph_nodes: smallvec::SmallVec::new(),
            extra: None,
            with_features: false,
        }
    }
}

impl From<Diagnostic> for Diag {
    fn from(d: Diagnostic) -> Self {
        Diag::new(d)
    }
}

pub enum Check {
    Advisories,
    Bans,
    Licenses,
    Sources,
}

pub struct Pack {
    pub check: Check,
    pub(crate) diags: Vec<Diag>,
    kid: Option<Kid>,
}

impl Pack {
    #[inline]
    pub(crate) fn new(check: Check) -> Self {
        Self {
            check,
            diags: Vec::new(),
            kid: None,
        }
    }

    #[inline]
    pub(crate) fn with_kid(check: Check, kid: Kid) -> Self {
        Self {
            check,
            diags: Vec::new(),
            kid: Some(kid),
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, diag: impl Into<Diag>) -> &mut Diag {
        let mut diag = diag.into();
        if diag.graph_nodes.is_empty() {
            if let Some(kid) = self.kid.clone() {
                diag.graph_nodes.push(GraphNode { kid, feature: None });
            }
        }

        self.diags.push(diag);
        self.diags.last_mut().unwrap()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.diags.len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.diags.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Diag> {
        self.diags.iter()
    }
}

impl IntoIterator for Pack {
    type Item = Diag;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.diags.into_iter()
    }
}

impl<T> From<(Check, T)> for Pack
where
    T: Into<Diag>,
{
    fn from((check, t): (Check, T)) -> Self {
        Self {
            check,
            diags: vec![t.into()],
            kid: None,
        }
    }
}

#[derive(Debug)]
pub struct ManifestDep<'k> {
    /// The dependency declaration
    pub dep: &'k krates::cm::Dependency,
    /// The crate the dependency resolved to
    pub krate: &'k Krate,
    /// Span for the dependency key
    pub key_span: toml_span::Span,
    /// Span for the overall dependency value
    pub value_span: toml_span::Span,
    /// Span for the `version` key, if present
    pub version_req: Option<toml_span::Spanned<semver::VersionReq>>,
    /// Span for the `workspace` key, if present
    pub workspace: Option<toml_span::Spanned<bool>>,
    /// Span for the `package` key, if present
    pub rename: Option<toml_span::Spanned<String>>,
}

/// A parsed crate manifest
#[derive(Debug)]
pub struct Manifest<'k> {
    /// Id for the cargo manifest file for the krate
    pub id: FileId,
    /// The parsed krate
    pub krate: &'k Krate,
    /// The resolved dependencies for the krate
    pub deps: Vec<ManifestDep<'k>>,
}

impl<'k> Manifest<'k> {
    pub fn parse(krate: &'k Krate, krates: &'k Krates, contents: &str) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        use krates::cm::DependencyKind;

        let root = toml_span::parse(contents)?;
        let mut pointer = String::new();
        let mut deps = Vec::new();

        let nid = krates
            .nid_for_kid(&krate.id)
            .with_context(|| format!("unable to find krate {}", krate.id))?;

        // Unfortunately cargo will "helpfully" prettify cfg expressions in the
        // metadata output, but this makes it impossible to just directly map back
        // to the location in the toml manifest since non-normalized cfg expressions
        // will just fail the pointer path, so we build a mapping of expressions
        // to pointers. Note that we need to account for cases where the manifest is
        // inconsistent, eg. `cfg(target_os="windows")`, `cfg(windows)`, and
        // `cfg(target_os = "windows")` are all equivalent
        struct Target<'m> {
            /// The cfg string as it appears in the manifest
            original: &'m str,
            expr: Option<cfg_expr::Expression>,
        }

        let targets = root.pointer("/target").map_or(Vec::new(), |targets| {
            let Some(table) = targets.as_table() else {
                return Vec::new();
            };

            table
                .keys()
                .map(|cfg| {
                    let original = cfg.name.as_ref();
                    let expr = if !cfg.name.starts_with("cfg(") {
                        None
                    } else {
                        cfg_expr::Expression::parse(&cfg.name).ok()
                    };

                    Target { original, expr }
                })
                .collect()
        });

        let get_dep_value =
            |dep: &krates::cm::Dependency,
             pointer: &mut String|
             -> Option<(&toml_span::value::Key<'_>, &toml_span::Value<'_>)> {
                pointer.clear();
                pointer.push('/');

                let name = dep.rename.as_ref().unwrap_or(&dep.name);

                let push_kind = |pointer: &mut String| {
                    let dep_kind = match dep.kind {
                        DependencyKind::Development => "dev-",
                        DependencyKind::Build => "build-",
                        DependencyKind::Normal => "",
                    };

                    pointer.push_str(dep_kind);
                    pointer.push_str("dependencies");
                };

                // If the dependency has a cfg/platform it is in `targets.<>.<kind>` so
                // we need a pointer to that first
                if let Some(cfg) = &dep.target {
                    pointer.push_str("target/");

                    let expr = cfg
                        .starts_with("cfg(")
                        .then(|| cfg_expr::Expression::parse(cfg).ok())
                        .flatten();

                    for target in &targets {
                        pointer.truncate(8 /* /target/ */);

                        match (&target.expr, &expr) {
                            (None, None) => {
                                pointer.push_str(target.original);
                            }
                            (Some(a), Some(b)) => {
                                if !a.predicates().zip(b.predicates()).all(|(a, b)| a == b) {
                                    continue;
                                }

                                pointer.push_str(target.original);
                            }
                            _ => continue,
                        }

                        pointer.push('/');

                        push_kind(pointer);

                        let Some(dep_table) = root.pointer(&pointer) else {
                            continue;
                        };

                        let Some(table) = dep_table.as_table() else {
                            log::warn!(
                                "{pointer} for manifest '{}' is not a valid toml table",
                                krate.manifest_path
                            );
                            continue;
                        };

                        if let Some(kv) = table.get_key_value(name.as_str()) {
                            return Some(kv);
                        }
                    }

                    None
                } else {
                    push_kind(pointer);

                    let Some(dep_table) = root.pointer(&pointer) else {
                        return None;
                    };

                    let Some(table) = dep_table.as_table() else {
                        log::warn!(
                            "{pointer} for manifest '{}' is not a valid toml table",
                            krate.manifest_path
                        );
                        return None;
                    };

                    table.get_key_value(name.as_str())
                }
            };

        for (i, dep) in krate.deps.iter().enumerate() {
            // Get the krate that was resolved for the dependency declaration, this
            // can be None if it was pruned via cfg etc
            let Some(dep_krate) = krates.resolved_dependency(nid, i) else {
                continue;
            };

            let Some((key, dep_value)) = get_dep_value(dep, &mut pointer) else {
                log::warn!(
                    "unable to locate {krate} - ({}) -> {}@{} in manifest '{}' (path: {pointer})",
                    dep.kind,
                    dep.name,
                    dep.req,
                    krate.manifest_path
                );
                continue;
            };

            let (workspace, version_req, rename) = if let Some(table) = dep_value.as_table() {
                let workspace = table.get("workspace").and_then(|v| {
                    v.as_bool()
                        .map(|b| toml_span::Spanned::with_span(b, v.span))
                });
                let version = table.get("version").and_then(|v| {
                    v.as_str().and_then(|vr| {
                        match vr.parse() {
                            Ok(vreq) => Some(toml_span::Spanned::with_span(vreq, v.span)),
                            Err(err) => {
                                log::error!("version requirement '{vr}' for {krate} -> {dep_krate} could not be parsed: {err:#}");
                                None
                            }
                        }
                    })
                });
                let rename = table.get("package").and_then(|v| {
                    v.as_str()
                        .map(|rn| toml_span::Spanned::with_span(rn.to_owned(), v.span))
                });

                (workspace, version, rename)
            } else if let Some(version) = dep_value.as_str() {
                (None, version.parse().map_err(|err| {
                    log::error!("version requirement '{version}' for {krate} -> {dep_krate} could not be parsed: {err:#}");
                    err
                }).ok().map(|vr| toml_span::Spanned::with_span(vr, dep_value.span)), None)
            } else {
                log::error!("dependency {krate} -> {dep_krate} is not a string nor table, this should be invalid...");
                (None, None, None)
            };

            deps.push(ManifestDep {
                dep,
                krate: dep_krate,
                key_span: key.span,
                value_span: dep_value.span,
                workspace,
                version_req,
                rename,
            });
        }

        Ok(Self { deps, krate, id: 0 })
    }
}

pub struct LockSpan {
    /// The total span for the lock entry, which includes the name, version, and source
    pub total: Span,
    /// The span that covers only the source portion of the entry
    pub source: Span,
}

/// The span locations for a workspace dependency
pub struct WorkspaceSpan<'k> {
    pub krate: &'k Krate,
    pub key: Span,
    pub value: Span,
    pub version: Option<toml_span::Spanned<semver::VersionReq>>,
    pub rename: Option<toml_span::Spanned<String>>,
}

pub struct Spans<'k> {
    pub lock: LockSpan,
    pub workspace: Option<WorkspaceSpan<'k>>,
    pub manifest: Option<Manifest<'k>>,
}

pub struct KrateSpans<'k> {
    spans: BTreeMap<&'k Kid, Spans<'k>>,
    pub workspace_id: Option<FileId>,
    /// The ID of the (synthesized) lockfile
    pub lock_id: FileId,
}

impl<'k> KrateSpans<'k> {
    pub fn synthesize(krates: &'k Krates, lock_name: &str, files: &mut Files) -> Self {
        use anyhow::Context as _;
        use std::fmt::Write as _;

        let mut sl = String::with_capacity(4 * 1024);
        //let mut lock_spans = Vec::with_capacity(krates.len());

        let mut okrates: Vec<_> = krates
            .krates()
            .map(|krate| {
                (
                    krate,
                    LockSpan {
                        total: Default::default(),
                        source: Default::default(),
                    },
                )
            })
            .collect();
        // [Krates::krates] only guarantees that krates are in the same order that cargo metadata
        // serializes them in, but we want to be stable across the full id
        okrates.sort_unstable_by_key(|(k, _s)| (&k.name, &k.version));
        for (krate, span) in &mut okrates {
            let span_start = sl.len();
            let source = if krate.source.is_some() {
                krate.id.source()
            } else {
                krate.manifest_path.parent().unwrap().as_str()
            };

            writeln!(sl, "{} {} {source}", krate.name, krate.version)
                .expect("unable to synthesize lockfile");

            let total = span_start..sl.len() - 1;
            span.source = (total.end - source.len()..total.end).into();
            span.total = total.into();
        }

        let lock_id = files.add(format!("{lock_name}/Cargo.lock"), sl);

        let mut manifests = Vec::with_capacity(krates.len());
        use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
        okrates
            .par_iter()
            .map(|(krate, _)| -> anyhow::Result<(Manifest<'_>, String)> {
                let contents = std::fs::read_to_string(&krate.manifest_path)
                    .with_context(|| format!("failed to read manifest {}", krate.manifest_path))?;
                let manifest = Manifest::parse(krate, krates, &contents)?;
                Ok((manifest, contents))
            })
            .collect_into_vec(&mut manifests);

        let mut spans = okrates
            .into_iter()
            .zip(manifests.into_iter())
            .map(|((krate, lock), res)| {
                let manifest = match res {
                    Ok((mut manifest, contents)) => {
                        manifest.id = files.add(krate.manifest_path.clone(), contents);
                        Some(manifest)
                    }
                    Err(err) => {
                        log::error!("unable to parse manifest for {krate}: {err:#}");
                        None
                    }
                };

                (
                    &krate.id,
                    Spans {
                        lock,
                        workspace: None,
                        manifest,
                    },
                )
            })
            .collect();

        // Add the root workspace toml if needed
        let workspace_root = krates.workspace_root().join("Cargo.toml");

        let workspace_id = if let Some(wid) = files.id_for_path(&workspace_root) {
            Some(wid)
        } else {
            match std::fs::read_to_string(&workspace_root) {
                Ok(contents) => Some(files.add(workspace_root, contents)),
                Err(err) => {
                    log::error!("failed to read workspace root '{workspace_root}': {err:#}");
                    None
                }
            }
        };

        if let Some(wid) = workspace_id {
            let workspace_root = files.source(wid);
            if let Err(err) = read_workspace_deps(workspace_root, krates, &mut spans) {
                log::error!(
                    "failed to resolve [workspace.dependencies] from '{}': {err:#}",
                    krates.workspace_root().join("Cargo.toml")
                );
            }
        }

        Self {
            lock_id,
            workspace_id,
            spans,
        }
    }

    #[inline]
    pub fn lock_span(&self, kid: &Kid) -> &LockSpan {
        &self.spans[kid].lock
    }

    #[inline]
    pub fn manifest(&self, kid: &Kid) -> Option<&Manifest<'k>> {
        self.spans[kid].manifest.as_ref()
    }

    #[inline]
    pub fn workspace_span(&self, kid: &Kid) -> Option<&WorkspaceSpan<'k>> {
        self.spans[kid].workspace.as_ref()
    }
}

pub struct WsDep<'k> {
    pub key_span: toml_span::Span,
    pub value_span: toml_span::Span,
    pub rename: Option<toml_span::Spanned<String>>,
    pub krate: &'k Krate,
}

/// Gather the crates declared in the `[workspace.dependencies]` section
fn read_workspace_deps<'k>(
    root_toml: &str,
    krates: &'k Krates,
    map: &mut BTreeMap<&'k Kid, Spans<'k>>,
) -> anyhow::Result<()> {
    use std::borrow::Cow;
    use toml_span::value::ValueInner;

    let mut root = toml_span::parse(root_toml)?;

    let Some(dep_table) = root.pointer_mut("/workspace/dependencies").and_then(|v| {
        let ValueInner::Table(table) = v.take() else {
            return None;
        };
        Some(table)
    }) else {
        log::info!("no workspace dependencies were declared");
        return Ok(());
    };

    struct RegistryUrlCache {
        urls: Vec<(String, Option<url::Url>)>,
    }

    impl RegistryUrlCache {
        fn get(&mut self, name: &str) -> Option<&url::Url> {
            let i = match self.urls.binary_search_by(|(rn, _)| rn.as_str().cmp(name)) {
                Ok(i) => i,
                Err(i) => {
                    let url = match tame_index::IndexUrl::for_registry_name(None, None, name) {
                        Ok(url) => url::Url::parse(url.as_str())
                            .map_err(|err| {
                                log::warn!(
                                    "unable to parse url '{}' for registry '{name}': {err}",
                                    url.as_str()
                                );
                                err
                            })
                            .ok(),
                        Err(err) => {
                            log::warn!("unable to retrieve url for registry '{name}': {err}");
                            None
                        }
                    };
                    self.urls.insert(i, (name.into(), url));
                    i
                }
            };

            self.urls[i].1.as_ref()
        }
    }

    let mut reg_cache = RegistryUrlCache {
        urls: Default::default(),
    };
    reg_cache.urls.push((
        "crates-io".into(),
        tame_index::IndexUrl::crates_io(None, None, None)
            .map_err(|err| {
                log::warn!("unable to retrieve crates.io url: {err}");
                err
            })
            .ok()
            .and_then(|iu| url::Url::parse(iu.as_str()).ok()),
    ));

    // Just as with normal package dependency tables, the workspace.dependencies can
    // use package = "<real_name>" to rename the dependency, and when
    // setting workspace = true in workspace member tables, they _must_
    // use the same name, ie, foo = { workspace = true, package = "bar" } will
    // only match [workspace.dependencies.foo], not [workspace.dependencies.bar]
    let dependencies = dep_table.into_iter().filter_map(|(key, mut dep)| {
        enum GitSpec<'t> {
            None,
            Branch(Cow<'t, str>),
            Tag(Cow<'t, str>),
            Rev(Cow<'t, str>),
        }

        enum Source<'t> {
            Registry {
                registry: Option<Cow<'t, str>>,
            },
            Path(Cow<'t, str>),
            Git {
                repo: url::Url,
                spec: GitSpec<'t>,
            }
        }

        fn take_string<'de>(name: &str, (key, mut val): (toml_span::value::Key<'de>, toml_span::Value<'de>)) -> Option<Cow<'de, str>> {
            match val.take() {
                ValueInner::String(s) => Some(s),
                other => {
                    log::warn!("[workspace.dependencies.{name}] `{}` was a {} instead of a string", key.name, other.type_str());
                    None
                }
            }
        }

        let (krate_src, version, rename) = match dep.take() {
            ValueInner::Table(mut dt) => {
                let rename = dt.remove("package").and_then(|v| v.as_str().map(|s| toml_span::Spanned::with_span(s.to_owned(), v.span)));

                let name = rename.as_ref().map_or(key.name.as_ref(), |v| v.value.as_str());

                let version = if let Some(version) = dt.remove_entry("version") {
                    let span = version.1.span;
                    let req_s = take_string(name, version)?;
                    req_s.parse::<semver::VersionReq>().map_err(|err| {
                        log::warn!("unable to parse version requirement '{req_s}' for {}: {err}", key.name);
                        err
                    }).ok().map(|vr| toml_span::Spanned::with_span(vr, span))
                } else {
                    None
                };

                // cargo _currently_ allows dependencies to be declared without a version/path/git field, but will
                // make it an error in the future, we'll just discard them because this lint is new
                let source = if let Some(registry) = dt.remove_entry("registry") {
                    let registry = take_string(name, registry)?;

                    Source::Registry {
                        registry: Some(registry)
                    }
                } else if let Some(path) = dt.remove_entry("path") {
                    Source::Path(take_string(name, path)?)
                } else if let Some(repo) = dt.remove_entry("git") {
                    let repo = url::Url::parse(&take_string(name, repo)?).ok()?;
                    let spec = if let Some(rev) = dt.remove_entry("rev") {
                        GitSpec::Rev(take_string(name, rev)?)
                    } else if let Some(branch) = dt.remove_entry("branch") {
                        GitSpec::Branch(take_string(name, branch)?)
                    } else if let Some(tag) = dt.remove_entry("tag") {
                        GitSpec::Tag(take_string(name, tag)?)
                    } else {
                        GitSpec::None
                    };

                    Source::Git { repo, spec }
                } else if version.is_some() {
                    Source::Registry {
                        registry: None,
                    }
                } else {
                    log::warn!("[workspace.dependencies.{name}] did not have a version, git, nor path field");
                    return None;
                };

                (source, version, rename)
            }
            ValueInner::String(req) => {
                let version = req.parse().map_err(|err| {
                    log::warn!("unable to parse version requirement '{req}' for {}: {err}", key.name);
                    err
                }).map(|vr| toml_span::Spanned::with_span(vr, dep.span)).ok();
                (Source::Registry { registry: None }, version, None)
            }
            _ => return None,
        };

        let krate_name = rename.as_ref().map_or(key.name.as_ref(), |r| r.value.as_str());

        let Some(krate) = krates.krates_by_name(krate_name).find_map(|km| {
            match (&km.krate.source, &krate_src) {
                (Some(crate::Source::Git {url, spec, spec_value}), Source::Git { repo, spec: dspec}) => {
                    if url != repo {
                        return None;
                    }

                    let sv = spec_value.as_deref();

                    match (spec, dspec) {
                        (crate::GitSpec::Any, GitSpec::None) => {},
                        (crate::GitSpec::Branch, GitSpec::None) if sv == Some("master") => {},
                        (crate::GitSpec::Branch, GitSpec::Branch(branch)) if sv == Some(branch) => {},
                        (crate::GitSpec::Tag, GitSpec::Tag(tag)) if sv == Some(tag) => {},
                        (crate::GitSpec::Rev, GitSpec::Rev(rev)) if sv == Some(rev) => {},
                        _ => return None,
                    }
                }
                (None, Source::Path(path)) => {
                    let parent = km.krate.manifest_path.parent()?;
                    if path != parent {
                        return None;
                    }
                }
                (Some(reg_src), Source::Registry { registry }) => {
                    let urls = reg_cache.get(registry.as_ref().map_or("crates-io", |r| r.as_ref()))?;
                    match reg_src {
                        crate::Source::CratesIo(_) => {
                            if urls.as_str() != tame_index::CRATES_IO_INDEX {
                                return None;
                            }
                        }
                        crate::Source::Registry(url) | crate::Source::Sparse(url) => {
                            if urls != url {
                                return None;
                            }
                        }
                        _ => return None,
                    }

                    if let Some(req) = &version {
                        if !req.value.matches(&km.krate.version) {
                            return None;
                        }
                    } else {
                        log::warn!("[workspace.dependencies.{krate_name}] did not specify a version");
                    }
                }
                _ => return None,
            }

            Some(km.krate)
        }) else {
            log::error!("[workspace.dependencies.{krate_name}] could not be satisfactorily resolved to a crate");
            return None;
        };

        Some(WorkspaceSpan {
            krate,
            key: key.span,
            value: dep.span,
            version,
            rename,
        })
    });

    for ws_dep in dependencies {
        if let Some(ws) = map.get_mut(&ws_dep.krate.id) {
            ws.workspace = Some(ws_dep);
        } else {
            let name = ws_dep
                .rename
                .as_ref()
                .map_or(&ws_dep.krate.name, |r| r.as_ref());
            log::error!("[workspace.dependencies.{name}] was resolved to {}...which wasn't in the list of available crates. This should be impossible", ws_dep.krate.id);
        }
    }

    Ok(())
}

pub type KrateCoord = Coord;
pub type CfgCoord = Coord;

#[derive(Clone)]
pub struct Coord {
    pub file: FileId,
    pub span: Span,
}

impl Coord {
    pub(crate) fn into_label(self) -> Label {
        self.into()
    }
}

impl From<Coord> for Label {
    fn from(c: Coord) -> Self {
        Label::primary(c.file, c.span)
    }
}

struct NodePrint {
    node: krates::NodeId,
    edge: Option<krates::EdgeId>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    Advisory(crate::advisories::Code),
    Bans(crate::bans::Code),
    License(crate::licenses::Code),
    Source(crate::sources::Code),
    General(general::Code),
}

impl DiagnosticCode {
    pub fn iter() -> impl Iterator<Item = Self> {
        use strum::IntoEnumIterator;
        crate::advisories::Code::iter()
            .map(Self::Advisory)
            .chain(crate::bans::Code::iter().map(Self::Bans))
            .chain(crate::licenses::Code::iter().map(Self::License))
            .chain(crate::sources::Code::iter().map(Self::Source))
            .chain(general::Code::iter().map(Self::General))
    }

    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory(code) => code.into(),
            Self::Bans(code) => code.into(),
            Self::License(code) => code.into(),
            Self::Source(code) => code.into(),
            Self::General(code) => code.into(),
        }
    }
}

use std::fmt;

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DiagnosticCode {
    type Err = strum::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<crate::advisories::Code>()
            .map(Self::Advisory)
            .or_else(|_err| s.parse::<crate::bans::Code>().map(Self::Bans))
            .or_else(|_err| s.parse::<crate::licenses::Code>().map(Self::License))
            .or_else(|_err| s.parse::<crate::sources::Code>().map(Self::Source))
            .or_else(|_err| s.parse::<general::Code>().map(Self::General))
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn codes_unique() {
        let mut unique = std::collections::BTreeSet::<&'static str>::new();

        for code in super::DiagnosticCode::iter() {
            if !unique.insert(code.as_str()) {
                panic!("existing code '{code}'");
            }
        }

        insta::assert_debug_snapshot!(unique);
    }
}
