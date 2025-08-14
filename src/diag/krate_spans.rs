use super::{FileId, Files, Span};
use crate::{Kid, Krate, Krates};
use std::collections::BTreeMap;

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
    deps: Vec<ManifestDep<'k>>,
    ignore: u8,
}

const NORMAL: u8 = 0x1;
const DEV: u8 = 0x2;
const BUILD: u8 = 0x4;

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

                        let Some(dep_table) = root.pointer(pointer) else {
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

                    let dep_table = root.pointer(pointer)?;

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
                log::error!(
                    "dependency {krate} -> {dep_krate} is not a string nor table, this should be invalid..."
                );
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

        let ignore = if krates.workspace_members().any(|wm| {
            let krates::Node::Krate { id, .. } = wm else {
                return false;
            };
            id == &krate.id
        }) {
            let mut ignore = 0;

            if let Some(val) = root
                .pointer("/package/metadata/cargo-deny/workspace-duplicates")
                .and_then(|arr| arr.as_array())
            {
                ignore = NORMAL | DEV | BUILD;

                for v in val {
                    let Some(s) = v.as_str() else {
                        continue;
                    };
                    match s {
                        "" => ignore &= !NORMAL,
                        "dev" => ignore &= !DEV,
                        "build" => ignore &= !BUILD,
                        _ => {}
                    }
                }
            }

            ignore
        } else {
            0
        };

        Ok(Self {
            deps,
            krate,
            id: 0,
            ignore,
        })
    }

    /// Retrieves the dependencies from the manifest.
    ///
    /// If `filter` is true, the dependencies that the manifest itself states it
    /// wants to ignore via metadata are not yielded
    pub fn deps(&self, filter: bool) -> impl Iterator<Item = &ManifestDep<'k>> {
        self.deps.iter().filter(move |dep| {
            !filter
                || (match dep.dep.kind {
                    krates::cm::DependencyKind::Normal => NORMAL,
                    krates::cm::DependencyKind::Development => DEV,
                    krates::cm::DependencyKind::Build => BUILD,
                } & self.ignore)
                    == 0
        })
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
    /// If this dependency was patched, this it the span of the original key
    pub patched: Option<toml_span::Span>,
}

pub struct UnusedWorkspaceDep {
    pub key: Span,
    pub value: Span,
    pub version: Option<toml_span::Spanned<semver::VersionReq>>,
    pub rename: Option<toml_span::Spanned<String>>,
    pub patched: Option<toml_span::Span>,
}

pub struct Spans<'k> {
    pub lock: LockSpan,
    pub workspace: Option<WorkspaceSpan<'k>>,
    pub manifest: Option<Manifest<'k>>,
}

pub struct KrateSpans<'k> {
    spans: BTreeMap<&'k Kid, Spans<'k>>,
    /// The ID of the workspace manifest
    pub workspace_id: Option<FileId>,
    /// The ID of the (synthesized) lockfile
    pub lock_id: FileId,
    /// `[workspace.dependencies]` that are not actually used in the graph
    pub unused_workspace_deps: Vec<UnusedWorkspaceDep>,
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
            .map(
                |(krate, _)| -> anyhow::Result<Option<(Manifest<'_>, String)>> {
                    // If the krate's source is not a local path we aren't really concerned with
                    // its contents (for now)
                    if krate.source.is_some() {
                        return Ok(None);
                    }

                    let contents =
                        std::fs::read_to_string(&krate.manifest_path).with_context(|| {
                            format!("failed to read manifest {}", krate.manifest_path)
                        })?;
                    let manifest = Manifest::parse(krate, krates, &contents)?;
                    Ok(Some((manifest, contents)))
                },
            )
            .collect_into_vec(&mut manifests);

        let mut spans = okrates
            .into_iter()
            .zip(manifests)
            .map(|((krate, lock), res)| {
                let manifest = match res {
                    Ok(Some((mut manifest, contents))) => {
                        manifest.id = files.add(krate.manifest_path.clone(), contents);
                        Some(manifest)
                    }
                    Ok(None) => None,
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

        let unused_workspace_deps = if let Some(wid) = workspace_id {
            let workspace_root = files.source(wid);
            match read_workspace_deps(workspace_root, krates, &mut spans) {
                Ok(unused) => unused,
                Err(err) => {
                    log::error!(
                        "failed to resolve [workspace.dependencies] from '{}': {err:#}",
                        krates.workspace_root().join("Cargo.toml")
                    );
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        Self {
            lock_id,
            workspace_id,
            spans,
            unused_workspace_deps,
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

use std::borrow::Cow;

#[derive(Debug)]
enum GitSpec<'t> {
    None,
    Branch(Cow<'t, str>),
    Tag(Cow<'t, str>),
    Rev(Cow<'t, str>),
}

#[derive(Debug)]
enum Source<'t> {
    Registry { registry: Option<Cow<'t, str>> },
    Path(Cow<'t, str>),
    Git { repo: url::Url, spec: GitSpec<'t> },
}

#[derive(Debug)]
struct PackageSource<'t> {
    source: Source<'t>,
    version: Option<toml_span::Spanned<semver::VersionReq>>,
    rename: Option<toml_span::Spanned<Cow<'t, str>>>,
}

use anyhow::Context as _;
use toml_span::value::ValueInner;

impl<'t> PackageSource<'t> {
    fn parse(
        section: &str,
        (key, mut val): (&toml_span::value::Key<'t>, toml_span::Value<'t>),
    ) -> anyhow::Result<Self> {
        fn take_string<'de>(
            section: &str,
            name: &str,
            (key, mut val): (toml_span::value::Key<'de>, toml_span::Value<'de>),
        ) -> anyhow::Result<Cow<'de, str>> {
            match val.take() {
                ValueInner::String(s) => Ok(s),
                other => {
                    anyhow::bail!(
                        "[{section}.{name}] `{}` was a {} instead of a string",
                        key.name,
                        other.type_str()
                    );
                }
            }
        }

        let this = match val.take() {
            ValueInner::Table(mut dt) => {
                let rename = dt.remove_entry("package").and_then(|v| {
                    let span = v.1.span;
                    take_string(section, &key.name, v)
                        .ok()
                        .map(|v| toml_span::Spanned::with_span(v, span))
                });

                let name = rename
                    .as_ref()
                    .map_or(key.name.as_ref(), |v| v.value.as_ref());

                let version = if let Some(version) = dt.remove_entry("version") {
                    let span = version.1.span;
                    let req_s = take_string(section, name, version)?;

                    let vr = req_s.parse::<semver::VersionReq>().with_context(|| {
                        format!("[{section}.{key}].version '{req_s}' could not be parsed")
                    })?;
                    Some(toml_span::Spanned::with_span(vr, span))
                } else {
                    None
                };

                // cargo _currently_ allows dependencies to be declared without a version/path/git field, but will
                // make it an error in the future, we'll just discard them because this lint is new
                let source = if let Some(registry) = dt.remove_entry("registry") {
                    let registry = take_string(section, name, registry)?;

                    Source::Registry {
                        registry: Some(registry),
                    }
                } else if let Some(path) = dt.remove_entry("path") {
                    Source::Path(take_string(section, name, path)?)
                } else if let Some(repo) = dt.remove_entry("git") {
                    let repo = url::Url::parse(&take_string(section, name, repo)?)?;
                    let spec = if let Some(rev) = dt.remove_entry("rev") {
                        GitSpec::Rev(take_string(section, name, rev)?)
                    } else if let Some(branch) = dt.remove_entry("branch") {
                        GitSpec::Branch(take_string(section, name, branch)?)
                    } else if let Some(tag) = dt.remove_entry("tag") {
                        GitSpec::Tag(take_string(section, name, tag)?)
                    } else {
                        GitSpec::None
                    };

                    Source::Git { repo, spec }
                } else if version.is_some() {
                    Source::Registry { registry: None }
                } else {
                    anyhow::bail!("[{section}.{key}] did not have a version, git, nor path field");
                };

                Self {
                    source,
                    version,
                    rename,
                }
            }
            ValueInner::String(req) => {
                let version = req
                    .parse()
                    .with_context(|| format!("[{section}].{key} '{req}' could not be parsed"))?;
                let version = Some(toml_span::Spanned::with_span(version, val.span));

                Self {
                    source: Source::Registry { registry: None },
                    version,
                    rename: None,
                }
            }
            other => anyhow::bail!(
                "[{section}.{key}] was a '{}' instead of a table or version string",
                other.type_str()
            ),
        };

        Ok(this)
    }
}

/// Gather the crates declared in the `[workspace.dependencies]` section
fn read_workspace_deps<'k>(
    root_toml: &str,
    krates: &'k Krates,
    map: &mut BTreeMap<&'k Kid, Spans<'k>>,
) -> anyhow::Result<Vec<UnusedWorkspaceDep>> {
    use toml_span::value::ValueInner;

    let config_root = krates.workspace_root();
    let mut root = toml_span::parse(root_toml)?;

    struct RegistryUrlCache {
        urls: Vec<(String, Option<url::Url>)>,
    }

    impl RegistryUrlCache {
        fn get(&mut self, name: &str, config_root: &crate::Path) -> Option<&url::Url> {
            let i = match self.urls.binary_search_by(|(rn, _)| rn.as_str().cmp(name)) {
                Ok(i) => i,
                Err(i) => {
                    let url = match tame_index::IndexUrl::for_registry_name(
                        Some(config_root.into()),
                        None,
                        name,
                    ) {
                        Ok(url) => url::Url::parse(url.as_str())
                            .inspect_err(|err| {
                                log::warn!(
                                    "unable to parse url '{}' for registry '{name}': {err}",
                                    url.as_str()
                                );
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
        tame_index::IndexUrl::crates_io(Some(config_root.into()), None, None)
            .map_err(|err| {
                log::warn!("unable to retrieve crates.io url: {err}");
                err
            })
            .ok()
            .and_then(|iu| url::Url::parse(iu.as_str()).ok()),
    ));

    // Grab any patches first, as they override the source information for any workspace dependencies
    // For now we only support [patch.crates-io] as that is the only patch that
    // a vast majority of workspaces will use, and honestly patching a git dependency
    // or custom registry seems kinda pointless to me
    let mut patches = match read_patches(&mut root) {
        Ok(p) => p,
        Err(err) => {
            log::error!("failed to read [patch.crates-io] table: {err}");
            Default::default()
        }
    };

    enum WsDep<'k> {
        Resolved(WorkspaceSpan<'k>),
        Unresolved(UnusedWorkspaceDep),
    }

    let Some(dep_table) = root.pointer_mut("/workspace/dependencies").and_then(|v| {
        let ValueInner::Table(table) = v.take() else {
            return None;
        };
        Some(table)
    }) else {
        log::info!("no workspace dependencies were declared");
        return Ok(Vec::new());
    };

    // Just as with normal package dependency tables, the workspace.dependencies can
    // use package = "<real_name>" to rename the dependency, and when
    // setting workspace = true in workspace member tables, they _must_
    // use the same name, ie, foo = { workspace = true, package = "bar" } will
    // only match [workspace.dependencies.foo], not [workspace.dependencies.bar]
    let dependencies = dep_table.into_iter().filter_map(|(mut key, dep)| {
        let value = dep.span;
        let mut ws_src = match PackageSource::parse("workspace.dependencies", (&key, dep)) {
            Ok(psrc) => psrc,
            Err(err) => {
                log::error!("failed to read source for [workspace.dependencies.{key}: {err:#}");
                return None;
            }
        };

        let mut patched = None;
        // If the dependency is patched, use its source information instead as it is what
        // will actually be present in the graph
        if matches!(&ws_src.source, Source::Registry { registry: None })
            && let Some((pkey, psrc)) = patches.remove_entry(&key)
        {
            patched = Some(key.span);
            key = pkey;
            ws_src = psrc;
        }

        let krate_name = ws_src
            .rename
            .as_ref()
            .map_or(key.name.as_ref(), |r| r.value.as_ref());

        let Some(krate) = krates.krates_by_name(krate_name).find_map(|km| {
            match (&km.krate.source, &ws_src.source) {
                (
                    Some(crate::Source::Git {
                        url,
                        spec,
                        spec_value,
                    }),
                    Source::Git { repo, spec: dspec },
                ) => {
                    if url.host_str() != repo.host_str()
                        || url.path().trim_end_matches(".git")
                            != repo.path().trim_end_matches(".git")
                    {
                        return None;
                    }

                    let sv = spec_value.as_deref();

                    match (spec, dspec) {
                        (crate::GitSpec::Any, GitSpec::None) => {}
                        (crate::GitSpec::Branch, GitSpec::None) if sv == Some("master") => {}
                        (crate::GitSpec::Branch, GitSpec::Branch(branch)) if sv == Some(branch) => {
                        }
                        (crate::GitSpec::Tag, GitSpec::Tag(tag)) if sv == Some(tag) => {}
                        (crate::GitSpec::Rev, GitSpec::Rev(rev)) if sv == Some(rev) => {}
                        _ => return None,
                    }
                }
                (None, Source::Path(path)) => {
                    // Paths should always be workspace relative, but we still need to
                    // account for parent paths to handle overly complicated nested workspace
                    // situations
                    let dir = km.krate.manifest_path.parent()?;
                    let path = crate::Path::new(path);

                    // Handle cases of current '.' or parent '..' directories
                    if path.as_str().contains('.') {
                        let mut pb = krates.workspace_root().to_owned();
                        for comp in path.components() {
                            match comp {
                                camino::Utf8Component::CurDir => {}
                                camino::Utf8Component::Normal(comp) => pb.push(comp),
                                camino::Utf8Component::ParentDir => {
                                    if !pb.pop() {
                                        break;
                                    }
                                }
                                camino::Utf8Component::RootDir
                                | camino::Utf8Component::Prefix(_) => {
                                    // We _could_ warn here, because absolute paths are
                                    // a terrible idea, but whatever
                                    if dir != path {
                                        return None;
                                    }

                                    break;
                                }
                            }
                        }
                    } else if dir
                        .strip_prefix(krates.workspace_root())
                        .is_ok_and(|dir| dir != path)
                    {
                        return None;
                    }
                }
                (Some(reg_src), Source::Registry { registry }) => {
                    let urls = reg_cache.get(
                        registry.as_ref().map_or("crates-io", |r| r.as_ref()),
                        config_root,
                    )?;
                    match reg_src {
                        crate::Source::CratesIo(is_sparse) => {
                            let crates_io = if *is_sparse {
                                tame_index::index::sparse::CRATES_IO_HTTP_INDEX
                            } else {
                                tame_index::index::git::CRATES_IO_INDEX
                            };

                            if urls.as_str() != crates_io {
                                return None;
                            }
                        }
                        crate::Source::Registry(url) | crate::Source::Sparse(url) => {
                            if urls != url {
                                return None;
                            }
                        }
                        crate::Source::Git { .. } => return None,
                    }

                    if let Some(req) = &ws_src.version {
                        if !req.value.matches(&km.krate.version) {
                            return None;
                        }
                    } else {
                        log::warn!(
                            "[workspace.dependencies.{krate_name}] did not specify a version"
                        );
                    }
                }
                _ => return None,
            }

            Some(km.krate)
        }) else {
            return Some(WsDep::Unresolved(UnusedWorkspaceDep {
                key: key.span,
                value,
                version: ws_src.version,
                rename: ws_src.rename.map(|s| s.map()),
                patched,
            }));
        };

        Some(WsDep::Resolved(WorkspaceSpan {
            krate,
            key: key.span,
            value,
            version: ws_src.version,
            patched,
            rename: ws_src.rename.map(|s| s.map()),
        }))
    });

    let mut ur = Vec::new();
    for ws_dep in dependencies {
        match ws_dep {
            WsDep::Resolved(ws_dep) => {
                if let Some(ws) = map.get_mut(&ws_dep.krate.id) {
                    ws.workspace = Some(ws_dep);
                } else {
                    let name = ws_dep
                        .rename
                        .as_ref()
                        .map_or(&ws_dep.krate.name, |r| r.as_ref());
                    log::error!(
                        "[workspace.dependencies.{name}] was resolved to {}...which wasn't in the list of available crates. This should be impossible",
                        ws_dep.krate.id
                    );
                }
            }
            WsDep::Unresolved(unresolved) => {
                ur.push(unresolved);
            }
        }
    }

    Ok(ur)
}

fn read_patches<'de>(
    root: &mut toml_span::Value<'de>,
) -> anyhow::Result<std::collections::BTreeMap<toml_span::value::Key<'de>, PackageSource<'de>>> {
    let Some(patches) = root.pointer_mut("/patch/crates-io") else {
        return Ok(Default::default());
    };

    let patches = match patches.take() {
        ValueInner::Table(table) => table,
        other => {
            anyhow::bail!(
                "[patch.crates-io] was not a table but a {}",
                other.type_str()
            );
        }
    };

    let mut map = std::collections::BTreeMap::new();
    for (key, value) in patches {
        match PackageSource::parse("patch.crates-io", (&key, value)) {
            Ok(psrc) => {
                map.insert(key, psrc);
            }
            Err(err) => {
                log::error!(
                    "failed to read source information for [patch.crates-io].{key}: {err:#}"
                );
            }
        }
    }

    Ok(map)
}
