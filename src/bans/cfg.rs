use crate::{
    cfg::{PackageSpec, PackageSpecOrExtended, Reason, ValidationContext},
    diag::{Diagnostic, FileId, Label},
    LintLevel, Spanned,
};
use toml_span::{de_helpers::TableHelper, value::Value, DeserError, Deserialize};

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CrateBanExtended {
    /// One or more crates that will allow this crate to be used if it is a
    /// direct dependency
    pub wrappers: Option<Spanned<Vec<Spanned<String>>>>,
    /// Setting this to true will only emit an error if multiple versions of the
    /// crate are found
    pub deny_multiple_versions: Option<Spanned<bool>>,
    /// The reason for banning the crate
    pub reason: Option<Reason>,
    /// The crate to use instead of the banned crate, could be just the crate name
    /// or a URL
    pub use_instead: Option<Spanned<String>>,
}

impl<'de> Deserialize<'de> for CrateBanExtended {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let wrappers = th.optional("wrappers");
        let deny_multiple_versions = th.optional("deny-multiple-versions");
        let reason = th.optional_s("reason");
        let use_instead = th.optional("use-instead");
        th.finalize(None)?;

        Ok(Self {
            wrappers,
            deny_multiple_versions,
            reason: reason.map(Reason::from),
            use_instead,
        })
    }
}

//#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CrateFeatures {
    pub spec: PackageSpec,
    /// All features that are allowed to be used.
    pub allow: Spanned<Vec<Spanned<String>>>,
    /// All features that are denied.
    pub deny: Vec<Spanned<String>>,
    /// The actual feature set has to exactly match the `allow` set.
    pub exact: Spanned<bool>,
    /// The reason for specifying the crate features
    pub reason: Option<Reason>,
}

impl<'de> Deserialize<'de> for CrateFeatures {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let spec = PackageSpec::deserialize(value)?;

        let mut th = TableHelper::new(value)?;

        let allow = th.optional("allow").unwrap_or_default();
        let deny = th.optional("deny").unwrap_or_default();
        let exact = th.optional("exact").unwrap_or_default();
        let reason = th.optional_s("reason");
        th.finalize(None)?;

        Ok(Self {
            spec,
            allow,
            deny,
            exact,
            reason: reason.map(Reason::from),
        })
    }
}

#[cfg_attr(test, derive(serde::Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Default, strum::VariantArray, strum::VariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum GraphHighlight {
    /// Highlights the path to a duplicate dependency with the fewest number
    /// of total edges, which tends to make it the best candidate for removing
    SimplestPath,
    /// Highlights the path to the duplicate dependency with the lowest version
    LowestVersion,
    /// Highlights with all of the other configs
    #[default]
    All,
}

crate::enum_deser!(GraphHighlight);

impl GraphHighlight {
    #[inline]
    pub(crate) fn simplest(self) -> bool {
        self == Self::SimplestPath || self == Self::All
    }

    #[inline]
    pub(crate) fn lowest_version(self) -> bool {
        self == Self::LowestVersion || self == Self::All
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Checksum(pub [u8; 32]);

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum ChecksumParseError {
    /// The checksum string had an invalid length
    InvalidLength(usize),
    /// The checksum string contained a non-hex character
    InvalidValue(char),
}

impl std::str::FromStr for Checksum {
    type Err = ChecksumParseError;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        if data.len() != 64 {
            return Err(ChecksumParseError::InvalidLength(data.len()));
        }

        let mut array = [0u8; 32];

        for (ind, chunk) in data.as_bytes().chunks(2).enumerate() {
            #[inline]
            fn parse_hex(b: u8) -> Result<u8, ChecksumParseError> {
                Ok(match b {
                    b'A'..=b'F' => b - b'A' + 10,
                    b'a'..=b'f' => b - b'a' + 10,
                    b'0'..=b'9' => b - b'0',
                    c => {
                        return Err(ChecksumParseError::InvalidValue(c as char));
                    }
                })
            }

            let mut cur = parse_hex(chunk[0])?;
            cur <<= 4;
            cur |= parse_hex(chunk[1])?;

            array[ind] = cur;
        }

        Ok(Self(array))
    }
}

impl<'de> Deserialize<'de> for Checksum {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let val = value.take_string(Some("a sha-256 hex encoded string"))?;

        val.parse().map_err(|err| {
            let err = match err {
                ChecksumParseError::InvalidLength(len) => {
                    toml_span::Error::from((toml_span::ErrorKind::Custom(format!("a sha-256 hex encoded string of length 64 but got a string of length '{len}'").into()), value.span))
                }
                ChecksumParseError::InvalidValue(c) => toml_span::Error::from((toml_span::ErrorKind::Unexpected(c), value.span)),
            };
            err.into()
        })
    }
}

#[cfg(test)]
impl serde::Serialize for Checksum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut hexs = [0; 64];

        const CHARS: &[u8] = b"0123456789abcdef";

        for (i, &byte) in self.0.iter().enumerate() {
            let i = i * 2;
            hexs[i] = CHARS[(byte >> 4) as usize];
            hexs[i + 1] = CHARS[(byte & 0xf) as usize];
        }

        serializer.serialize_str(std::str::from_utf8(&hexs).unwrap())
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, serde::Serialize))]
pub struct BypassPath {
    /// The crate-relative path to the executable
    pub path: Spanned<crate::PathBuf>,
    /// An optional sha-256 checksum to ensure that the executable is matched exactly
    pub checksum: Option<Spanned<Checksum>>,
}

impl<'de> Deserialize<'de> for BypassPath {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let path: Spanned<String> = th.required_s("path")?;
        let checksum = th.optional("checksum");
        th.finalize(None)?;

        Ok(Self {
            path: path.map(),
            checksum,
        })
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Bypass {
    pub spec: PackageSpec,
    pub build_script: Option<Spanned<Checksum>>,
    /// List of features that, if matched, means the build script/proc macro is
    /// not actually executed/run
    pub required_features: Vec<Spanned<String>>,
    /// List of glob patterns that are allowed. This is much more loose than
    /// `allow`, but can be useful in scenarios where things like test suites or
    /// the like that contain many scripts/test executables that are present in
    /// the packaged source, but are (hopefully) not actually read or executed
    /// during builds
    pub allow_globs: Option<Vec<Spanned<String>>>,
    /// One or more executables that are allowed. If not set all executables are
    /// allowed.
    pub allow: Vec<BypassPath>,
}

impl<'de> Deserialize<'de> for Bypass {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let spec = PackageSpec::deserialize(value)?;
        let mut th = TableHelper::new(value)?;
        let build_script = th.optional("build-script");
        let required_features = th.optional("required-features").unwrap_or_default();
        let allow_globs = th.optional("allow-globs");
        let allow = th.optional("allow").unwrap_or_default();
        th.finalize(None)?;

        Ok(Self {
            spec,
            build_script,
            required_features,
            allow_globs,
            allow,
        })
    }
}

pub struct BuildConfig {
    /// List of crates that are allowed to have build scripts. If this is set,
    /// any crates with a build script that aren't listed here will be banned
    pub allow_build_scripts: Option<Vec<PackageSpec>>,
    /// Lint level for when executables are detected within crates with build
    /// scripts or are proc macros, or are a dependency of either of them
    pub executables: LintLevel,
    /// The lint level for interpreted scripts
    pub interpreted: LintLevel,
    /// List of script extensions that are considered to be executable. These
    /// are always in addition to the builtin ones.
    pub script_extensions: Option<Vec<Spanned<String>>>,
    /// The list of allowed executables, by crate
    pub bypass: Option<Vec<Bypass>>,
    /// If true, enables the built-in glob patterns
    pub enable_builtin_globs: bool,
    /// If true, all dependencies of proc macro crates or crates with build
    /// scripts are also checked for executables/glob patterns
    pub include_dependencies: bool,
    /// If true, workspace crates are included
    pub include_workspace: bool,
    /// If true, archive files are counted as native executables
    pub include_archives: bool,
}

impl<'de> Deserialize<'de> for BuildConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let allow_build_scripts = th.optional("allow-build-scripts");
        let executables = th.optional("executables").unwrap_or(LintLevel::Deny);
        let interpreted = th.optional("interpreted").unwrap_or(LintLevel::Allow);
        let script_extensions = th.optional("script-extensions");
        let bypass = th.optional("bypass");
        let enable_builtin_globs = th.optional("enable-builtin-globs").unwrap_or_default();
        let include_dependencies = th.optional("include-dependencies").unwrap_or_default();
        let include_workspace = th.optional("include-workspace").unwrap_or_default();
        let include_archives = th.optional("include-archives").unwrap_or_default();
        th.finalize(None)?;

        Ok(Self {
            allow_build_scripts,
            executables,
            interpreted,
            script_extensions,
            bypass,
            enable_builtin_globs,
            include_dependencies,
            include_workspace,
            include_archives,
        })
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, serde::Serialize))]
pub struct TreeSkipExtended {
    pub depth: Option<usize>,
    /// Reason the tree is being skipped
    pub reason: Option<Reason>,
}

impl<'de> Deserialize<'de> for TreeSkipExtended {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let reason = if value.has_key("reason") {
            Some(Reason::deserialize(value)?)
        } else {
            None
        };

        let mut th = TableHelper::new(value)?;
        let depth = th.optional("depth");
        th.finalize(None)?;
        Ok(Self { depth, reason })
    }
}

pub type CrateBan = PackageSpecOrExtended<CrateBanExtended>;
pub type CrateAllow = PackageSpecOrExtended<Reason>;
pub type CrateSkip = PackageSpecOrExtended<Reason>;
pub type TreeSkip = PackageSpecOrExtended<TreeSkipExtended>;

pub struct Config {
    /// How to handle multiple versions of the same crate
    pub multiple_versions: LintLevel,
    pub multiple_versions_include_dev: bool,
    /// How the duplicate graphs are highlighted
    pub highlight: GraphHighlight,
    /// The crates that will cause us to emit failures
    pub deny: Vec<CrateBan>,
    /// If specified, means only the listed crates are allowed
    pub allow: Vec<CrateAllow>,
    /// Allows specifying features that are or are not allowed on crates
    pub features: Vec<CrateFeatures>,
    /// The default lint level for default features for external, non-workspace
    /// crates, can be overridden in `features` on a crate by crate basis
    pub external_default_features: Option<Spanned<LintLevel>>,
    /// The default lint level for default features for workspace crates, can be
    /// overridden in `features` on a crate by crate basis
    pub workspace_default_features: Option<Spanned<LintLevel>>,
    /// If specified, disregards the crate completely
    pub skip: Vec<CrateSkip>,
    /// If specified, disregards the crate's transitive dependencies
    /// down to a certain depth
    pub skip_tree: Vec<TreeSkip>,
    /// How to handle wildcard dependencies
    pub wildcards: LintLevel,
    /// Wildcard dependencies defined using path attributes will be treated as
    /// if they were [`LintLevel::Allow`] for private crates, but other wildcard
    /// dependencies will be treated as [`LintLevel::Deny`].
    ///
    /// crates.io does not allow packages to be published with path dependencies,
    /// thus this rule will not effect public packages.
    pub allow_wildcard_paths: bool,
    /// Deprecated and moved into `build.allow_build_scripts`, will eventually
    /// be removed
    pub allow_build_scripts: Option<Spanned<Vec<PackageSpec>>>,
    /// Options for crates that run at build time
    pub build: Option<BuildConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            multiple_versions: LintLevel::Warn,
            multiple_versions_include_dev: false,
            highlight: GraphHighlight::All,
            deny: Vec::new(),
            allow: Vec::new(),
            features: Vec::new(),
            external_default_features: None,
            workspace_default_features: None,
            skip: Vec::new(),
            skip_tree: Vec::new(),
            wildcards: LintLevel::Allow,
            allow_wildcard_paths: false,
            allow_build_scripts: None,
            build: None,
        }
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let multiple_versions = th.optional("multiple-versions").unwrap_or(LintLevel::Warn);
        let multiple_versions_include_dev = th
            .optional("multiple-versions-include-dev")
            .unwrap_or_default();
        let highlight = th.optional("highlight").unwrap_or_default();
        let deny = th.optional("deny").unwrap_or_default();
        let allow = th.optional("allow").unwrap_or_default();
        let features = th.optional("features").unwrap_or_default();
        let external_default_features = th.optional("external-default-features");
        let workspace_default_features = th.optional("workspace-default-features");
        let skip = th.optional("skip").unwrap_or_default();
        let skip_tree = th.optional("skip-tree").unwrap_or_default();
        let wildcards = th.optional("wildcards").unwrap_or(LintLevel::Allow);
        let allow_wildcard_paths = th.optional("allow-wildcard-paths").unwrap_or_default();
        let allow_build_scripts = th.optional("allow-build-scripts");
        let build = th.optional("build");

        th.finalize(None)?;

        Ok(Self {
            multiple_versions,
            multiple_versions_include_dev,
            highlight,
            deny,
            allow,
            features,
            external_default_features,
            workspace_default_features,
            skip,
            skip_tree,
            wildcards,
            allow_wildcard_paths,
            allow_build_scripts,
            build,
        })
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, mut ctx: ValidationContext<'_>) -> Self::ValidCfg {
        let cfg_id = ctx.cfg_id;

        let (denied_multiple_versions, denied) = {
            let mut dmulti = Vec::new();
            let mut denied = Vec::new();
            for deny_spec in self.deny {
                let spec = deny_spec.spec;

                let inner = if let Some(extended) = deny_spec.inner {
                    let dmv = extended.deny_multiple_versions;
                    let wrappers = extended.wrappers;

                    if let Some((dmv, wrappers)) = dmv.as_ref().zip(wrappers.as_ref()) {
                        if dmv.value && !wrappers.value.is_empty() {
                            ctx.push(
                                Diagnostic::error()
                                    .with_message(
                                        "a crate ban was specified with both `wrappers` and `deny-multiple-versions` = true",
                                    )
                                    .with_labels(vec![
                                        Label::secondary(cfg_id, wrappers.span)
                                            .with_message(format!("has {} `wrappers`", wrappers.value.len())),
                                        Label::secondary(cfg_id, dmv.span)
                                            .with_message("has `deny-multiple-versions` set to true"),
                                    ]),
                            );
                            continue;
                        }
                    }

                    if dmv.map_or(false, |d| d.value) {
                        dmulti.push(spec);
                        continue;
                    }

                    Some(KrateBan {
                        wrappers: wrappers.map(|sv| sv.value),
                        reason: extended.reason,
                        use_instead: extended.use_instead,
                    })
                } else {
                    None
                };

                denied.push(ValidKrateBan { spec, inner });
            }

            (dmulti, denied)
        };

        let allowed = self.allow;
        let skipped = self.skip;

        let dupe_crate_diag = |ctx: &mut ValidationContext<'_>,
                               first: (&PackageSpec, &str),
                               second: (&PackageSpec, &str)| {
            let diag = Diagnostic::error()
                .with_message(format!(
                    "a crate was specified in both `{}` and `{}`",
                    second.1, first.1
                ))
                .with_labels(vec![
                    Label::secondary(cfg_id, first.0.name.span)
                        .with_message(format!("marked as `{}`", first.1)),
                    Label::secondary(cfg_id, second.0.name.span)
                        .with_message(format!("marked as `{}`", second.1)),
                ]);

            ctx.push(diag);
        };

        let dupe_feature_diag = |ctx: &mut ValidationContext<'_>,
                                 krate: &PackageSpec,
                                 allow: &Spanned<String>,
                                 deny: &Spanned<String>| {
            let diag = Diagnostic::error()
                .with_message("a crate feature was specified as both allowed and denied")
                .with_labels(vec![
                    Label::primary(cfg_id, krate.name.span).with_message("crate ban entry"),
                    Label::secondary(cfg_id, allow.span).with_message("marked as `allow`"),
                    Label::secondary(cfg_id, deny.span).with_message("marked as `deny`"),
                ]);

            ctx.push(diag);
        };

        for d in &denied {
            if let Some(dupe) = exact_match(&allowed, &d.spec) {
                dupe_crate_diag(&mut ctx, (&d.spec, "deny"), (dupe, "allow"));
            }

            if let Some(dupe) = exact_match(&skipped, &d.spec) {
                dupe_crate_diag(&mut ctx, (&d.spec, "deny"), (dupe, "skip"));
            }
        }

        for all in &allowed {
            if let Some(dupe) = exact_match(&skipped, &all.spec) {
                dupe_crate_diag(&mut ctx, (&all.spec, "allow"), (dupe, "skip"));
            }
        }

        // Ensure that a feature isn't both allowed and denied
        let features = self
            .features
            .into_iter()
            .map(|cf| {
                let spec = cf.spec;
                for allowed in &cf.allow.value {
                    if let Some(denied) = cf.deny.iter().find(|df| df.value == allowed.value) {
                        dupe_feature_diag(&mut ctx, &spec, allowed, denied);
                    }
                }

                ValidKrateFeatures {
                    spec,
                    features: Features {
                        allow: cf.allow,
                        deny: cf.deny,
                        exact: cf.exact,
                    },
                    reason: cf.reason.map(Reason::from),
                }
            })
            .collect();

        let build = if let Some(bc) = self.build {
            // Give higher precedence to the user's extensions
            let mut gsb = GlobsetBuilder::new();
            if let Some(extensions) = bc.script_extensions {
                for ext in extensions {
                    // This top level config should only be extensions, not glob patterns
                    if !ext.value.is_ascii() {
                        ctx.diagnostics.push(
                            Diagnostic::error()
                                .with_message("non-ascii file extension provided")
                                .with_labels(vec![Label::primary(ctx.cfg_id, ext.span)
                                    .with_message("invalid extension")]),
                        );
                        continue;
                    }

                    if let Some(i) = ext.value.chars().position(|c| !c.is_ascii_alphanumeric()) {
                        ctx.diagnostics.push(
                            Diagnostic::error()
                                .with_message("invalid file extension provided")
                                .with_labels(vec![
                                    Label::primary(ctx.cfg_id, ext.span).with_message("extension"),
                                    Label::secondary(
                                        ctx.cfg_id,
                                        ext.span.start + i..ext.span.start + i + 1,
                                    )
                                    .with_message("invalid character"),
                                ]),
                        );
                        continue;
                    }

                    match globset::Glob::new(&format!("*.{}", ext.value)) {
                        Ok(glob) => {
                            gsb.add(glob, GlobPattern::User(ext));
                        }
                        Err(err) => {
                            ctx.diagnostics.push(
                                Diagnostic::error()
                                    .with_message(format!("invalid glob pattern: {err}"))
                                    .with_labels(vec![Label::primary(ctx.cfg_id, ext.span)
                                        .with_message("extension")]),
                            );
                        }
                    }
                }
            }

            if bc.enable_builtin_globs {
                load_builtin_globs(ctx.files, &mut gsb);
            }

            let script_extensions = gsb.build().unwrap_or_else(|err| {
                ctx.diagnostics
                    .push(Diagnostic::error().with_message(format!(
                        "failed to build script extensions glob set: {err}"
                    )));
                ValidGlobSet::default()
            });

            let bypass = if let Some(aexes) = bc.bypass {
                let mut aex = Vec::new();

                for aexe in aexes {
                    let spec = aexe.spec;

                    let allow_globs = if let Some(allow_globs) = aexe.allow_globs {
                        let mut gsb = GlobsetBuilder::new();

                        for ag in allow_globs {
                            match globset::Glob::new(&ag.value) {
                                Ok(glob) => {
                                    gsb.add(glob, GlobPattern::User(ag));
                                }
                                Err(err) => {
                                    ctx.diagnostics.push(
                                        Diagnostic::error()
                                            .with_message(format!("invalid glob pattern: {err}"))
                                            .with_labels(vec![Label::primary(ctx.cfg_id, ag.span)]),
                                    );
                                }
                            }
                        }

                        match gsb.build() {
                            Ok(set) => Some(set),
                            Err(err) => {
                                ctx.diagnostics
                                    .push(Diagnostic::error().with_message(format!(
                                        "failed to build script extensions glob set: {err}"
                                    )));
                                None
                            }
                        }
                    } else {
                        None
                    };

                    let mut allow = aexe.allow;
                    allow.retain(|ae| {
                        let keep = ae.path.value.is_relative();
                        if !keep {
                            ctx.diagnostics.push(
                                Diagnostic::error()
                                    .with_message("absolute paths are not allowed")
                                    .with_labels(vec![Label::primary(ctx.cfg_id, ae.path.span)]),
                            );
                        }

                        keep
                    });
                    allow.sort_by(|a, b| a.path.value.cmp(&b.path.value));

                    aex.push(ValidBypass {
                        spec,
                        build_script: aexe.build_script,
                        required_features: aexe.required_features,
                        allow,
                        allow_globs,
                    });
                }

                aex
            } else {
                Vec::new()
            };

            Some(ValidBuildConfig {
                allow_build_scripts: bc.allow_build_scripts,
                executables: bc.executables,
                script_extensions,
                bypass,
                include_dependencies: bc.include_dependencies,
                include_workspace: bc.include_workspace,
                include_archives: bc.include_archives,
                interpreted: bc.interpreted,
            })
        } else if let Some(abs) = self.allow_build_scripts {
            ctx.push(Diagnostic::warning()
                .with_message("[bans.allow-build-scripts] has been deprecated in favor of [bans.build.allow-build-scripts], this will become an error in the future")
                .with_labels(vec![
                    Label::primary(ctx.cfg_id, abs.span)
                ]));
            Some(ValidBuildConfig {
                allow_build_scripts: Some(abs.value),
                executables: LintLevel::Allow,
                script_extensions: ValidGlobSet::default(),
                bypass: Vec::new(),
                include_dependencies: false,
                include_workspace: false,
                include_archives: false,
                interpreted: LintLevel::Warn,
            })
        } else {
            None
        };

        ValidConfig {
            file_id: ctx.cfg_id,
            multiple_versions: self.multiple_versions,
            multiple_versions_include_dev: self.multiple_versions_include_dev,
            highlight: self.highlight,
            denied,
            denied_multiple_versions,
            allowed,
            features,
            external_default_features: self.external_default_features,
            workspace_default_features: self.workspace_default_features,
            skipped,
            wildcards: self.wildcards,
            allow_wildcard_paths: self.allow_wildcard_paths,
            tree_skipped: self.skip_tree,
            build,
        }
    }
}

fn load_builtin_globs(files: &mut crate::diag::Files, gsb: &mut GlobsetBuilder) {
    const BUILTIN_GLOBS: &str = include_str!("builtin_globs.toml");

    let mut biv = toml_span::parse(BUILTIN_GLOBS).expect("failed to parse builtin_globs.toml");
    let mut th = TableHelper::new(&mut biv).expect("builtin_globs.toml does not have a root table");

    let globs: Vec<Spanned<String>> = th.required("globs").expect("failed to find 'globs' array");

    let file_id = files.add("builtin_globs.toml", BUILTIN_GLOBS.to_owned());

    for glob in globs {
        gsb.add(
            globset::Glob::new(&glob.value).expect("failed to parse builtin glob"),
            GlobPattern::Builtin((glob, file_id)),
        );
    }
}

#[inline]
pub(crate) fn exact_match<'v, T>(
    arr: &'v [PackageSpecOrExtended<T>],
    id: &'_ PackageSpec,
) -> Option<&'v PackageSpec> {
    arr.iter()
        .find_map(|sid| (&sid.spec == id).then_some(&sid.spec))
}

#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct KrateBan {
    pub wrappers: Option<Vec<Spanned<String>>>,
    pub reason: Option<Reason>,
    pub use_instead: Option<Spanned<String>>,
}

pub(crate) type ValidKrateBan = PackageSpecOrExtended<KrateBan>;

#[cfg_attr(test, derive(serde::Serialize))]
pub struct Features {
    pub allow: Spanned<Vec<Spanned<String>>>,
    pub deny: Vec<Spanned<String>>,
    pub exact: Spanned<bool>,
}

#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct ValidKrateFeatures {
    pub spec: PackageSpec,
    pub features: Features,
    pub reason: Option<Reason>,
}

#[cfg_attr(test, derive(serde::Serialize))]
pub enum GlobPattern {
    Builtin((Spanned<String>, FileId)),
    User(Spanned<String>),
}

struct GlobsetBuilder {
    builder: globset::GlobSetBuilder,
    patterns: Vec<GlobPattern>,
}

impl GlobsetBuilder {
    fn new() -> Self {
        Self {
            builder: globset::GlobSetBuilder::new(),
            patterns: Vec::new(),
        }
    }

    fn add(&mut self, glob: globset::Glob, pattern: GlobPattern) {
        self.builder.add(glob);
        self.patterns.push(pattern);
    }

    fn build(self) -> anyhow::Result<ValidGlobSet> {
        use anyhow::Context as _;
        let set = self.builder.build().context("unable to build globset")?;

        Ok(ValidGlobSet {
            set,
            patterns: self.patterns,
        })
    }
}

pub struct ValidGlobSet {
    set: globset::GlobSet,
    /// Patterns in the globset for lint output
    pub(crate) patterns: Vec<GlobPattern>,
}

#[cfg(test)]
impl serde::Serialize for ValidGlobSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.patterns.iter().filter_map(|gp| {
            let GlobPattern::User(gp) = gp else {
                return None;
            };
            Some(gp)
        }))
    }
}

impl Default for ValidGlobSet {
    fn default() -> Self {
        Self {
            set: globset::GlobSet::empty(),
            patterns: Vec::new(),
        }
    }
}

impl ValidGlobSet {
    #[inline]
    pub fn matches(
        &self,
        path: &globset::Candidate<'_>,
        indices: &mut Vec<usize>,
    ) -> Option<Vec<&GlobPattern>> {
        self.set.matches_candidate_into(path, indices);
        (!indices.is_empty()).then(|| indices.iter().map(|i| &self.patterns[*i]).collect())
    }
}

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidBypass {
    pub spec: PackageSpec,
    pub build_script: Option<Spanned<Checksum>>,
    pub required_features: Vec<Spanned<String>>,
    pub allow_globs: Option<ValidGlobSet>,
    pub allow: Vec<BypassPath>,
}

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidBuildConfig {
    pub allow_build_scripts: Option<Vec<PackageSpec>>,
    pub executables: LintLevel,
    pub script_extensions: ValidGlobSet,
    pub bypass: Vec<ValidBypass>,
    pub include_dependencies: bool,
    pub include_workspace: bool,
    pub include_archives: bool,
    pub interpreted: LintLevel,
}

pub type ValidTreeSkip = PackageSpecOrExtended<TreeSkipExtended>;
pub type SpecAndReason = PackageSpecOrExtended<Reason>;

#[cfg_attr(test, derive(serde::Serialize))]
pub struct ValidConfig {
    pub file_id: FileId,
    pub multiple_versions: LintLevel,
    pub multiple_versions_include_dev: bool,
    pub highlight: GraphHighlight,
    pub(crate) denied: Vec<ValidKrateBan>,
    pub(crate) denied_multiple_versions: Vec<PackageSpec>,
    pub(crate) allowed: Vec<SpecAndReason>,
    pub(crate) features: Vec<ValidKrateFeatures>,
    pub external_default_features: Option<Spanned<LintLevel>>,
    pub workspace_default_features: Option<Spanned<LintLevel>>,
    pub(crate) skipped: Vec<SpecAndReason>,
    pub(crate) tree_skipped: Vec<ValidTreeSkip>,
    pub wildcards: LintLevel,
    pub allow_wildcard_paths: bool,
    pub build: Option<ValidBuildConfig>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::ConfigData;

    #[test]
    fn deserializes_ban_cfg() {
        struct Bans {
            bans: Config,
        }

        impl<'de> toml_span::Deserialize<'de> for Bans {
            fn deserialize(
                value: &mut toml_span::value::Value<'de>,
            ) -> Result<Self, toml_span::DeserError> {
                let mut th = toml_span::de_helpers::TableHelper::new(value)?;
                let bans = th.required("bans").unwrap();
                th.finalize(None)?;
                Ok(Self { bans })
            }
        }

        let cd = ConfigData::<Bans>::load("tests/cfg/bans.toml");
        let validated = cd.validate(|b| b.bans);

        insta::assert_json_snapshot!(validated);
    }
}
