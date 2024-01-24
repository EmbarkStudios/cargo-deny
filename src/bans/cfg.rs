use crate::{
    cfg::{
        ConfigWithSpec, EmbeddedSpec, PackageSpec, PackageSpecOrExtended, Reason, ValidationContext,
    },
    diag::{Diagnostic, FileId, Label},
    LintLevel, Spanned,
};
use serde::Deserialize;

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExtendedCrateBan {
    #[serde(flatten)]
    pub spec: EmbeddedSpec,
    /// One or more crates that will allow this crate to be used if it is a
    /// direct dependency
    pub wrappers: Option<Spanned<Vec<Spanned<PackageSpec>>>>,
    /// Setting this to true will only emit an error if multiple versions of the
    /// crate are found
    pub deny_multiple_versions: Option<Spanned<bool>>,
    /// The reason for banning the crate
    pub reason: Option<Spanned<String>>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub struct CrateFeatures {
    #[serde(flatten)]
    pub spec: EmbeddedSpec,
    /// All features that are allowed to be used.
    #[serde(default)]
    pub allow: Spanned<Vec<Spanned<String>>>,
    /// All features that are denied.
    #[serde(default)]
    pub deny: Vec<Spanned<String>>,
    /// The actual feature set has to exactly match the `allow` set.
    #[serde(default)]
    pub exact: Spanned<bool>,
    /// The reason for specifying the crate features
    pub reason: Option<Spanned<String>>,
}

#[derive(Deserialize, PartialEq, Eq, Copy, Clone, Default)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
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
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        struct HexStrVisitor;

        impl<'de> serde::de::Visitor<'de> for HexStrVisitor {
            type Value = Checksum;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a sha-256 hex encoded string")
            }

            fn visit_str<E: Error>(self, data: &str) -> Result<Self::Value, E> {
                data.parse().map_err(|err| match err {
                    ChecksumParseError::InvalidLength(len) => {
                        serde::de::Error::invalid_length(len, &"a string with 64 characters")
                    }
                    ChecksumParseError::InvalidValue(c) => serde::de::Error::invalid_value(
                        serde::de::Unexpected::Char(c),
                        &"a hexadecimal character",
                    ),
                })
            }

            fn visit_borrowed_str<E: Error>(self, data: &'de str) -> Result<Self::Value, E> {
                self.visit_str(data)
            }
        }

        deserializer.deserialize_str(HexStrVisitor)
    }
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BypassPath {
    /// The crate-relative path to the executable
    pub path: Spanned<crate::PathBuf>,
    /// An optional sha-256 checksum to ensure that the executable is matched exactly
    pub checksum: Option<Spanned<Checksum>>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Bypass {
    #[serde(flatten)]
    pub spec: EmbeddedSpec,
    pub build_script: Option<Spanned<Checksum>>,
    /// List of features that, if matched, means the build script/proc macro is
    /// not actually executed/run
    #[serde(default)]
    pub required_features: Vec<Spanned<String>>,
    /// List of glob patterns that are allowed. This is much more loose than
    /// `allow`, but can be useful in scenarios where things like test suites or
    /// the like that contain many scripts/test executables that are present in
    /// the packaged source, but are (hopefully) not actually read or executed
    /// during builds
    pub allow_globs: Option<Vec<Spanned<String>>>,
    /// One or more executables that are allowed. If not set all executables are
    /// allowed.
    #[serde(default)]
    pub allow: Vec<BypassPath>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BuildConfig {
    /// List of crates that are allowed to have build scripts. If this is set,
    /// any crates with a build script that aren't listed here will be banned
    pub allow_build_scripts: Option<Spanned<Vec<EmbeddedSpec>>>,
    /// Lint level for when executables are detected within crates with build
    /// scripts or are proc macros, or are a dependency of either of them
    #[serde(default = "crate::lint_deny")]
    pub executables: LintLevel,
    /// The lint level for interpreted scripts
    #[serde(default = "crate::lint_allow")]
    pub interpreted: LintLevel,
    /// List of script extensions that are considered to be executable. These
    /// are always in addition to the builtin ones.
    pub script_extensions: Option<Vec<Spanned<String>>>,
    /// The list of allowed executables, by crate
    pub bypass: Option<Vec<Spanned<Bypass>>>,
    /// If true, enables the built-in glob patterns
    #[serde(default)]
    pub enable_builtin_globs: bool,
    /// If true, all dependencies of proc macro crates or crates with build
    /// scripts are also checked for executables/glob patterns
    #[serde(default)]
    pub include_dependencies: bool,
    /// If true, workspace crates are included
    #[serde(default)]
    pub include_workspace: bool,
    /// If true, archive files are counted as native executables
    #[serde(default)]
    pub include_archives: bool,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CrateSpecWithReason {
    #[serde(flatten)]
    pub spec: EmbeddedSpec,
    /// Reason for this package id being in the list
    pub reason: Option<Spanned<String>>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExtendedTreeSkip {
    #[serde(flatten)]
    pub spec: EmbeddedSpec,
    pub depth: Option<usize>,
    /// Reason the tree is being skipped
    pub reason: Option<Spanned<String>>,
}

pub type CrateBan = PackageSpecOrExtended<ExtendedCrateBan>;
pub type CrateAllow = PackageSpecOrExtended<CrateSpecWithReason>;
pub type CrateSkip = PackageSpecOrExtended<CrateSpecWithReason>;
pub type TreeSkip = PackageSpecOrExtended<ExtendedTreeSkip>;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// How to handle multiple versions of the same crate
    #[serde(default = "crate::lint_warn")]
    pub multiple_versions: LintLevel,
    #[serde(default)]
    pub multiple_versions_include_dev: bool,
    /// How the duplicate graphs are highlighted
    #[serde(default)]
    pub highlight: GraphHighlight,
    /// The crates that will cause us to emit failures
    #[serde(default)]
    pub deny: Vec<CrateBan>,
    /// If specified, means only the listed crates are allowed
    #[serde(default)]
    pub allow: Vec<CrateAllow>,
    /// Allows specifying features that are or are not allowed on crates
    #[serde(default)]
    pub features: Vec<Spanned<CrateFeatures>>,
    /// The default lint level for default features for external, non-workspace
    /// crates, can be overriden in `features` on a crate by crate basis
    #[serde(default)]
    pub external_default_features: Option<Spanned<LintLevel>>,
    /// The default lint level for default features for workspace crates, can be
    /// overriden in `features` on a crate by crate basis
    #[serde(default)]
    pub workspace_default_features: Option<Spanned<LintLevel>>,
    /// If specified, disregards the crate completely
    #[serde(default)]
    pub skip: Vec<CrateSkip>,
    /// If specified, disregards the crate's transitive dependencies
    /// down to a certain depth
    #[serde(default)]
    pub skip_tree: Vec<TreeSkip>,
    /// How to handle wildcard dependencies
    #[serde(default = "crate::lint_allow")]
    pub wildcards: LintLevel,
    /// Wildcard dependencies defined using path attributes will be treated as
    /// if they were [`LintLevel::Allow`] for private crates, but other wildcard
    /// dependencies will be treated as [`LintLevel::Deny`].
    ///
    /// crates.io does not allow packages to be published with path dependencies,
    /// thus this rule will not effect public packages.
    #[serde(default)]
    pub allow_wildcard_paths: bool,
    /// Deprecated and moved into `build.allow_build_scripts`, will eventually
    /// be removed
    pub allow_build_scripts: Option<Spanned<Vec<EmbeddedSpec>>>,
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

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, mut ctx: ValidationContext<'_>) -> Self::ValidCfg {
        let cfg_id = ctx.cfg_id;

        let from = |ctx: &mut ValidationContext<'_>,
                    ekid: PackageSpecOrExtended<CrateSpecWithReason>|
         -> Option<ConfigWithSpec<Reason>> {
            ctx.convert_embedded(ekid, |ext, ctx| {
                Ok(ConfigWithSpec {
                    spec: PackageSpec::from_embedded(ext.spec, ctx)?,
                    inner: ext.reason.map(|r| Some(r)),
                })
            })
        };

        let (denied_multiple_versions, denied) = {
            let mut dmv = Vec::new();
            let mut denied = Vec::new();
            for deny_spec in self.deny {
                let deny_multiple_versions = match &deny_spec {
                    PackageSpecOrExtended::Simple(_) => false,
                    PackageSpecOrExtended::Extended(ext) => {
                        let deny_mv = ext
                            .value
                            .deny_multiple_versions
                            .as_ref()
                            .map_or(false, |dmv| dmv.value);

                        if let Some(mv_span) = ext
                            .value
                            .deny_multiple_versions
                            .as_ref()
                            .and_then(|mv| mv.value.then_some(mv.span.clone()))
                        {
                            if let Some(wrappers_span) = ext
                                .value
                                .wrappers
                                .as_ref()
                                .and_then(|w| (!w.value.is_empty()).then_some(w.span.clone()))
                            {
                                ctx.push(
                                    Diagnostic::error()
                                        .with_message(
                                            "a crate ban was specified with both `wrappers` and `multiple-versions` = true",
                                        )
                                        .with_labels(vec![
                                            Label::secondary(cfg_id, wrappers_span)
                                                .with_message("has one or more `wrappers`"),
                                            Label::secondary(cfg_id, mv_span)
                                                .with_message("has `multiple-versions` set to true"),
                                        ]),
                                );
                            }
                        }

                        deny_mv
                    }
                };

                let Some(deny_spec) = ctx.convert_embedded(deny_spec, |ext, cctx| {
                    Ok(ValidKrateBan {
                        spec: PackageSpec::from_embedded(ext.spec, cctx)?,
                        inner: Some(KrateBan {
                            wrappers: ext.wrappers.map(|spanned| spanned.value),
                            reason: ext.reason,
                        }),
                    })
                }) else {
                    continue;
                };

                if deny_multiple_versions {
                    dmv.push(deny_spec.spec);
                } else {
                    denied.push(deny_spec);
                }
            }

            (dmv, denied)
        };

        let allowed: Vec<_> = self
            .allow
            .into_iter()
            .filter_map(|a| from(&mut ctx, a))
            .collect();
        let skipped: Vec<_> = self
            .skip
            .into_iter()
            .filter_map(|s| from(&mut ctx, s))
            .collect();

        let dupe_crate_diag = |ctx: &mut ValidationContext<'_>,
                               first: (&PackageSpec, &str),
                               second: (&PackageSpec, &str)| {
            let diag = Diagnostic::error()
                .with_message(format!(
                    "a crate was specified in both `{}` and `{}`",
                    second.1, first.1
                ))
                .with_labels(vec![
                    Label::secondary(cfg_id, first.0.span.clone())
                        .with_message(format!("marked as `{}`", first.1)),
                    Label::secondary(cfg_id, second.0.span.clone())
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
                    Label::primary(cfg_id, krate.span.clone()).with_message("crate ban entry"),
                    Label::secondary(cfg_id, allow.span.clone()).with_message("marked as `allow`"),
                    Label::secondary(cfg_id, deny.span.clone()).with_message("marked as `deny`"),
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
            .filter_map(|cf| {
                let (cf, span) = (cf.value, cf.span);
                let spec = ctx.convert_spanned(span, cf.spec)?;
                for allowed in &cf.allow.value {
                    if let Some(denied) = cf.deny.iter().find(|df| df.value == allowed.value) {
                        dupe_feature_diag(&mut ctx, &spec, allowed, denied);
                    }
                }

                Some(ValidKrateFeatures {
                    spec,
                    features: Features {
                        allow: cf.allow,
                        deny: cf.deny,
                        exact: cf.exact,
                    },
                    reason: cf.reason,
                })
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
                                .with_labels(vec![Label::primary(ctx.cfg_id, ext.span.clone())
                                    .with_message("invalid extension")]),
                        );
                        continue;
                    }

                    if let Some(i) = ext.value.chars().position(|c| !c.is_ascii_alphanumeric()) {
                        ctx.diagnostics.push(
                            Diagnostic::error()
                                .with_message("invalid file extension provided")
                                .with_labels(vec![
                                    Label::primary(ctx.cfg_id, ext.span.clone())
                                        .with_message("extension"),
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
                                    .with_labels(vec![Label::primary(
                                        ctx.cfg_id,
                                        ext.span.clone(),
                                    )
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
                    let (aexe, span) = (aexe.value, aexe.span);
                    let Some(spec) = ctx.convert_spanned(span, aexe.spec) else {
                        continue;
                    };
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
                                            .with_labels(vec![Label::primary(
                                                ctx.cfg_id,
                                                ag.span.clone(),
                                            )]),
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
                                    .with_labels(vec![Label::primary(
                                        ctx.cfg_id,
                                        ae.path.span.clone(),
                                    )]),
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
                allow_build_scripts: bc.allow_build_scripts.map(|abs| {
                    abs.value
                        .into_iter()
                        .filter_map(|es| ctx.convert_spanned(abs.span, es))
                        .collect()
                }),
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
                    Label::primary(ctx.cfg_id, abs.span.clone())
                ]));
            Some(ValidBuildConfig {
                allow_build_scripts: Some(
                    abs.value
                        .into_iter()
                        .filter_map(|es| ctx.convert_spanned(abs.span, es))
                        .collect(),
                ),
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

        let tree_skipped = self
            .skip_tree
            .into_iter()
            .filter_map(|st| {
                ctx.convert_embedded(st, |ext, ctx| {
                    Ok(ValidTreeSkip {
                        spec: PackageSpec::from_embedded(ext.spec, ctx)?,
                        inner: Some(ValidExtendedTreeSkipConfig {
                            depth: ext.depth,
                            reason: ext.reason,
                        }),
                    })
                })
            })
            .collect();

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
            tree_skipped,
            build,
        }
    }
}

fn load_builtin_globs(files: &mut crate::diag::Files, gsb: &mut GlobsetBuilder) {
    const BUILTIN_GLOBS: &str = include_str!("builtin_globs.toml");

    #[derive(Deserialize)]
    struct Builtin {
        globs: Vec<Spanned<String>>,
    }

    let bi: Builtin = toml::from_str(BUILTIN_GLOBS).expect("failed to parse builtin_globs.toml");
    let file_id = files.add("builtin_globs.toml", BUILTIN_GLOBS.to_owned());

    for glob in bi.globs {
        gsb.add(
            globset::Glob::new(&glob.value).expect("failed to parse builtin glob"),
            GlobPattern::Builtin((glob, file_id)),
        );
    }
}

#[inline]
pub(crate) fn exact_match<'v, T>(
    arr: &'v [ConfigWithSpec<T>],
    id: &'_ PackageSpec,
) -> Option<&'v PackageSpec> {
    arr.iter()
        .find_map(|sid| (&sid.spec == id).then_some(&sid.spec))
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct KrateBan {
    pub wrappers: Option<Vec<Spanned<PackageSpec>>>,
    pub reason: Option<Spanned<String>>,
}

pub type ValidKrateBan = ConfigWithSpec<KrateBan>;

#[cfg_attr(test, derive(Debug))]
pub struct Features {
    pub allow: Spanned<Vec<Spanned<String>>>,
    pub deny: Vec<Spanned<String>>,
    pub exact: Spanned<bool>,
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct ValidKrateFeatures {
    pub spec: PackageSpec,
    pub features: Features,
    pub reason: Reason,
}

#[cfg_attr(test, derive(Debug))]
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

#[cfg_attr(test, derive(Debug))]
pub struct ValidGlobSet {
    set: globset::GlobSet,
    /// Patterns in the globset for lint output
    pub(crate) patterns: Vec<GlobPattern>,
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

#[cfg_attr(test, derive(Debug))]
pub struct ValidBypass {
    pub spec: PackageSpec,
    pub build_script: Option<Spanned<Checksum>>,
    pub required_features: Vec<Spanned<String>>,
    pub allow_globs: Option<ValidGlobSet>,
    pub allow: Vec<BypassPath>,
}

#[cfg_attr(test, derive(Debug))]
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

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct ValidExtendedTreeSkipConfig {
    pub depth: Option<usize>,
    pub reason: Reason,
}

pub type ValidTreeSkip = ConfigWithSpec<ValidExtendedTreeSkipConfig>;
pub type SpecAndReason = ConfigWithSpec<Reason>;

#[cfg_attr(test, derive(Debug))]
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
    use crate::cfg::{test::*, *};

    #[test]
    fn deserializes_ban_cfg() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bans {
            bans: Config,
        }

        let mut cd: ConfigData<Bans> = load("tests/cfg/bans.toml");

        let mut diags = Vec::new();
        let validated = cd.config.bans.validate(ValidationContext {
            cfg_id: cd.id,
            files: &mut cd.files,
            diagnostics: &mut diags,
        });

        insta::assert_debug_snapshot!(validated);
    }
}
