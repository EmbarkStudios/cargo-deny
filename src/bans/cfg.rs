use super::KrateId;
use crate::{
    diag::{Diagnostic, FileId, Label},
    LintLevel, Spanned,
};
use semver::VersionReq;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub struct CrateId {
    // The name of the crate
    pub name: String,
    /// The version constraints of the crate
    pub version: Option<VersionReq>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CrateBan {
    pub name: Spanned<String>,
    pub version: Option<VersionReq>,
    /// One or more crates that will allow this crate to be used if it is a
    /// direct dependency
    pub wrappers: Option<Spanned<Vec<Spanned<String>>>>,
    /// Setting this to true will only emit an error if multiple
    // versions of the crate are found
    pub deny_multiple_versions: Option<Spanned<bool>>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub struct CrateFeatures {
    pub name: Spanned<String>,
    pub version: Option<VersionReq>,
    /// All features that are allowed to be used.
    #[serde(default)]
    pub allow: Spanned<Vec<Spanned<String>>>,
    /// All features that are denied.
    #[serde(default)]
    pub deny: Vec<Spanned<String>>,
    /// The actual feature set has to exactly match the `allow` set.
    #[serde(default)]
    pub exact: Spanned<bool>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TreeSkip {
    #[serde(flatten)]
    pub id: CrateId,
    pub depth: Option<usize>,
}

const fn highlight() -> GraphHighlight {
    GraphHighlight::All
}

#[derive(Deserialize, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum GraphHighlight {
    /// Highlights the path to a duplicate dependency with the fewest number
    /// of total edges, which tends to make it the best candidate for removing
    SimplestPath,
    /// Highlights the path to the duplicate dependency with the lowest version
    LowestVersion,
    /// Highlights with all of the other configs
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
pub struct Checksum([u8; 32]);

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
pub struct AllowedExecutable {
    /// The crate-relative path to the executable
    pub path: Spanned<crate::PathBuf>,
    /// An optional sha-256 checksum to ensure that the executable is matched exactly
    pub checksum: Option<Spanned<Checksum>>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Executables {
    pub name: Spanned<String>,
    pub version: Option<VersionReq>,
    /// List of glob patterns that are allowed. This is much more loose than
    /// `allow`, but can be useful in scenarios where things like test suites or
    /// the like that contain many scripts/test executables that are present in
    /// the packged source, but are (hopefully) not actually read or executed
    /// during builds
    pub allow_globs: Option<Vec<Spanned<String>>>,
    /// One or more executables that are allowed. If not set all executables are
    /// allowed.
    pub allow: Option<Vec<Spanned<AllowedExecutable>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BuildConfig {
    /// List of crates that are allowed to have build scripts. If this is set,
    /// any crates with a build script that aren't listed here will be banned
    pub allow_build_scripts: Option<Spanned<Vec<CrateId>>>,
    /// Lint level for when executables are detected within crates with build
    /// scripts or are proc macros, or are a dependency of either of them
    #[serde(default = "crate::lint_deny")]
    pub executables: LintLevel,
    /// List of script extensions that are considered to be executable. These
    /// are always in addition to the builtin ones.
    pub script_extensions: Option<Vec<Spanned<String>>>,
    /// The list of allowed executables, by crate
    pub allow_executables: Option<Vec<Executables>>,
}

/// List of "common" patterns for scripting languages or easily executable
/// compiled languages that could be used for local execution with build scripts
/// or proc macros. Obviously this list is not and never can be complete since
/// in most cases extensions are only for humans and most tools will happily
/// execute scripts/code they can regardless of extension (eg. shell scripts),
/// and besides that, an _actually_ malicious crate could generate files on demand,
/// download from a remote location, or, really, anything
pub const BUILTIN_SCRIPT_GLOBS: &[&str] = &[
    // batch
    "*.bat", "*.cmd", "*.go",   // Go `go run <file.go>`
    "*.java", // Java `java <file.java>`
    // javascript
    ".js", "._js", ".es", ".es6", // perl
    ".pl", ".perl", ".pm", // perl 6
    ".6pl", ".6pm", ".p6", ".p6l", ".p6m", ".pl6", ".pm6", ".t", // powershell
    ".ps1", ".psd1", ".psm1", "*.py", // python
    "*.rb", // ruby
    // shell
    ".sh", ".bash", ".zsh",
];

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// How to handle multiple versions of the same crate
    #[serde(default = "crate::lint_warn")]
    pub multiple_versions: LintLevel,
    /// How the duplicate graphs are highlighted
    #[serde(default = "highlight")]
    pub highlight: GraphHighlight,
    /// The crates that will cause us to emit failures
    #[serde(default)]
    pub deny: Vec<CrateBan>,
    /// If specified, means only the listed crates are allowed
    #[serde(default)]
    pub allow: Vec<Spanned<CrateId>>,
    /// Allows specifying features that are or are not allowed on crates
    #[serde(default)]
    pub features: Vec<CrateFeatures>,
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
    pub skip: Vec<Spanned<CrateId>>,
    /// If specified, disregards the crate's transitive dependencies
    /// down to a certain depth
    #[serde(default)]
    pub skip_tree: Vec<Spanned<TreeSkip>>,
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
    /// Options for crates that run at build time
    pub build: Option<BuildConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            multiple_versions: LintLevel::Warn,
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
            build: None,
        }
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId, diags: &mut Vec<Diagnostic>) -> Self::ValidCfg {
        let from = |s: Spanned<CrateId>| {
            Skrate::new(
                KrateId {
                    name: s.value.name,
                    version: s.value.version,
                },
                s.span,
            )
        };

        let (deny_multiple_versions, deny): (Vec<_>, Vec<_>) =
            self.deny.into_iter().partition(|kb| {
                kb.deny_multiple_versions
                    .as_ref()
                    .map_or(false, |spanned| spanned.value)
            });

        let denied: Vec<_> = deny
            .into_iter()
            .map(|cb| KrateBan {
                id: Skrate::new(
                    KrateId {
                        name: cb.name.value,
                        version: cb.version,
                    },
                    cb.name.span,
                ),
                wrappers: cb.wrappers.map(|spanned| spanned.value),
            })
            .collect();

        let denied_multiple_versions: Vec<_> = deny_multiple_versions
            .into_iter()
            .map(|cb| {
                let wrappers = cb.wrappers.filter(|spanned| !spanned.value.is_empty());
                if let Some(wrappers) = wrappers {
                    // cb.multiple_versions is guaranteed to be Some(_) by the
                    // earlier call to `partition`
                    let multiple_versions = cb.deny_multiple_versions.unwrap();
                    diags.push(
                        Diagnostic::error()
                            .with_message(
                                "a crate ban was specified with both `wrappers` and `multiple-versions`",
                            )
                            .with_labels(vec![
                                Label::secondary(cfg_file, wrappers.span)
                                    .with_message("has one or more `wrappers`"),
                                Label::secondary(cfg_file, multiple_versions.span)
                                    .with_message("has `multiple-versions` set to true"),
                            ]),
                    );
                }

                Skrate::new(
                    KrateId {
                        name: cb.name.value,
                        version: cb.version,
                    },
                    cb.name.span,
                )
            })
            .collect();

        let allowed: Vec<_> = self.allow.into_iter().map(from).collect();
        let skipped: Vec<_> = self.skip.into_iter().map(from).collect();

        let dupe_crate_diag = |first: (&Skrate, &str), second: (&Skrate, &str)| -> Diagnostic {
            Diagnostic::error()
                .with_message(format!(
                    "a crate was specified in both `{}` and `{}`",
                    second.1, first.1
                ))
                .with_labels(vec![
                    Label::secondary(cfg_file, first.0.span.clone())
                        .with_message(format!("marked as `{}`", first.1)),
                    Label::secondary(cfg_file, second.0.span.clone())
                        .with_message(format!("marked as `{}`", second.1)),
                ])
        };

        let dupe_feature_diag = |krate: &Skrate,
                                 allow: &Spanned<String>,
                                 deny: &Spanned<String>|
         -> Diagnostic {
            Diagnostic::error()
                .with_message("a crate feature was specified as both allowed and denied")
                .with_labels(vec![
                    Label::primary(cfg_file, krate.span.clone()).with_message("crate ban entry"),
                    Label::secondary(cfg_file, allow.span.clone())
                        .with_message("marked as `allow`"),
                    Label::secondary(cfg_file, deny.span.clone()).with_message("marked as `deny`"),
                ])
        };

        for d in &denied {
            if let Some(dupe) = exact_match(&allowed, &d.id.value) {
                diags.push(dupe_crate_diag((&d.id, "deny"), (dupe, "allow")));
            }

            if let Some(dupe) = exact_match(&skipped, &d.id.value) {
                diags.push(dupe_crate_diag((&d.id, "deny"), (dupe, "skip")));
            }
        }

        for all in &allowed {
            if let Some(dupe) = exact_match(&skipped, &all.value) {
                diags.push(dupe_crate_diag((all, "allow"), (dupe, "skip")));
            }
        }

        // Ensure that a feature isn't both allowed and denied
        let features = self
            .features
            .into_iter()
            .map(|cf| {
                let id = Skrate::new(
                    KrateId {
                        name: cf.name.value,
                        version: cf.version,
                    },
                    cf.name.span,
                );

                for allowed in &cf.allow.value {
                    if let Some(denied) = cf.deny.iter().find(|df| df.value == allowed.value) {
                        diags.push(dupe_feature_diag(&id, allowed, denied));
                    }
                }

                KrateFeatures {
                    id,
                    features: Features {
                        allow: cf.allow,
                        deny: cf.deny,
                        exact: cf.exact,
                    },
                }
            })
            .collect();

        let build = if let Some(bc) = self.build {
            // Give higher precedence to the user's extensions
            let mut gs = globset::GlobSetBuilder::new();
            let mut patterns = Vec::new();
            if let Some(extensions) = bc.script_extensions {
                for ext in extensions {
                    // This top level config should only be extensions, not glob patterns
                    if !ext.value.is_ascii() {
                        diags.push(
                            Diagnostic::error()
                                .with_message("non-ascii file extension provided")
                                .with_labels(vec![Label::primary(cfg_file, ext.span.clone())
                                    .with_message("invalid extension")]),
                        );
                        continue;
                    }

                    if let Some(i) = ext.value.chars().position(|c| !c.is_ascii_alphanumeric()) {
                        diags.push(
                            Diagnostic::error()
                                .with_message("invalid file extension provided")
                                .with_labels(vec![
                                    Label::primary(cfg_file, ext.span.clone())
                                        .with_message("extension"),
                                    Label::secondary(
                                        cfg_file,
                                        ext.span.start + i..ext.span.start + i + 1,
                                    )
                                    .with_message("invalid character"),
                                ]),
                        );
                        continue;
                    }

                    match globset::Glob::new(&format!("*.{}", ext.value)) {
                        Ok(glob) => {
                            gs.add(glob);
                            patterns.push(GlobPattern::User(ext));
                        }
                        Err(err) => {
                            diags.push(
                                Diagnostic::error()
                                    .with_message(format!("invalid glob pattern: {err}"))
                                    .with_labels(vec![Label::primary(cfg_file, ext.span.clone())
                                        .with_message("extension")]),
                            );
                        }
                    }
                }
            }

            for bi in BUILTIN_SCRIPT_GLOBS {
                gs.add(globset::Glob::new(bi).expect("invalid builtin glob pattern"));
                patterns.push(GlobPattern::Builtin);
            }

            let script_extensions = match gs.build() {
                Ok(set) => ValidGlobSet { set, patterns },
                Err(err) => {
                    diags.push(Diagnostic::error().with_message(format!(
                        "failed to build script extensions glob set: {err}"
                    )));
                    ValidGlobSet {
                        set: globset::GlobSet::empty(),
                        patterns: Vec::new(),
                    }
                }
            };

            let allow_executables = if let Some(aexes) = bc.allow_executables {
                let mut aex = Vec::new();

                for ae in aexes {
                    let allow_globs = if let Some(allow_globs) = ae.allow_globs {
                        let mut gs = globset::GlobSetBuilder::new();
                        let mut patterns = Vec::new();

                        for ag in allow_globs {
                            match globset::Glob::new(&ag.value) {
                                Ok(glob) => {
                                    gs.add(glob);
                                    patterns.push(GlobPattern::User(ag));
                                }
                                Err(err) => {
                                    diags.push(
                                        Diagnostic::error()
                                            .with_message(format!("invalid glob pattern: {err}"))
                                            .with_labels(vec![Label::primary(
                                                cfg_file,
                                                ag.span.clone(),
                                            )]),
                                    );
                                }
                            }
                        }

                        match gs.build() {
                            Ok(set) => Some(ValidGlobSet { set, patterns }),
                            Err(err) => {
                                diags.push(Diagnostic::error().with_message(format!(
                                    "failed to build script extensions glob set: {err}"
                                )));
                                None
                            }
                        }
                    } else {
                        None
                    };

                    aex.push(ValidExecutables {
                        name: ae.name,
                        version: ae.version,
                        allow: ae.allow,
                        allow_globs,
                    });
                }

                Some(aex)
            } else {
                None
            };

            Some(ValidBuildConfig {
                allow_build_scripts: bc.allow_build_scripts,
                executables: bc.executables,
                script_extensions,
                allow_executables,
            })
        } else {
            None
        };

        ValidConfig {
            file_id: cfg_file,
            multiple_versions: self.multiple_versions,
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
            tree_skipped: self
                .skip_tree
                .into_iter()
                .map(crate::Spanned::from)
                .collect(),
            build,
        }
    }
}

#[inline]
pub(crate) fn exact_match<'v>(arr: &'v [Skrate], id: &'_ KrateId) -> Option<&'v Skrate> {
    arr.iter().find(|sid| *sid == id)
}

pub(crate) type Skrate = Spanned<KrateId>;

#[cfg_attr(test, derive(Debug))]
pub(crate) struct KrateBan {
    pub id: Skrate,
    pub wrappers: Option<Vec<Spanned<String>>>,
}

#[cfg_attr(test, derive(Debug))]
pub struct Features {
    pub allow: Spanned<Vec<Spanned<String>>>,
    pub deny: Vec<Spanned<String>>,
    pub exact: Spanned<bool>,
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct KrateFeatures {
    pub id: Skrate,
    pub features: Features,
}

pub enum GlobPattern {
    Builtin,
    User(Spanned<String>),
}

pub struct ValidGlobSet {
    set: globset::GlobSet,
    /// Patterns in the globset for lint output
    patterns: Vec<GlobPattern>,
}

impl ValidGlobSet {
    #[inline]
    pub fn matches(
        &self,
        path: &globset::Candidate<'_>,
        indices: &mut Vec<usize>,
    ) -> Vec<&GlobPattern> {
        self.set.matches_candidate_into(path, indices);
        indices.iter().map(|i| &self.patterns[*i]).collect()
    }
}

pub struct ValidExecutables {
    pub name: Spanned<String>,
    pub version: Option<VersionReq>,
    pub allow_globs: Option<ValidGlobSet>,
    pub allow: Option<Vec<Spanned<AllowedExecutable>>>,
}

pub struct ValidBuildConfig {
    pub allow_build_scripts: Option<Spanned<Vec<CrateId>>>,
    pub executables: LintLevel,
    pub script_extensions: ValidGlobSet,
    pub allow_executables: Option<Vec<ValidExecutables>>,
}

pub struct ValidConfig {
    pub file_id: FileId,
    pub multiple_versions: LintLevel,
    pub highlight: GraphHighlight,
    pub(crate) denied: Vec<KrateBan>,
    pub(crate) denied_multiple_versions: Vec<Skrate>,
    pub(crate) allowed: Vec<Skrate>,
    pub(crate) features: Vec<KrateFeatures>,
    pub external_default_features: Option<Spanned<LintLevel>>,
    pub workspace_default_features: Option<Spanned<LintLevel>>,
    pub(crate) skipped: Vec<Skrate>,
    pub(crate) tree_skipped: Vec<Spanned<TreeSkip>>,
    pub wildcards: LintLevel,
    pub allow_wildcard_paths: bool,
    pub build: Option<ValidBuildConfig>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, *};

    macro_rules! kid {
        ($name:expr) => {
            KrateId {
                name: String::from($name),
                version: None,
            }
        };

        ($name:expr, $vs:expr) => {
            KrateId {
                name: String::from($name),
                version: Some($vs.parse::<semver::VersionReq>().unwrap().into()),
            }
        };
    }

    impl PartialEq<KrateId> for KrateBan {
        fn eq(&self, o: &KrateId) -> bool {
            &self.id.value == o
        }
    }

    #[test]
    fn deserializes_ban_cfg() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bans {
            bans: Config,
        }

        let cd: ConfigData<Bans> = load("tests/cfg/bans.toml");

        let mut diags = Vec::new();
        let validated = cd.config.bans.validate(cd.id, &mut diags);
        assert!(diags.is_empty());

        assert_eq!(validated.file_id, cd.id);
        assert_eq!(validated.multiple_versions, LintLevel::Deny);

        assert_eq!(validated.wildcards, LintLevel::Deny);
        assert!(validated.allow_wildcard_paths);

        assert_eq!(validated.highlight, GraphHighlight::SimplestPath);
        assert_eq!(
            validated.external_default_features.unwrap().value,
            LintLevel::Deny
        );
        assert_eq!(
            validated.workspace_default_features.unwrap().value,
            LintLevel::Warn
        );

        assert_eq!(
            validated.allowed,
            vec![kid!("all-versionsa"), kid!("specific-versiona", "<0.1.1")]
        );

        assert_eq!(
            validated.denied,
            vec![kid!("all-versionsd"), kid!("specific-versiond", "=0.1.9")]
        );

        assert_eq!(validated.skipped, vec![kid!("rand", "=0.6.5")]);

        assert_eq!(
            validated.tree_skipped,
            vec![TreeSkip {
                id: CrateId {
                    name: "blah".to_owned(),
                    version: None,
                },
                depth: Some(20),
            }]
        );

        let kf = &validated.features[0];

        assert_eq!(kf.id, kid!("featured-krate", "1.0"));
        assert_eq!(kf.features.deny[0].value, "bad-feature");
        assert_eq!(kf.features.allow.value[0].value, "good-feature");
        assert!(kf.features.exact.value);
    }
}
