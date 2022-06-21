use super::KrateId;
use crate::{
    diag::{Diagnostic, FileId, Label},
    LintLevel, Spanned,
};
use semver::VersionReq;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(deny_unknown_fields)]
pub struct CrateId {
    // The name of the crate
    pub name: String,
    /// The version constraints of the crate
    pub version: Option<VersionReq>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(deny_unknown_fields)]
pub struct CrateBan {
    pub name: Spanned<String>,
    pub version: Option<VersionReq>,
    /// One or more crates that will allow this crate to be used if it is a
    /// direct dependency
    #[serde(default)]
    pub wrappers: Vec<Spanned<String>>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
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
    /// List of crates that are allowed to have a build step.
    pub allow_build_scripts: Option<Spanned<Vec<CrateId>>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            multiple_versions: LintLevel::Warn,
            highlight: GraphHighlight::All,
            deny: Vec::new(),
            allow: Vec::new(),
            skip: Vec::new(),
            skip_tree: Vec::new(),
            wildcards: LintLevel::Allow,
            allow_build_scripts: None,
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

        let denied: Vec<_> = self
            .deny
            .into_iter()
            .map(|cb| KrateBan {
                id: Skrate::new(
                    KrateId {
                        name: cb.name.value,
                        version: cb.version,
                    },
                    cb.name.span,
                ),
                wrappers: cb.wrappers,
            })
            .collect();

        let allowed: Vec<_> = self.allow.into_iter().map(from).collect();
        let skipped: Vec<_> = self.skip.into_iter().map(from).collect();

        let mut add_diag = |first: (&Skrate, &str), second: (&Skrate, &str)| {
            diags.push(
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
                    ]),
            );
        };

        for d in &denied {
            if let Some(dupe) = exact_match(&allowed, &d.id.value) {
                add_diag((&d.id, "deny"), (dupe, "allow"));
            }
            if let Some(dupe) = exact_match(&skipped, &d.id.value) {
                add_diag((&d.id, "deny"), (dupe, "skip"));
            }
        }

        for all in &allowed {
            if let Some(dupe) = exact_match(&skipped, &all.value) {
                add_diag((all, "allow"), (dupe, "skip"));
            }
        }

        ValidConfig {
            file_id: cfg_file,
            multiple_versions: self.multiple_versions,
            highlight: self.highlight,
            denied,
            allowed,
            skipped,
            wildcards: self.wildcards,
            tree_skipped: self
                .skip_tree
                .into_iter()
                .map(crate::Spanned::from)
                .collect(),
            allow_build_scripts: self.allow_build_scripts.map(|v| {
                Spanned::new(
                    v.value
                        .into_iter()
                        .map(|id| KrateId {
                            name: id.name,
                            version: id.version,
                        })
                        .collect(),
                    v.span,
                )
            }),
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
    pub wrappers: Vec<Spanned<String>>,
}

pub struct ValidConfig {
    pub file_id: FileId,
    pub multiple_versions: LintLevel,
    pub highlight: GraphHighlight,
    pub(crate) denied: Vec<KrateBan>,
    pub(crate) allowed: Vec<Skrate>,
    pub(crate) skipped: Vec<Skrate>,
    pub(crate) tree_skipped: Vec<Spanned<TreeSkip>>,
    pub wildcards: LintLevel,
    pub allow_build_scripts: Option<Spanned<Vec<KrateId>>>,
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
    fn works() {
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
        assert_eq!(validated.highlight, GraphHighlight::SimplestPath);

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
    }
}
