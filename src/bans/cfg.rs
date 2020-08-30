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
    #[serde(default = "any")]
    pub version: VersionReq,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CrateBan {
    pub name: Spanned<String>,
    #[serde(default = "any")]
    pub version: VersionReq,
    /// One or more crates that will allow this crate to be used if it is a
    /// direct dependency
    #[serde(default)]
    pub wrappers: Vec<Spanned<String>>,
    /// All features that are allowed to be used.
    #[serde(default)]
    pub allow_features: Vec<Spanned<String>>,
    /// All features that are denied.
    #[serde(default)]
    pub deny_features: Spanned<Vec<Spanned<String>>>,
    /// The actual feature set has to match the `allow_features` sets.
    #[serde(default)]
    pub exact_features: Spanned<bool>,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TreeSkip {
    #[serde(flatten)]
    pub id: CrateId,
    pub depth: Option<usize>,
}

fn any() -> VersionReq {
    VersionReq::any()
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
        }
    }
}

impl crate::cfg::UnvalidatedConfig for Config {
    type ValidCfg = ValidConfig;

    fn validate(self, cfg_file: FileId, diags: &mut Vec<Diagnostic>) -> Self::ValidCfg {
        use rayon::prelude::*;

        let from = |s: Spanned<CrateId>| {
            Skrate::new(
                KrateId {
                    name: s.value.name,
                    version: s.value.version,
                },
                s.span,
            )
        };

        let mut denied: Vec<_> = self
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
                allow_features: cb.allow_features,
                deny_features: cb.deny_features,
                exact_features: cb.exact_features,
            })
            .collect();
        denied.par_sort();

        let mut allowed: Vec<_> = self.allow.into_iter().map(from).collect();
        allowed.par_sort();

        let mut skipped: Vec<_> = self.skip.into_iter().map(from).collect();
        skipped.par_sort();

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

        for a in &allowed {
            if let Ok(si) = skipped.binary_search(&a) {
                add_diag((a, "allow"), (&skipped[si], "skip"));
            }
        }

        for d in &denied {
            if let Ok(ai) = allowed.binary_search(&d.id) {
                add_diag((&d.id, "deny"), (&allowed[ai], "allow"));
            }
            if let Ok(si) = skipped.binary_search(&d.id) {
                add_diag((&d.id, "deny"), (&skipped[si], "skip"));
            }
        }

        for d in &denied {
            for allowed_f in &d.allow_features {
                if let Ok(fi) = &d.deny_features.value.binary_search(allowed_f) {
                    let deny_f = &d.deny_features.value[*fi];

                    diagnostics.push(
                        Diagnostic::error()
                            .with_message(
                                "a feature was specified in both `allowed-features` and `deny-features`",
                            )
                            .with_labels(vec![
                                Label::secondary(cfg_file, allowed_f.span.clone())
                                    .with_message("marked as `allow`"),
                                Label::secondary(cfg_file, deny_f.span.clone())
                                    .with_message("marked as `deny`"),
                            ]),
                    );
                }
            }

            if d.exact_features.value && !d.deny_features.value.is_empty() {
                // TODO: Should this really be like this?
                diagnostics.push(
                    Diagnostic::error()
                        .with_message("can not deny features if `exact-features` is enabled")
                        .with_labels(vec![
                            Label::secondary(cfg_file, d.exact_features.span.clone())
                                .with_message("exact-features enabled here"),
                            Label::secondary(cfg_file, d.deny_features.span.clone())
                                .with_message("features are denied here"),
                        ]),
                );
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
        }
    }
}

pub(crate) type Skrate = Spanned<KrateId>;

#[derive(Eq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct KrateBan {
    pub id: Skrate,
    pub wrappers: Vec<Spanned<String>>,
    pub allow_features: Vec<Spanned<String>>,
    pub deny_features: Spanned<Vec<Spanned<String>>>,
    pub exact_features: Spanned<bool>,
}

use std::cmp::{Ord, Ordering};

impl Ord for KrateBan {
    fn cmp(&self, o: &Self) -> Ordering {
        self.id.cmp(&o.id)
    }
}

impl PartialOrd for KrateBan {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl PartialEq for KrateBan {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cfg::{test::*, *};

    macro_rules! kid {
        ($name:expr) => {
            KrateId {
                name: String::from($name),
                version: semver::VersionReq::any(),
            }
        };

        ($name:expr, $vs:expr) => {
            KrateId {
                name: String::from($name),
                version: $vs.parse().unwrap(),
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
                    version: semver::VersionReq::any(),
                },
                depth: Some(20),
            }]
        );
    }
}
