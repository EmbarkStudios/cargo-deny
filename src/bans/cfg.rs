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
#[serde(deny_unknown_fields)]
pub struct CrateBan {
    pub name: Spanned<String>,
    #[serde(default = "any")]
    pub version: VersionReq,
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

#[inline]
fn any() -> VersionReq {
    VersionReq::STAR
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
        let from = |s: Spanned<CrateId>| {
            Skrate::new(
                KrateId {
                    name: s.value.name,
                    version: s.value.version,
                },
                s.span,
            )
        };

        let mut denied: BTreeMap<String, Vec<KrateBan>> = BTreeMap::new();

        for kb in self.deny.into_iter().map(|cb| KrateBan {
            id: Skrate::new(
                KrateId {
                    name: cb.name.value,
                    version: cb.version,
                },
                cb.name.span,
            ),
            wrappers: cb.wrappers,
        }) {
            match denied.get_mut(&kb.id.value.name) {
                Some(list) => list.push(kb),
                None => {
                    denied.insert(kb.id.value.name.clone(), vec![kb]);
                }
            }
        }

        let mut allowed: BTreeMap<String, Vec<Skrate>> = BTreeMap::new();
        for a in self.allow.into_iter().map(from) {
            match allowed.get_mut(&a.value.name) {
                Some(list) => list.push(a),
                None => {
                    allowed.insert(a.value.name.clone(), vec![a]);
                }
            }
        }

        let mut skipped: BTreeMap<String, Vec<Skrate>> = BTreeMap::new();
        for s in self.skip.into_iter().map(from) {
            match skipped.get_mut(&s.value.name) {
                Some(list) => list.push(s),
                None => {
                    skipped.insert(s.value.name.clone(), vec![s]);
                }
            }
        }

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

        for den in denied.values() {
            for d in den {
                if let Some(dupe) = exact_match(&allowed, &d.id.value) {
                    add_diag((&d.id, "deny"), (dupe, "allow"));
                }
                if let Some(dupe) = exact_match(&skipped, &d.id.value) {
                    add_diag((&d.id, "deny"), (dupe, "skip"));
                }
            }
        }

        for all in allowed.values() {
            for a in all {
                if let Some(dupe) = exact_match(&skipped, &a.value) {
                    add_diag((a, "allow"), (dupe, "skip"));
                }
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

#[inline]
pub(crate) fn exact_match<'hm>(
    hm: &'hm BTreeMap<String, Vec<Skrate>>,
    id: &'_ KrateId,
) -> Option<&'hm Skrate> {
    hm.get(&id.name)
        .and_then(|v| v.iter().find(|sid| &sid.value == id))
}

pub(crate) type Skrate = Spanned<KrateId>;

#[cfg_attr(test, derive(Debug))]
pub(crate) struct KrateBan {
    pub id: Skrate,
    pub wrappers: Vec<Spanned<String>>,
}

use std::collections::BTreeMap;

pub struct ValidConfig {
    pub file_id: FileId,
    pub multiple_versions: LintLevel,
    pub highlight: GraphHighlight,
    pub(crate) denied: BTreeMap<String, Vec<KrateBan>>,
    pub(crate) allowed: BTreeMap<String, Vec<Skrate>>,
    pub(crate) skipped: BTreeMap<String, Vec<Skrate>>,
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
                version: semver::VersionReq::STAR.into(),
            }
        };

        ($name:expr, $vs:expr) => {
            KrateId {
                name: String::from($name),
                version: $vs.parse::<semver::VersionReq>().unwrap().into(),
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

        for kid in [kid!("all-versionsa"), kid!("specific-versiona", "<0.1.1")] {
            assert!(validated
                .allowed
                .get(&kid.name)
                .unwrap()
                .iter()
                .any(|a| a.value == kid));
        }

        for kid in [kid!("all-versionsd"), kid!("specific-versiond", "=0.1.9")] {
            assert!(validated
                .denied
                .get(&kid.name)
                .unwrap()
                .iter()
                .any(|d| d.id.value == kid));
        }

        for kid in [kid!("rand", "=0.6.5")] {
            assert!(validated
                .skipped
                .get(&kid.name)
                .unwrap()
                .iter()
                .any(|s| s.value == kid));
        }

        assert_eq!(
            validated.tree_skipped,
            vec![TreeSkip {
                id: CrateId {
                    name: "blah".to_owned(),
                    version: semver::VersionReq::STAR,
                },
                depth: Some(20),
            }]
        );
    }
}
