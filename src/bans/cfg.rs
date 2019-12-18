use super::KrateId;
use crate::LintLevel;
use semver::VersionReq;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CrateId {
    // The name of the crate
    pub name: String,
    /// The version constraints of the crate
    #[serde(default = "any")]
    pub version: VersionReq,
}

#[derive(Deserialize)]
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
    pub deny: Vec<toml::Spanned<CrateId>>,
    /// If specified, means only the listed crates are allowed
    #[serde(default)]
    pub allow: Vec<toml::Spanned<CrateId>>,
    /// If specified, disregards the crate completely
    #[serde(default)]
    pub skip: Vec<toml::Spanned<CrateId>>,
    /// If specified, disregards the crate's transitive dependencies
    /// down to a certain depth
    #[serde(default)]
    pub skip_tree: Vec<toml::Spanned<TreeSkip>>,
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
        }
    }
}

impl Config {
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
    ) -> Result<ValidConfig, Vec<crate::diag::Diagnostic>> {
        use crate::diag::{Diagnostic, Label};
        use rayon::prelude::*;

        let from = |s: toml::Spanned<CrateId>| {
            let span = s.start() as u32..s.end() as u32;
            let inner = s.into_inner();
            KrateId {
                name: inner.name,
                version: inner.version,
                span,
            }
        };

        let mut diagnostics = Vec::new();

        let mut denied: Vec<_> = self.deny.into_iter().map(from).collect();
        denied.par_sort();

        let mut allowed: Vec<_> = self.allow.into_iter().map(from).collect();
        allowed.par_sort();

        let mut skipped: Vec<_> = self.skip.into_iter().map(from).collect();
        skipped.par_sort();

        let mut add_diag = |first: (&KrateId, &str), second: (&KrateId, &str)| {
            let flabel = Label::new(
                cfg_file,
                first.0.span.clone(),
                format!("marked as `{}`", first.1),
            );
            let slabel = Label::new(
                cfg_file,
                second.0.span.clone(),
                format!("marked as `{}`", second.1),
            );

            // Put the one that occurs last as the primary label to make it clear
            // that the first one was "ok" until we noticed this other one
            let diag = if flabel.span.start() > slabel.span.start() {
                Diagnostic::new_error(
                    format!(
                        "a license id was specified in both `{}` and `{}`",
                        first.1, second.1
                    ),
                    flabel,
                )
                .with_secondary_labels(std::iter::once(slabel))
            } else {
                Diagnostic::new_error(
                    format!(
                        "a license id was specified in both `{}` and `{}`",
                        second.1, first.1
                    ),
                    slabel,
                )
                .with_secondary_labels(std::iter::once(flabel))
            };

            diagnostics.push(diag);
        };

        for d in &denied {
            if let Ok(ai) = allowed.binary_search(&d) {
                add_diag((d, "deny"), (&allowed[ai], "allow"));
            }
            if let Ok(si) = skipped.binary_search(&d) {
                add_diag((d, "deny"), (&skipped[si], "skip"));
            }
        }

        for a in &allowed {
            if let Ok(si) = skipped.binary_search(&a) {
                add_diag((a, "allow"), (&skipped[si], "skip"));
            }
        }

        if !diagnostics.is_empty() {
            Err(diagnostics)
        } else {
            Ok(ValidConfig {
                file_id: cfg_file,
                multiple_versions: self.multiple_versions,
                highlight: self.highlight,
                denied,
                allowed,
                skipped,
                tree_skipped: self.skip_tree,
            })
        }
    }
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,
    pub multiple_versions: LintLevel,
    pub highlight: GraphHighlight,
    pub(crate) denied: Vec<KrateId>,
    pub(crate) allowed: Vec<KrateId>,
    pub(crate) skipped: Vec<KrateId>,
    pub(crate) tree_skipped: Vec<toml::Spanned<TreeSkip>>,
}
