mod package_spec;

use crate::diag;
pub use package_spec::{PackageSpec, PackageSpecOrExtended};
pub use toml_span::span::{Span, Spanned};

pub struct ValidationContext<'ctx> {
    pub cfg_id: diag::FileId,
    pub files: &'ctx mut diag::Files,
    pub diagnostics: &'ctx mut Vec<diag::Diagnostic>,
}

impl ValidationContext<'_> {
    #[inline]
    pub fn push(&mut self, diag: diag::Diagnostic) {
        self.diagnostics.push(diag);
    }

    /// Sorts a vec and prints a warning about duplicate items before removing them
    pub fn dedup<T>(&mut self, v: &mut Vec<Spanned<T>>)
    where
        T: Ord,
    {
        if v.len() <= 1 {
            return;
        }

        v.sort();

        for window in v.windows(2) {
            if window[0] != window[1] {
                continue;
            }

            self.push(
                diag::Diagnostic::warning()
                    .with_message("duplicate items detected")
                    .with_labels(vec![
                        diag::Label::secondary(self.cfg_id, window[0].span),
                        diag::Label::secondary(self.cfg_id, window[1].span),
                    ]),
            );
        }

        v.dedup();
    }
}

pub trait UnvalidatedConfig {
    type ValidCfg;

    fn validate(self, ctx: ValidationContext<'_>) -> Self::ValidCfg;
}

#[derive(Copy, Clone, PartialEq, strum::VariantNames, strum::VariantArray)]
#[cfg_attr(test, derive(serde::Serialize))]
#[strum(serialize_all = "kebab-case")]
pub enum Scope {
    /// Matches any crate
    All,
    /// Matches crates in the workspace
    Workspace,
    /// Matches external crates
    Transitive,
    /// Matches no crates
    None,
}

crate::enum_deser!(Scope);

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, serde::Serialize))]
pub struct Reason(pub Spanned<String>);

impl From<Spanned<String>> for Reason {
    fn from(s: Spanned<String>) -> Self {
        Self(s)
    }
}

impl<'de> toml_span::Deserialize<'de> for Reason {
    fn deserialize(
        value: &mut toml_span::value::Value<'de>,
    ) -> Result<Self, toml_span::DeserError> {
        let mut th = toml_span::de_helpers::TableHelper::new(value)?;
        let r = th.required("reason")?;
        th.finalize(Some(value))?;
        Ok(Self(r))
    }
}

/// Deserialize a field from the table if it exists, but append the key's span
/// so it can be marked as deprecated
pub fn deprecated<'de, T>(
    th: &mut toml_span::de_helpers::TableHelper<'de>,
    field: &'static str,
    spans: &mut Vec<Span>,
) -> Option<T>
where
    T: toml_span::Deserialize<'de>,
{
    let (k, mut v) = th.take(field)?;
    spans.push(k.span);

    T::deserialize(&mut v).ok()
}
