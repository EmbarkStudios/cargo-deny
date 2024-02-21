//! Contains general diagnostics that are shared between various checks

use crate::{
    diag::{Diagnostic, FileId, Label, Severity},
    Span,
};
use std::fmt;

#[derive(
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Code {
    Deprecated,
}

impl From<Code> for String {
    fn from(c: Code) -> Self {
        c.to_string()
    }
}

pub enum DeprecationReason {
    WillBeRemoved(Option<&'static str>),
    Moved(&'static str),
    Renamed(&'static str),
    MovedAndRenamed {
        table: &'static str,
        key: &'static str,
    },
    Removed(&'static str),
}

impl fmt::Display for DeprecationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WillBeRemoved(url) => {
                if let Some(url) = url {
                    write!(
                        f,
                        "this key will be removed in a future update, see {url} for details"
                    )
                } else {
                    f.write_str("this key will be removed in a future update")
                }
            }
            Self::Moved(tab) => write!(f, "this key has been moved to [{tab}]"),
            Self::Renamed(nname) => write!(f, "this key has been renamed to '{nname}'"),
            Self::MovedAndRenamed { table, key } => {
                write!(f, "this key been moved to [{table}] and renamed to '{key}'")
            }
            Self::Removed(url) => {
                write!(
                    f,
                    "this key has been removed, see {url} for migration information"
                )
            }
        }
    }
}

pub struct Deprecated {
    pub key: Span,
    pub reason: DeprecationReason,
    pub file_id: FileId,
}

impl From<Deprecated> for Diagnostic {
    fn from(dep: Deprecated) -> Self {
        Diagnostic::new(Severity::Warning)
            .with_message(dep.reason.to_string())
            .with_labels(vec![Label::primary(dep.file_id, dep.key)])
            .with_code(Code::Deprecated)
    }
}
