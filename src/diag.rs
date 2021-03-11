mod obj_grapher;
mod sink;
mod text_grapher;

pub use obj_grapher::{cs_diag_to_json, diag_to_json, ObjectGrapher};
pub use sink::ErrorSink;
pub use text_grapher::TextGrapher;

use std::{collections::HashMap, ops::Range};

use crate::{Kid, Krates};
pub use codespan_reporting::diagnostic::Severity;

pub use codespan::FileId;

pub type Diagnostic = codespan_reporting::diagnostic::Diagnostic<FileId>;
pub type Label = codespan_reporting::diagnostic::Label<FileId>;
pub type Files = codespan::Files<String>;
// Map of crate id => (path to cargo.toml, synthetic cargo.toml content, map(cratename => crate span))
pub type RawCargoSpans = HashMap<Kid, (krates::Utf8PathBuf, String, HashMap<String, Range<usize>>)>;
// Same as RawCargoSpans but path to cargo.toml and cargo.toml content replaced with FileId
pub type CargoSpans = HashMap<Kid, (FileId, HashMap<String, Range<usize>>)>;

impl Into<Severity> for crate::LintLevel {
    fn into(self) -> Severity {
        match self {
            Self::Warn => Severity::Warning,
            Self::Deny => Severity::Error,
            Self::Allow => Severity::Note,
        }
    }
}

pub struct Diag {
    pub diag: Diagnostic,
    pub kids: smallvec::SmallVec<[Kid; 2]>,
    pub extra: Option<(&'static str, serde_json::Value)>,
}

impl Diag {
    pub(crate) fn new(diag: Diagnostic) -> Self {
        Self {
            diag,
            kids: smallvec::SmallVec::new(),
            extra: None,
        }
    }
}

impl From<Diagnostic> for Diag {
    fn from(d: Diagnostic) -> Self {
        Diag::new(d)
    }
}

pub enum Check {
    Advisories,
    Bans,
    Licenses,
    Sources,
}

pub struct Pack {
    pub check: Check,
    diags: Vec<Diag>,
    kid: Option<Kid>,
}

impl Pack {
    pub(crate) fn new(check: Check) -> Self {
        Self {
            check,
            diags: Vec::new(),
            kid: None,
        }
    }

    pub(crate) fn with_kid(check: Check, kid: Kid) -> Self {
        Self {
            check,
            diags: Vec::new(),
            kid: Some(kid),
        }
    }

    pub(crate) fn push(&mut self, diag: impl Into<Diag>) -> &mut Diag {
        let mut diag = diag.into();
        if diag.kids.is_empty() {
            if let Some(kid) = self.kid.take() {
                diag.kids.push(kid);
            }
        }

        self.diags.push(diag);
        self.diags.last_mut().unwrap()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.diags.is_empty()
    }
}

impl IntoIterator for Pack {
    type Item = Diag;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.diags.into_iter()
    }
}

impl<T> From<(Check, T)> for Pack
where
    T: Into<Diag>,
{
    fn from((check, t): (Check, T)) -> Self {
        Self {
            check,
            diags: vec![t.into()],
            kid: None,
        }
    }
}

pub type Span = std::ops::Range<usize>;

pub struct KrateSpan {
    span: Span,
}

pub struct KrateSpans {
    spans: Vec<KrateSpan>,
    pub file_id: FileId,
}

impl std::ops::Index<usize> for KrateSpans {
    type Output = Span;

    #[inline]
    fn index(&self, i: usize) -> &Self::Output {
        &self.spans[i].span
    }
}

impl KrateSpans {
    pub fn with_spans(spans: Vec<KrateSpan>, id: FileId) -> Self {
        Self { spans, file_id: id }
    }

    pub fn synthesize(krates: &Krates) -> (Vec<KrateSpan>, String, RawCargoSpans) {
        use std::fmt::Write;

        let mut sl = String::with_capacity(4 * 1024);
        let mut spans = Vec::with_capacity(krates.len());
        let mut cargo_spans = RawCargoSpans::new();

        for krate in krates.krates().map(|kn| &kn.krate) {
            let span_start = sl.len();
            match &krate.source {
                Some(src) => writeln!(sl, "{} {} {}", krate.name, krate.version, src)
                    .expect("unable to synthesize lockfile"),
                None => writeln!(
                    sl,
                    "{} {} {}",
                    krate.name,
                    krate.version,
                    krate.manifest_path.parent().unwrap()
                )
                .expect("unable to synthesize lockfile"),
            };

            let span_end = sl.len() - 1;

            spans.push(KrateSpan {
                span: span_start..span_end,
            });

            let mut sl2 = String::with_capacity(4 * 1024);
            let mut deps_map = HashMap::new();

            for dep in &krate.deps {
                let span_start = sl2.len();
                writeln!(sl2, "{} = \"{}\"", dep.name, dep.req)
                    .expect("unable to synthesize Cargo.toml");
                let span_end = sl2.len() - 1;
                deps_map.insert(dep.name.clone(), span_start..span_end);
            }

            cargo_spans.insert(
                krate.id.clone(),
                (krate.manifest_path.clone(), sl2, deps_map),
            );
        }

        (spans, sl, cargo_spans)
    }

    #[inline]
    pub fn label_for_index(&self, krate_index: usize, msg: impl Into<String>) -> Label {
        Label::secondary(self.file_id, self.spans[krate_index].span.clone()).with_message(msg)
    }

    #[inline]
    pub fn get_coord(&self, krate_index: usize) -> KrateCoord {
        KrateCoord {
            file: self.file_id,
            span: self.spans[krate_index].span.clone(),
        }
    }
}

pub type KrateCoord = Coord;
pub type CfgCoord = Coord;

#[derive(Clone)]
pub struct Coord {
    pub file: FileId,
    pub span: Range<usize>,
}

impl Coord {
    pub(crate) fn into_label(self) -> Label {
        self.into()
    }
}

impl Into<Label> for Coord {
    fn into(self) -> Label {
        Label::primary(self.file, self.span)
    }
}

struct NodePrint<'a> {
    krate: &'a crate::Krate,
    id: krates::NodeId,
    kind: &'static str,
}
