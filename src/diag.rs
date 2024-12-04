pub mod general;
mod grapher;
pub mod krate_spans;
mod sink;

pub use grapher::{cs_diag_to_json, diag_to_json, write_graph_as_text, InclusionGrapher};
pub use sink::{DiagnosticOverrides, ErrorSink};

use std::{collections::BTreeMap, ops::Range};

use crate::{Kid, PathBuf, Span};
pub use codespan_reporting::diagnostic::Severity;
pub use krate_spans::{KrateSpans, Manifest, ManifestDep, UnusedWorkspaceDep};

pub type FileId = usize;

pub type FilesErr = codespan_reporting::files::Error;
pub type Diagnostic = codespan_reporting::diagnostic::Diagnostic<FileId>;
pub type Label = codespan_reporting::diagnostic::Label<FileId>;

/// Channel type used to send diagnostics from checks
pub type PackChannel = crossbeam::channel::Sender<Pack>;

struct File {
    name: PathBuf,
    source: String,
    line_starts: Vec<u32>,
}

use codespan_reporting::files::Files as _;

/// Implementation of [`codespan_reporting::files::Files`], which can also query
/// [`FileId`] by path
pub struct Files {
    files: Vec<File>,
    /// Since we hand out ids we keep a mapping of path -> id for faster searching
    map: BTreeMap<PathBuf, FileId>,
}

impl Files {
    #[inline]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            map: Default::default(),
        }
    }

    #[inline]
    pub fn source_by_path(&self, path: &crate::Path) -> Option<&str> {
        self.id_for_path(path)
            .map(|id| self.files[id].source.as_str())
    }

    #[inline]
    pub fn id_for_path(&self, path: &crate::Path) -> Option<FileId> {
        self.map.get(path).copied()
    }

    #[inline]
    pub fn add(&mut self, path: impl Into<crate::PathBuf>, source: impl Into<String>) -> FileId {
        let name = path.into();

        if let Some(id) = self.id_for_path(&name) {
            panic!("path {name}({id}) is already present");
        }

        let id = self.files.len();
        self.map.insert(name.clone(), id);
        self.files.push(File {
            name,
            source: String::new(),
            line_starts: Vec::new(),
        });

        self.update(id, source);
        id
    }

    #[inline]
    pub fn update(&mut self, id: FileId, source: impl Into<String>) {
        let file = &mut self.files[id];

        let source = source.into();

        let mut line_starts = Vec::new();
        line_starts.push(0);
        line_starts.extend(memchr::memchr_iter(b'\n', source.as_bytes()).map(|i| (i + 1) as u32));

        file.source = source;
        file.line_starts = line_starts;
    }

    pub fn location(&self, id: FileId, byte_index: u32) -> Result<codespan::Location, FilesErr> {
        let given = byte_index as usize;
        let line_index = self.line_index(id, given)?;

        let file = &self.files[id];
        let line_start = file.line_starts[line_index] as usize;

        let line_src = file.source.get(line_start..given).ok_or_else(|| {
            let max = file.source.len() - 1;
            if given > max {
                FilesErr::IndexTooLarge { given, max }
            } else {
                FilesErr::InvalidCharBoundary { given }
            }
        })?;

        Ok(codespan::Location {
            line: (line_index as u32).into(),
            column: (line_src.chars().count() as u32).into(),
        })
    }

    #[inline]
    pub fn source(&self, id: FileId) -> &str {
        &self.files[id].source
    }
}

impl<'f> codespan_reporting::files::Files<'f> for Files {
    type FileId = FileId;
    type Name = &'f crate::Path;
    type Source = &'f str;

    fn source(&'f self, id: Self::FileId) -> Result<Self::Source, FilesErr> {
        self.files
            .get(id)
            .map(|f| f.source.as_str())
            .ok_or(FilesErr::FileMissing)
    }

    fn name(&'f self, id: Self::FileId) -> Result<Self::Name, FilesErr> {
        self.files
            .get(id)
            .map(|f| f.name.as_path())
            .ok_or(FilesErr::FileMissing)
    }

    fn line_index(&'f self, id: Self::FileId, byte_index: usize) -> Result<usize, FilesErr> {
        let file = self.files.get(id).ok_or(FilesErr::FileMissing)?;

        let byte_index: u32 = byte_index
            .try_into()
            .map_err(|_e| FilesErr::IndexTooLarge {
                given: byte_index,
                max: file.line_starts.last().map_or(u32::MAX as _, |ls| *ls as _),
            })?;

        Ok(match file.line_starts.binary_search(&byte_index) {
            Ok(line) => line,
            Err(next_line) => next_line - 1,
        })
    }

    fn line_range(&'f self, id: Self::FileId, line_index: usize) -> Result<Range<usize>, FilesErr> {
        let file = self.files.get(id).ok_or(FilesErr::FileMissing)?;

        let start = *file
            .line_starts
            .get(line_index)
            .ok_or(FilesErr::LineTooLarge {
                given: line_index,
                max: file.line_starts.len(),
            })?;
        let end = if line_index + 1 < file.line_starts.len() {
            file.line_starts[line_index + 1]
        } else {
            file.source.len() as _
        };

        Ok(start as _..end as _)
    }
}

impl From<crate::LintLevel> for Severity {
    fn from(ll: crate::LintLevel) -> Self {
        match ll {
            crate::LintLevel::Warn => Severity::Warning,
            crate::LintLevel::Deny => Severity::Error,
            crate::LintLevel::Allow => Severity::Note,
        }
    }
}

pub struct GraphNode {
    pub kid: Kid,
    pub feature: Option<String>,
}

pub struct Diag {
    pub diag: Diagnostic,
    pub graph_nodes: smallvec::SmallVec<[GraphNode; 2]>,
    pub extra: Option<(&'static str, serde_json::Value)>,
    pub with_features: bool,
}

impl Diag {
    pub(crate) fn new(diag: Diagnostic) -> Self {
        Self {
            diag,
            graph_nodes: smallvec::SmallVec::new(),
            extra: None,
            with_features: false,
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
    pub(crate) diags: Vec<Diag>,
    kid: Option<Kid>,
}

impl Pack {
    #[inline]
    pub(crate) fn new(check: Check) -> Self {
        Self {
            check,
            diags: Vec::new(),
            kid: None,
        }
    }

    #[inline]
    pub(crate) fn with_kid(check: Check, kid: Kid) -> Self {
        Self {
            check,
            diags: Vec::new(),
            kid: Some(kid),
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, diag: impl Into<Diag>) -> &mut Diag {
        let mut diag = diag.into();
        if diag.graph_nodes.is_empty() {
            if let Some(kid) = self.kid.clone() {
                diag.graph_nodes.push(GraphNode { kid, feature: None });
            }
        }

        self.diags.push(diag);
        self.diags.last_mut().unwrap()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.diags.len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.diags.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Diag> {
        self.diags.iter()
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

pub type KrateCoord = Coord;
pub type CfgCoord = Coord;

#[derive(Clone)]
pub struct Coord {
    pub file: FileId,
    pub span: Span,
}

impl Coord {
    pub(crate) fn into_label(self) -> Label {
        self.into()
    }
}

impl From<Coord> for Label {
    fn from(c: Coord) -> Self {
        Label::primary(c.file, c.span)
    }
}

struct NodePrint {
    node: krates::NodeId,
    edge: Option<krates::EdgeId>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    Advisory(crate::advisories::Code),
    Bans(crate::bans::Code),
    License(crate::licenses::Code),
    Source(crate::sources::Code),
    General(general::Code),
}

impl DiagnosticCode {
    pub fn iter() -> impl Iterator<Item = Self> {
        use strum::IntoEnumIterator;
        crate::advisories::Code::iter()
            .map(Self::Advisory)
            .chain(crate::bans::Code::iter().map(Self::Bans))
            .chain(crate::licenses::Code::iter().map(Self::License))
            .chain(crate::sources::Code::iter().map(Self::Source))
            .chain(general::Code::iter().map(Self::General))
    }

    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory(code) => code.into(),
            Self::Bans(code) => code.into(),
            Self::License(code) => code.into(),
            Self::Source(code) => code.into(),
            Self::General(code) => code.into(),
        }
    }
}

use std::fmt;

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DiagnosticCode {
    type Err = strum::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<crate::advisories::Code>()
            .map(Self::Advisory)
            .or_else(|_err| s.parse::<crate::bans::Code>().map(Self::Bans))
            .or_else(|_err| s.parse::<crate::licenses::Code>().map(Self::License))
            .or_else(|_err| s.parse::<crate::sources::Code>().map(Self::Source))
            .or_else(|_err| s.parse::<general::Code>().map(Self::General))
    }
}

/// A codespan config that modifies the character set used
///
/// This is a shared function so it is used by both check and tests
pub fn codespan_config() -> codespan_reporting::term::Config {
    let mut config = codespan_reporting::term::Config::default();
    // TODO: rustc spans have 2 note bullets, the default one that is used for everything..
    // _except_ the last note, which uses `╰`, but codespan_reporting only has a single
    // note bullet, so would be good to add a PR to add that in since it does look nicer
    config.chars.note_bullet = '├';
    config.chars.multi_primary_caret_start = '┘';
    config.chars.multi_secondary_caret_start = '┘';
    config.chars.single_primary_caret = '━';
    config.chars.single_secondary_caret = '─';
    config
}

#[cfg(test)]
mod test {
    #[test]
    fn codes_unique() {
        let mut unique = std::collections::BTreeSet::<&'static str>::new();

        for code in super::DiagnosticCode::iter() {
            if !unique.insert(code.as_str()) {
                panic!("existing code '{code}'");
            }
        }

        insta::assert_debug_snapshot!(unique);
    }

    /// While _most_ of the possible output if codespan is covered by various tests
    /// there are a couple of cases that aren't covered, so we just generate a
    /// set of outputs to easily show output differences when changing settings
    #[test]
    fn codespan_output() {
        use codespan_reporting::diagnostic::{Diagnostic, Label};
        let mut files = super::Files::new();

        let mut term = codespan_reporting::term::termcolor::NoColor::new(Vec::new());
        let config = super::codespan_config();

        const FILE: &str = r#"
[table.key]
value1 = "value"
value2 = 29

[[table.notes]]
name = "short"
text = "this is a single line of note text"

[[table.notes]]
name = "long"
text = """
this is a longer text note that
has multiple
lines
"""
"#;

        let file_id = files.add("fake-path.toml", FILE);

        let toml = toml_span::parse(FILE).unwrap();

        let mut diags = vec![
            // The simplest diagnostic
            Diagnostic::warning().with_message("simple"),
        ];

        // Still simple
        diags.push(
            Diagnostic::error()
                .with_message("with code")
                .with_code("code-id"),
        );

        // Single label
        diags.push(
            Diagnostic::warning()
                .with_message("label")
                .with_labels(vec![Label::primary(
                    file_id,
                    toml.pointer("/table/key/value1").unwrap().span,
                )]),
        );

        // Multiple labels in order
        diags.push(
            Diagnostic::warning()
                .with_message("labels, ordered")
                .with_labels(vec![
                    Label::primary(file_id, toml.pointer("/table/key/value1").unwrap().span),
                    Label::secondary(file_id, toml.pointer("/table/key/value2").unwrap().span),
                ]),
        );

        // Multiple labels out of order
        diags.push(
            Diagnostic::warning()
                .with_message("labels, out of order")
                .with_labels(vec![
                    Label::primary(file_id, toml.pointer("/table/key/value2").unwrap().span),
                    Label::secondary(file_id, toml.pointer("/table/key/value1").unwrap().span),
                ]),
        );

        // Simple with note
        diags.push(
            Diagnostic::error()
                .with_message("with code and note")
                .with_code("code-id")
                .with_notes(vec!["simple note".into()]),
        );

        // Only note, no labels
        diags.push(
            Diagnostic::note()
                .with_message("note only")
                .with_notes(vec!["i don't even have a label".into()]),
        );

        // Label and note
        diags.push(
            Diagnostic::warning()
                .with_message("label and note")
                .with_labels(vec![Label::primary(
                    file_id,
                    toml.pointer("/table/key/value1").unwrap().span,
                )])
                .with_notes(vec!["i have a label too".into()]),
        );

        // single line notes and label
        {
            let val = toml.pointer("/table/notes/0/text").unwrap();

            diags.push(
                Diagnostic::warning()
                    .with_message("single line notes and label")
                    .with_labels(vec![Label::primary(file_id, val.span)])
                    .with_notes(
                        val.as_str()
                            .unwrap()
                            .lines()
                            .map(|s| s.to_owned())
                            .collect(),
                    ),
            );
        }

        // multi-line label and notes
        {
            let val = toml.pointer("/table/notes/1/text").unwrap();
            diags.push(
                Diagnostic::warning()
                    .with_message("multi line")
                    .with_labels(vec![Label::primary(file_id, val.span)])
                    .with_notes(
                        val.as_str()
                            .unwrap()
                            .lines()
                            .map(|s| s.to_owned())
                            .collect(),
                    ),
            );
        }

        // multiple labels on same line
        {
            let val = toml.pointer("/table/notes/0/text").unwrap();
            let mut offset = val.span.start;
            diags.push(
                Diagnostic::warning()
                    .with_message("multiple labels on same line")
                    .with_labels(
                        val.as_str()
                            .unwrap()
                            .split(' ')
                            .map(|word| {
                                let lab = Label::secondary(file_id, offset..offset + word.len());
                                offset += word.len() + 1;
                                lab
                            })
                            .collect(),
                    )
                    .with_notes(
                        val.as_str()
                            .unwrap()
                            .lines()
                            .map(|s| s.to_owned())
                            .collect(),
                    ),
            );
        }

        // multiple labels on same line with messages
        {
            let val = toml.pointer("/table/notes/0/text").unwrap();
            let mut offset = val.span.start;
            diags.push(
                Diagnostic::warning()
                    .with_message("multiple labels with messages on same line")
                    .with_labels(
                        val.as_str()
                            .unwrap()
                            .split(' ')
                            .enumerate()
                            .map(|(i, word)| {
                                let lab = Label::secondary(file_id, offset..offset + word.len())
                                    .with_message(format!("word {i}"));
                                offset += word.len() + 1;
                                lab
                            })
                            .collect(),
                    )
                    .with_notes(
                        val.as_str()
                            .unwrap()
                            .lines()
                            .map(|s| s.to_owned())
                            .collect(),
                    ),
            );
        }

        // multiple labels on multiple lines with messages
        {
            let val = toml.pointer("/table/notes/1/text").unwrap();
            let mut offset = val.span.start;
            diags.push(
                Diagnostic::warning()
                    .with_message("multiple labels with messages on same line")
                    .with_labels(
                        val.as_str()
                            .unwrap()
                            .split(char::is_whitespace)
                            .enumerate()
                            .filter_map(|(i, word)| {
                                if word.is_empty() {
                                    return None;
                                }
                                let lab = Label::new(
                                    if i % 2 == 0 {
                                        codespan_reporting::diagnostic::LabelStyle::Primary
                                    } else {
                                        codespan_reporting::diagnostic::LabelStyle::Secondary
                                    },
                                    file_id,
                                    offset..offset + word.len(),
                                )
                                .with_message(format!("word {i}"));
                                offset += word.len() + 1;
                                Some(lab)
                            })
                            .collect(),
                    )
                    .with_notes(
                        val.as_str()
                            .unwrap()
                            .lines()
                            .map(|s| s.to_owned())
                            .collect(),
                    ),
            );
        }

        for diag in diags {
            codespan_reporting::term::emit(&mut term, &config, &files, &diag).unwrap();
        }

        insta::assert_snapshot!(String::from_utf8(term.into_inner()).unwrap());
    }
}
