use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

use crate::{DepKind, Kid, Krate, Krates};
use anyhow::{Context, Error};
pub use codespan_reporting::diagnostic::Severity;
use krates::petgraph as pg;

pub use codespan::FileId;

pub type Diagnostic = codespan_reporting::diagnostic::Diagnostic<FileId>;
pub type Label = codespan_reporting::diagnostic::Label<FileId>;
pub type Files = codespan::Files<String>;
// Map of crate id => (path to cargo.toml, synthetic cargo.toml content, map(cratename => crate span))
pub type RawCargoSpans = HashMap<Kid, (PathBuf, String, HashMap<String, Range<usize>>)>;
// Same as RawCargoSpans but path to cargo.toml and cargo.toml content replaced with FileId
pub type CargoSpans = HashMap<Kid, (FileId, HashMap<String, Range<usize>>)>;

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
}

impl std::ops::Index<usize> for KrateSpans {
    type Output = Span;

    #[inline]
    fn index(&self, i: usize) -> &Self::Output {
        &self.spans[i].span
    }
}

impl KrateSpans {
    pub fn new(krates: &Krates) -> (Self, String, RawCargoSpans) {
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
                    krate.manifest_path.parent().unwrap().to_string_lossy()
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

        (Self { spans }, sl, cargo_spans)
    }
}

use std::collections::HashSet;

/// Simplified copy of what cargo tree does to display dependency graphs.
/// In our case, we only care about the inverted form, ie, not what the
/// dependencies of a package are, but rather how a particular package
/// is actually pulled in via 1 or more root crates
pub struct TextGrapher<'a> {
    krates: &'a Krates,
}

const DWN: char = '│';
const TEE: char = '├';
const ELL: char = '└';
const RGT: char = '─';

struct NodePrint<'a> {
    krate: &'a Krate,
    id: krates::NodeId,
    kind: &'static str,
}

impl<'a> TextGrapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self { krates }
    }

    pub fn write_graph(&self, id: &Kid) -> Result<String, Error> {
        let mut out = String::with_capacity(1024);
        let mut levels = Vec::new();
        let mut visited = HashSet::new();

        let node_id = self.krates.nid_for_kid(id).context("unable to find node")?;
        let krate = &self.krates[node_id];

        let np = NodePrint {
            krate,
            id: node_id,
            kind: "",
        };

        self.write_parent(np, &mut out, &mut visited, &mut levels)?;

        Ok(out)
    }

    fn write_parent(
        &self,
        np: NodePrint<'a>,
        out: &mut String,
        visited: &mut HashSet<krates::NodeId>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        use pg::visit::EdgeRef;
        use std::fmt::Write;

        let new = visited.insert(np.id);
        let star = if new { "" } else { " (*)" };

        if let Some((&last_continues, rest)) = levels_continue.split_last() {
            for &continues in rest {
                let c = if continues { DWN } else { ' ' };
                write!(out, "{}   ", c)?;
            }

            let c = if last_continues { TEE } else { ELL };
            write!(out, "{0}{1}{1} ", c, RGT)?;
        }

        match np.kind {
            "" => writeln!(out, "{} v{}{}", np.krate.name, np.krate.version, star),
            kind => writeln!(
                out,
                "({}) {} v{}{}",
                kind, np.krate.name, np.krate.version, star
            ),
        }?;

        if !new {
            return Ok(());
        }

        let mut parents = smallvec::SmallVec::<[NodePrint<'a>; 10]>::new();
        let graph = self.krates.graph();
        for edge in graph.edges_directed(np.id, pg::Direction::Incoming) {
            let parent_id = edge.source();
            let parent = &graph[parent_id];

            let kind = match edge.weight().kind {
                DepKind::Normal => "",
                DepKind::Dev => "dev",
                DepKind::Build => "build",
            };

            parents.push(NodePrint {
                krate: &parent.krate,
                id: parent_id,
                kind,
            });
        }

        if !parents.is_empty() {
            // Resolve uses Hash data types internally but we want consistent output ordering
            parents.sort_by_key(|n| &n.krate.id);
            self.write_parents(parents, out, visited, levels_continue)?;
        }

        Ok(())
    }

    fn write_parents(
        &self,
        parents: smallvec::SmallVec<[NodePrint<'a>; 10]>,
        out: &mut String,
        visited: &mut HashSet<krates::NodeId>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        let cont = parents.len() - 1;

        for (i, parent) in parents.into_iter().enumerate() {
            levels_continue.push(i < cont);
            self.write_parent(parent, out, visited, levels_continue)?;
            levels_continue.pop();
        }

        Ok(())
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !v
}

#[allow(clippy::ptr_arg)]
fn is_empty(v: &Vec<GraphNode>) -> bool {
    v.is_empty()
}

fn is_normal(v: &'static str) -> bool {
    v == ""
}

#[derive(serde::Serialize)]
pub struct GraphNode {
    name: String,
    version: semver::Version,
    #[serde(skip_serializing_if = "is_normal")]
    kind: &'static str,
    #[serde(skip_serializing_if = "is_false")]
    repeat: bool,
    #[serde(skip_serializing_if = "is_empty")]
    parents: Vec<GraphNode>,
}

/// As with the textgrapher, only crates inclusion graphs, but in the form of
/// a serializable object rather than a text string
pub struct ObjectGrapher<'a> {
    krates: &'a Krates,
}

impl<'a> ObjectGrapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self { krates }
    }

    pub fn write_graph(&self, id: &Kid) -> Result<GraphNode, Error> {
        let mut visited = HashSet::new();

        let node_id = self.krates.nid_for_kid(id).context("unable to find node")?;
        let krate = &self.krates[node_id];

        let np = NodePrint {
            krate,
            id: node_id,
            kind: "",
        };

        Ok(self.write_parent(np, &mut visited)?)
    }

    fn write_parent(
        &self,
        np: NodePrint<'a>,
        visited: &mut HashSet<krates::NodeId>,
    ) -> Result<GraphNode, Error> {
        use pg::visit::EdgeRef;

        let repeat = !visited.insert(np.id);

        let mut node = GraphNode {
            name: np.krate.name.clone(),
            version: np.krate.version.clone(),
            kind: np.kind,
            repeat,
            parents: Vec::new(),
        };

        if repeat {
            return Ok(node);
        }

        let mut parents = smallvec::SmallVec::<[NodePrint<'a>; 10]>::new();
        let graph = self.krates.graph();
        for edge in graph.edges_directed(np.id, pg::Direction::Incoming) {
            let parent_id = edge.source();
            let parent = &graph[parent_id];

            let kind = match edge.weight().kind {
                DepKind::Normal => "",
                DepKind::Dev => "dev",
                DepKind::Build => "build",
            };

            parents.push(NodePrint {
                krate: &parent.krate,
                id: parent_id,
                kind,
            });
        }

        if !parents.is_empty() {
            // Resolve uses Hash data types internally but we want consistent output ordering
            parents.sort_by_key(|n| &n.krate.id);
            node.parents.reserve(parents.len());

            for parent in parents {
                let pnode = self.write_parent(parent, visited)?;
                node.parents.push(pnode);
            }
        }

        Ok(node)
    }
}

pub type CSDiag = codespan_reporting::diagnostic::Diagnostic<FileId>;

pub fn cs_diag_to_json(diag: CSDiag, files: &Files) -> serde_json::Value {
    let mut val = serde_json::json!({
        "type": "diagnostic",
        "fields": {
            "severity": match diag.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Note => "note",
                Severity::Help => "help",
                Severity::Bug => "bug",
            },
            "message": diag.message,
        },
    });

    {
        let obj = val.as_object_mut().unwrap();
        let obj = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

        if let Some(code) = diag.code {
            obj.insert("code".to_owned(), serde_json::Value::String(code));
        }

        if !diag.labels.is_empty() {
            let mut labels = Vec::with_capacity(diag.labels.len());

            for label in diag.labels {
                let location = files
                    .location(label.file_id, label.range.start as u32)
                    .unwrap();
                labels.push(serde_json::json!({
                    "message": label.message,
                    "span": &files.source(label.file_id)[label.range],
                    "line": location.line.to_usize() + 1,
                    "column": location.column.to_usize() + 1,
                }));
            }

            obj.insert("labels".to_owned(), serde_json::Value::Array(labels));
        }

        if !diag.notes.is_empty() {
            obj.insert(
                "notes".to_owned(),
                serde_json::Value::Array(
                    diag.notes
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    val
}

pub fn diag_to_json(
    diag: Diag,
    files: &Files,
    grapher: Option<&ObjectGrapher<'_>>,
) -> serde_json::Value {
    let mut to_print = cs_diag_to_json(diag.diag, files);

    let obj = to_print.as_object_mut().unwrap();
    let fields = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

    if let Some(grapher) = &grapher {
        let mut graphs = Vec::new();
        for kid in diag.kids {
            if let Ok(graph) = grapher.write_graph(&kid) {
                if let Ok(sgraph) = serde_json::value::to_value(graph) {
                    graphs.push(sgraph);
                }
            }
        }

        fields.insert("graphs".to_owned(), serde_json::Value::Array(graphs));
    }

    if let Some((key, val)) = diag.extra {
        fields.insert(key.to_owned(), val);
    }

    to_print
}
