use super::NodePrint;
use crate::{DepKind, Kid, Krates};
use anyhow::{Context, Error};
use krates::petgraph as pg;
use std::collections::HashSet;

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

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !v
}

fn is_normal(v: &'static str) -> bool {
    v == ""
}

#[allow(clippy::ptr_arg)]
fn is_empty(v: &Vec<GraphNode>) -> bool {
    v.is_empty()
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

use super::{Diag, FileId, Files, Severity};

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
