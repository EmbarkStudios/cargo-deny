use super::NodePrint;
use crate::{DepKind, Kid, Krates};
use anyhow::{Context, Error};
use krates::petgraph as pg;
use std::collections::HashSet;

#[derive(serde::Serialize)]
pub struct GraphNode {
    #[serde(flatten)]
    inner: NodeInner,
    #[serde(skip_serializing_if = "is_false")]
    repeat: bool,
    #[serde(skip_serializing_if = "is_empty")]
    parents: Vec<GraphNode>,
}

#[derive(serde::Serialize)]
pub enum NodeInner {
    Krate {
        name: String,
        version: semver::Version,
        #[serde(skip_serializing_if = "is_normal")]
        kind: &'static str,
    },
    Feature {
        name: String,
    },
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !v
}

fn is_normal(v: &'static str) -> bool {
    v.is_empty()
}

#[allow(clippy::ptr_arg)]
fn is_empty(v: &Vec<GraphNode>) -> bool {
    v.is_empty()
}

/// As with the textgrapher, only emits inclusion graphs, but in the form of
/// a serializable object rather than a text string
pub struct ObjectGrapher<'a> {
    krates: &'a Krates,
}

impl<'a> ObjectGrapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self { krates }
    }

    pub fn write_graph(
        &self,
        id: &super::GraphNode,
        add_features: bool,
    ) -> Result<GraphNode, Error> {
        let mut visited = HashSet::new();

        let (node_id, _node) = self
            .krates
            .get_node(&id.kid, id.feature.as_deref())
            .context("unable to find node")?;

        let np = NodePrint {
            node: node_id,
            edge: None,
        };

        self.write_parent(np, add_features, &mut visited)
    }

    fn make_node(&self, np: NodePrint) -> NodeInner {
        match &self.krates.graph()[np.node] {
            krates::Node::Krate { krate, .. } => {
                let kind = np
                    .edge
                    .map(|eid| match self.krates.graph()[eid] {
                        krates::Edge::Dep { kind, .. } => match kind {
                            DepKind::Normal => "",
                            DepKind::Dev => "dev",
                            DepKind::Build => "build",
                        },
                        krates::Edge::Feature => "feature",
                    })
                    .unwrap_or("");

                NodeInner::Krate {
                    name: krate.name.clone(),
                    version: krate.version.clone(),
                    kind,
                }
            }
            krates::Node::Feature { name, .. } => NodeInner::Feature { name: name.clone() },
        }
    }

    fn write_parent(
        &self,
        np: NodePrint,
        add_features: bool,
        visited: &mut HashSet<krates::NodeId>,
    ) -> Result<GraphNode, Error> {
        use pg::visit::EdgeRef;

        if !visited.insert(np.node) {
            return Ok(GraphNode {
                inner: self.make_node(np),
                repeat: true,
                parents: Vec::new(),
            });
        }

        let mut node_parents = smallvec::SmallVec::<[NodePrint; 10]>::new();
        let graph = self.krates.graph();
        for edge in graph.edges_directed(np.node, pg::Direction::Incoming) {
            let parent_id = edge.source();

            if let krates::Edge::Feature = edge.weight() {
                if !add_features {
                    continue;
                }
            }

            node_parents.push(NodePrint {
                node: parent_id,
                edge: Some(edge.id()),
            });
        }

        let parents = if !node_parents.is_empty() {
            // Resolve uses Hash data types internally but we want consistent output ordering
            // node_parents.sort_by(|a, b| {

            //     &n.krate.id
            // });

            let mut parents = Vec::with_capacity(node_parents.len());

            for parent in node_parents {
                let pnode = self.write_parent(parent, add_features, visited)?;
                parents.push(pnode);
            }

            parents
        } else {
            Vec::new()
        };

        Ok(GraphNode {
            inner: self.make_node(np),
            repeat: false,
            parents,
        })
    }
}

use super::{Diag, FileId, Files, Severity};

pub type CsDiag = codespan_reporting::diagnostic::Diagnostic<FileId>;

pub fn cs_diag_to_json(diag: CsDiag, files: &Files) -> serde_json::Value {
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
                    "span": files.source(label.file_id)[label.range].trim_matches('"'),
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
        for gn in diag.graph_nodes {
            if let Ok(graph) = grapher.write_graph(&gn, diag.with_features) {
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
