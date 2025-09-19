use super::NodePrint;
use crate::{DepKind, Krates};
use anyhow::Context;
use krates::{Edge, Node, petgraph as pg};
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
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<&'static str>,
    },
    Feature {
        crate_name: String,
        name: String,
    },
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !v
}

#[allow(clippy::ptr_arg)]
fn is_empty(v: &Vec<GraphNode>) -> bool {
    v.is_empty()
}

/// Provides the `InclusionGrapher::write_graph` method which creates a reverse
/// dependency graph rooted at a specific node
pub struct InclusionGrapher<'a> {
    pub krates: &'a Krates,
}

impl<'a> InclusionGrapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self { krates }
    }

    /// Creates an inclusion graph rooted at the specified node.
    pub fn build_graph(
        &self,
        id: &super::GraphNode,
        max_feature_depth: usize,
    ) -> anyhow::Result<GraphNode> {
        let mut visited = HashSet::new();

        let (node_id, _node) = self
            .krates
            .get_node(&id.kid, id.feature.as_deref())
            .context("unable to find node")?;

        let np = NodePrint {
            node: node_id,
            edge: None,
        };

        let root = self.append_node(np, 0, max_feature_depth, &mut visited)?;

        // If the graph was rooted on a feature node, we want to use that as the
        // root when building the graph, but want the actual crate the feature
        // belongs to be the root of the graph the user sees
        if id.feature.is_some() {
            let (_id, root_krate) = self.krates.get_node(&id.kid, None).with_context(|| {
                format!(
                    "graph was built but we were unable to find the node for {}",
                    id.kid
                )
            })?;

            let inner = if let Node::Krate { krate, .. } = root_krate {
                NodeInner::Krate {
                    name: krate.name.clone(),
                    version: krate.version.clone(),
                    kind: None,
                }
            } else {
                anyhow::bail!("unable to find crate node for {}", id.kid);
            };

            Ok(GraphNode {
                inner,
                repeat: false,
                parents: vec![root],
            })
        } else {
            Ok(root)
        }
    }

    fn make_node(&self, np: NodePrint) -> NodeInner {
        match &self.krates.graph()[np.node] {
            Node::Krate { krate, .. } => {
                let kind = np.edge.and_then(|eid| match self.krates.graph()[eid] {
                    Edge::Dep { kind, .. } | Edge::DepFeature { kind, .. } => match kind {
                        DepKind::Normal => None,
                        DepKind::Dev => Some("dev"),
                        DepKind::Build => Some("build"),
                    },
                    Edge::Feature => None,
                });

                NodeInner::Krate {
                    name: krate.name.clone(),
                    version: krate.version.clone(),
                    kind,
                }
            }
            Node::Feature { name, krate_index } => {
                let crate_name =
                    if let Node::Krate { krate, .. } = &self.krates.graph()[*krate_index] {
                        krate.name.clone()
                    } else {
                        "".to_owned()
                    };

                NodeInner::Feature {
                    crate_name,
                    name: name.clone(),
                }
            }
        }
    }

    fn append_node(
        &self,
        np: NodePrint,
        depth: usize,
        max_feature_depth: usize,
        visited: &mut HashSet<krates::NodeId>,
    ) -> anyhow::Result<GraphNode> {
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

        if depth < max_feature_depth {
            node_parents.extend(graph.edges_directed(np.node, pg::Direction::Incoming).map(
                |edge| NodePrint {
                    node: edge.source(),
                    edge: Some(edge.id()),
                },
            ));
        } else {
            // If we're not adding features we need to walk up any feature edges
            // until we reach an actual crate dependenc

            node_parents.extend(
                self.krates
                    .direct_dependents(np.node)
                    .into_iter()
                    .map(|dd| NodePrint {
                        node: dd.node_id,
                        edge: Some(dd.edge_id),
                    }),
            );
        }

        let parents = if !node_parents.is_empty() {
            // Resolve uses Hash data types internally but we want consistent output ordering
            node_parents.sort_by(|a, b| match (&graph[a.node], &graph[b.node]) {
                (Node::Krate { krate: a, .. }, Node::Krate { krate: b, .. }) => a.id.cmp(&b.id),
                (Node::Krate { .. }, Node::Feature { .. }) => std::cmp::Ordering::Less,
                (Node::Feature { .. }, Node::Krate { .. }) => std::cmp::Ordering::Greater,
                (Node::Feature { name: a, .. }, Node::Feature { name: b, .. }) => a.cmp(b),
            });

            let mut parents = Vec::with_capacity(node_parents.len());

            for parent in node_parents {
                let pnode = self.append_node(parent, depth + 1, max_feature_depth, visited)?;
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
    grapher: Option<&InclusionGrapher<'_>>,
) -> serde_json::Value {
    let mut to_print = cs_diag_to_json(diag.diag, files);

    let obj = to_print.as_object_mut().unwrap();
    let fields = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

    if let Some(grapher) = &grapher {
        let mut graphs = Vec::new();
        for gn in diag.graph_nodes {
            if let Ok(graph) =
                grapher.build_graph(&gn, if diag.with_features { usize::MAX } else { 0 })
                && let Ok(sgraph) = serde_json::value::to_value(graph)
            {
                graphs.push(sgraph);
            }
        }

        fields.insert("graphs".to_owned(), serde_json::Value::Array(graphs));
    }

    if let Some(extra) = diag.extra {
        let key = extra.key();
        if let Ok(val) = serde_json::to_value(extra) {
            fields.insert(key.into(), val);
        }
    }

    to_print
}

pub fn write_graph_as_text(root: &GraphNode) -> String {
    use std::fmt::Write;

    const DWN: char = '│';
    const TEE: char = '├';
    const ELL: char = '└';
    const RGT: char = '─';

    let mut out = String::with_capacity(256);
    let mut levels = smallvec::SmallVec::<[bool; 10]>::new();

    fn write(
        node: &GraphNode,
        out: &mut String,
        levels_continue: &mut smallvec::SmallVec<[bool; 10]>,
    ) {
        let star = if !node.repeat { "" } else { " (*)" };

        if let Some((&last_continues, rest)) = levels_continue.split_last() {
            for &continues in rest {
                let c = if continues { DWN } else { ' ' };
                write!(out, "{c}   ").unwrap();
            }

            let c = if last_continues { TEE } else { ELL };
            write!(out, "{c}{RGT}{RGT} ").unwrap();
        }

        match &node.inner {
            NodeInner::Krate {
                name,
                version,
                kind,
            } => {
                if let Some(kind) = kind {
                    write!(out, "({kind}) ").unwrap();
                }

                writeln!(out, "{name} v{version}{star}").unwrap();
            }
            NodeInner::Feature { crate_name, name } => {
                writeln!(out, "{crate_name} feature '{name}' {star}").unwrap();
            }
        }

        if node.parents.is_empty() {
            return;
        }

        let cont = node.parents.len() - 1;

        for (i, parent) in node.parents.iter().enumerate() {
            levels_continue.push(i < cont);
            write(parent, out, levels_continue);
            levels_continue.pop();
        }
    }

    write(root, &mut out, &mut levels);
    out
}
