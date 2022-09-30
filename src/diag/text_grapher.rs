use super::NodePrint;
use crate::{DepKind, Kid, Krates};
use anyhow::{Context, Error};
use krates::{petgraph as pg, Edge, Node};
use std::collections::HashSet;
use std::fmt::Write;

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

impl<'a> TextGrapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self { krates }
    }

    pub fn write_graph(&self, id: &super::GraphNode, add_features: bool) -> Result<String, Error> {
        let mut out = String::with_capacity(1024);
        let mut levels = Vec::new();
        let mut visited = HashSet::new();

        let (node_id, _node) = self
            .krates
            .get_node(&id.kid, None)
            .context("unable to find node")?;

        let np = NodePrint {
            node: node_id,
            edge: None,
        };

        self.write_parent(&np, add_features, &mut out, &mut visited, &mut levels)?;

        Ok(out)
    }

    #[inline]
    fn write_node(&self, np: &NodePrint, star: &str, out: &mut String) -> Result<(), Error> {
        match &self.krates.graph()[np.node] {
            Node::Krate { krate, .. } => {
                let kind = np.edge.and_then(|eid| match self.krates.graph()[eid] {
                    Edge::Dep { kind, .. } => match kind {
                        DepKind::Normal => None,
                        DepKind::Dev => Some("dev"),
                        DepKind::Build => Some("build"),
                    },
                    Edge::Feature => None,
                    Edge::DepFeature { kind, .. } => match kind {
                        DepKind::Normal => Some("feature ()"),
                        DepKind::Dev => Some("feature (dev)"),
                        DepKind::Build => Some("feature (build)"),
                    },
                });

                if let Some(kind) = kind {
                    writeln!(out, "({kind}) {} v{}{star}", krate.name, krate.version)
                } else {
                    writeln!(out, "{} v{}{star}", krate.name, krate.version)
                }?;
            }
            Node::Feature { name, .. } => {
                writeln!(out, "feature {name} {star}")?;
            }
        }

        Ok(())
    }

    #[allow(clippy::ptr_arg)]
    fn write_parent(
        &self,
        np: &NodePrint,
        add_features: bool,
        out: &mut String,
        visited: &mut HashSet<krates::NodeId>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        use pg::visit::EdgeRef;

        let new = visited.insert(np.node);

        if add_features || matches!(self.krates.graph()[np.node], krates::Node::Krate { .. }) {
            let star = if new { "" } else { " (*)" };

            if let Some((&last_continues, rest)) = levels_continue.split_last() {
                for &continues in rest {
                    let c = if continues { DWN } else { ' ' };
                    write!(out, "{c}   ")?;
                }

                let c = if last_continues { TEE } else { ELL };
                write!(out, "{c}{0}{0} ", RGT)?;
            }

            self.write_node(np, star, out)?;
        }

        if !new {
            return Ok(());
        }

        let mut parents = smallvec::SmallVec::<[NodePrint; 10]>::new();
        let graph = self.krates.graph();
        for edge in graph.edges_directed(np.node, pg::Direction::Incoming) {
            let parent_id = edge.source();

            parents.push(NodePrint {
                node: parent_id,
                edge: Some(edge.id()),
            });
        }

        if !parents.is_empty() {
            // Resolve uses Hash data types internally but we want consistent output ordering
            parents.sort_by(|a, b| {
                let graph = self.krates.graph();

                match (&graph[a.node], &graph[b.node]) {
                    (Node::Krate { krate: a, .. }, Node::Krate { krate: b, .. }) => a.id.cmp(&b.id),
                    (Node::Krate { .. }, Node::Feature { .. }) => std::cmp::Ordering::Less,
                    (Node::Feature { .. }, Node::Krate { .. }) => std::cmp::Ordering::Greater,
                    (Node::Feature { name: a, .. }, Node::Feature { name: b, .. }) => a.cmp(b),
                }
            });

            let cont = parents.len() - 1;

            for (i, parent) in parents.into_iter().enumerate() {
                levels_continue.push(i < cont);
                self.write_parent(&parent, add_features, out, visited, levels_continue)?;
                levels_continue.pop();
            }
        }

        Ok(())
    }
}
