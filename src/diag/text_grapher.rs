use super::NodePrint;
use crate::{DepKind, Kid, Krates};
use anyhow::{Context, Error};
use krates::petgraph as pg;
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

    #[allow(clippy::ptr_arg)]
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
