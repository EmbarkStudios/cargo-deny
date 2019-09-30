use crate::{KrateDetails, Krates};
use failure::Error;
use petgraph::Graph;
use rayon::prelude::*;
use std::collections::{hash_map::Entry, HashMap, HashSet};

pub type Pid = cargo_metadata::PackageId;
type Nid = petgraph::graph::NodeIndex<u32>;

struct Node<'a> {
    metadata: &'a KrateDetails,
}

/// Simplified copy of what cargo tree does to display dependency graphs.
/// In our case, we only care about the inverted form, ie, not what the
/// dependencies of a package are, but rather how a particular package
/// is actually pulled into the root project
pub struct Grapher<'a> {
    graph: Graph<Node<'a>, &'a str>,
    node_map: HashMap<Pid, Nid>,
    krates: &'a Krates,
}

const DWN: char = '│';
const TEE: char = '├';
const ELL: char = '└';
const RGT: char = '─';

impl<'a> Grapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self {
            graph: Graph::new(),
            node_map: HashMap::new(),
            krates,
        }
    }

    fn build_graph_to_package(&mut self, id: &Pid) -> Result<(), Error> {
        use smallvec::SmallVec;

        if self.node_map.contains_key(id) {
            return Ok(());
        }

        let node = Node {
            metadata: &self.krates.krates[self.krates.krate_map[id]],
        };

        let node_id = self.graph.add_node(node);
        self.node_map.insert(id.clone(), node_id);

        let mut pending = SmallVec::<[Pid; 10]>::new();
        pending.push(id.clone());

        while let Some(pkg_id) = pending.pop() {
            let idx = self.node_map[&pkg_id];
            let pkg = &self.krates.krates[self.krates.krate_map[&pkg_id]];

            // Obtain the crates that are directly referencing the current crate
            let parents: Vec<_> = self
                .krates
                .resolved
                .nodes
                .par_iter()
                .filter_map(|rnode| {
                    rnode
                        .dependencies
                        .binary_search(&pkg_id)
                        .ok()
                        .map(|_| &self.krates.krates[self.krates.krate_map[&rnode.id]])
                })
                .collect();

            for parent in parents {
                let parent_nid = match self.node_map.entry(parent.id.clone()) {
                    Entry::Occupied(e) => *e.get(),
                    Entry::Vacant(e) => {
                        pending.push(parent.id.clone());
                        let parent_node = Node { metadata: &parent };

                        *e.insert(self.graph.add_node(parent_node))
                    }
                };

                let kind = parent
                    .deps
                    .iter()
                    .find(|d| d.name == pkg.name)
                    .map(|dep| match dep.kind {
                        cargo_metadata::DependencyKind::Normal
                        | cargo_metadata::DependencyKind::Unknown => "",
                        cargo_metadata::DependencyKind::Development => "dev",
                        cargo_metadata::DependencyKind::Build => "build",
                    })
                    .unwrap_or("");

                self.graph.add_edge(idx, parent_nid, kind);
            }
        }

        Ok(())
    }

    pub fn write_graph(&mut self, id: &Pid) -> Result<String, Error> {
        self.build_graph_to_package(id)?;

        let mut out = String::with_capacity(1024);
        let mut levels = Vec::new();
        let mut visited = HashSet::new();

        let node = &self.graph[self.node_map[id]];

        self.write_parent(node, "", &mut out, &mut visited, &mut levels)?;

        Ok(out)
    }

    fn write_parent(
        &self,
        krate: &Node<'a>,
        kind: &'a str,
        out: &mut String,
        visited: &mut HashSet<Pid>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        use petgraph::visit::EdgeRef;
        use std::fmt::Write;

        let new = visited.insert(krate.metadata.id.clone());
        let star = if new { "" } else { " (*)" };

        if let Some((&last_continues, rest)) = levels_continue.split_last() {
            for &continues in rest {
                let c = if continues { DWN } else { ' ' };
                write!(out, "{}   ", c)?;
            }

            let c = if last_continues { TEE } else { ELL };
            write!(out, "{0}{1}{1} ", c, RGT)?;
        }

        match kind {
            "" => writeln!(
                out,
                "{} v{}{}",
                krate.metadata.name, krate.metadata.version, star
            ),
            k => writeln!(
                out,
                "({}) {} v{}{}",
                k, krate.metadata.name, krate.metadata.version, star
            ),
        }?;

        if !new {
            return Ok(());
        }

        let mut parents = smallvec::SmallVec::<[(&Node<'_>, &'_ str); 6]>::new();
        for edge in self.graph.edges_directed(
            self.node_map[&krate.metadata.id],
            petgraph::Direction::Outgoing,
        ) {
            let parent = &self.graph[edge.target()];
            parents.push((parent, *edge.weight()));
        }

        if !parents.is_empty() {
            self.write_parents(&mut parents, out, visited, levels_continue)?;
        }

        Ok(())
    }

    fn write_parents(
        &self,
        parents: &mut [(&Node<'a>, &'a str)],
        out: &mut String,
        visited: &mut HashSet<Pid>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        // Resolve uses Hash data types internally but we want consistent output ordering
        parents.sort_by_key(|n| &n.0.metadata.id);

        let mut it = parents.iter().peekable();
        while let Some(parent) = it.next() {
            levels_continue.push(it.peek().is_some());

            self.write_parent(parent.0, parent.1, out, visited, levels_continue)?;

            levels_continue.pop();
        }

        Ok(())
    }
}
