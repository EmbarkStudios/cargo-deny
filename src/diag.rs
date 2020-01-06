use crate::{KrateDetails, Krates, Pid};
use anyhow::Error;
pub use codespan_reporting::diagnostic::{Diagnostic, Label, Severity};

pub struct Pack {
    // The particular package that the diagnostics pertain to
    pub krate_id: Option<Pid>,
    pub diagnostics: Vec<Diagnostic>,
}

pub type Span = std::ops::Range<u32>;

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
    pub fn new(krates: &Krates) -> (Self, String) {
        use std::fmt::Write;

        let mut sl = String::with_capacity(4 * 1024);
        let mut spans = Vec::with_capacity(krates.krates_count());
        for krate in krates.krates() {
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
                span: span_start as u32..span_end as u32,
            });
        }

        (Self { spans }, sl)
    }
}

//use petgraph::Graph;
//use rayon::prelude::*;
use std::collections::{hash_map::Entry, HashMap, HashSet};

struct Node<'a> {
    metadata: &'a KrateDetails,
}

/// Simplified copy of what cargo tree does to display dependency graphs.
/// In our case, we only care about the inverted form, ie, not what the
/// dependencies of a package are, but rather how a particular package
/// is actually pulled into the root project
pub struct Grapher<'a> {
    //graph: Graph<Node<'a>, &'a str>,
    //node_map: HashMap<Pid, Nid>,
    krates: &'a Krates,
}

const DWN: char = '│';
const TEE: char = '├';
const ELL: char = '└';
const RGT: char = '─';

struct NodePrint<'a> {
    krate: &'a crate::graph::Node,
    id: crate::graph::NodeId,
    kind: &'static str,
}

impl<'a> Grapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self {
            //graph: Graph::new(),
            //node_map: HashMap::new(),
            krates,
        }
    }

    pub fn write_graph(&mut self, id: &Pid) -> Result<String, Error> {
        //self.build_graph_to_package(id)?;

        let mut out = String::with_capacity(1024);
        let mut levels = Vec::new();
        let mut visited = HashSet::new();

        let node = self.krates.get_node(id);

        let np = NodePrint {
            krate: node.0,
            id: node.1,
            kind: "",
        };

        self.write_parent(np, &mut out, &mut visited, &mut levels)?;

        Ok(out)
    }

    fn write_parent(
        &self,
        np: NodePrint<'a>,
        out: &mut String,
        visited: &mut HashSet<crate::graph::NodeId>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        use petgraph::visit::EdgeRef;
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
        for edge in self
            .krates
            .graph
            .edges_directed(np.id, petgraph::Direction::Incoming)
        {
            let parent_id = edge.source();
            let parent = &self.krates.graph[parent_id];

            let kind = match edge.weight() {
                crate::DepKind::Normal => "",
                crate::DepKind::Dev => "dev",
                crate::DepKind::Build => "build",
            };

            parents.push(NodePrint {
                krate: parent,
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
        visited: &mut HashSet<crate::graph::NodeId>,
        levels_continue: &mut Vec<bool>,
    ) -> Result<(), Error> {
        let mut it = parents.iter().peekable();

        let cont = parents.len() - 1;

        for (i, parent) in parents.into_iter().enumerate() {
            levels_continue.push(i < cont);
            self.write_parent(parent, out, visited, levels_continue)?;
            levels_continue.pop();
        }

        Ok(())
    }
}
