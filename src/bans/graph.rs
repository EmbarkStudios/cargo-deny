use super::cfg::GraphHighlight;
use crate::{DepKind, Kid, Krate};
use anyhow::{Context, Error};
use krates::petgraph as pg;
use semver::Version;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt,
};

#[derive(Hash, Copy, Clone, PartialEq, Eq)]
struct Node<'a> {
    name: &'a str,
    version: &'a Version,
}

impl<'a, 'b: 'a> From<&'b Krate> for Node<'a> {
    fn from(d: &'b Krate) -> Self {
        Self {
            name: &d.name,
            version: &d.version,
        }
    }
}

impl<'a> fmt::Debug for Node<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, self.version)
    }
}

impl<'a> fmt::Display for Node<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, self.version)
    }
}

type Id = pg::graph::NodeIndex<u32>;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Shape {
    r#box,
    // polygon,
    // ellipse,
    // oval,
    // circle,
    // point,
    // egg,
    // triangle,
    // plaintext,
    // plain,
    // diamond,
    // trapezium,
    // parallelogram,
    // house,
    // pentagon,
    // hexagon,
    // septagon,
    // octagon,
    // doublecircle,
    // doubleoctagon,
    // tripleoctagon,
    // invtriangle,
    // invtrapezium,
    // invhouse,
    // Mdiamond,
    // Msquare,
    // Mcircle,
    // rect,
    // rectangle,
    // square,
    // star,
    // none,
    // underline,
    // cylinder,
    // note,
    // tab,
    // folder,
    // box3d,
    // component,
    // promoter,
    // cds,
    // terminator,
    // utr,
    // primersite,
    // restrictionsite,
    // fivepoverhang,
    // threepoverhang,
    // noverhang,
    // assembly,
    // signature,
    // insulator,
    // ribosite,
    // rnastab,
    // proteasesite,
    // proteinstab,
    // rpromoter,
    // rarrow,
    // larrow,
    // lpromoter,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Style {
    // filled,
    // invisible,
    // diagonals,
    rounded,
    // dashed,
    // dotted,
    // solid,
    // bold,
}

struct NodeAttributes<'a> {
    label: Option<&'a str>,
    shape: Option<Shape>,
    style: Option<Style>,
    color: Option<&'static str>,
    fill_color: Option<&'static str>,
}

impl<'a> Default for NodeAttributes<'a> {
    fn default() -> Self {
        Self {
            label: None,
            shape: None,
            style: None,
            color: None,
            fill_color: None,
        }
    }
}

impl<'a> NodeAttributes<'a> {
    fn has_attrs(&self) -> bool {
        self.label.is_some()
            || self.shape.is_some()
            || self.style.is_some()
            || self.color.is_some()
            || self.fill_color.is_some()
    }
}

#[derive(Default)]
struct EdgeAttributes<'a> {
    color: Option<&'static str>,
    label: Option<&'a str>,
}

const INDENT: &str = "    ";

pub(crate) fn create_graph(
    dup_name: &str,
    highlight: GraphHighlight,
    krates: &crate::Krates,
    duplicates: &[usize],
) -> Result<String, Error> {
    use pg::visit::{EdgeRef, NodeRef};

    let mut graph = pg::Graph::new();
    let mut node_map = HashMap::new();

    let mut node_stack = Vec::new();

    let duplicates: Vec<_> = duplicates.iter().map(|di| krates[*di].id.clone()).collect();

    for dup in &duplicates {
        let nid = graph.add_node(dup);
        node_map.insert(dup, nid);
        node_stack.push(dup);
    }

    while let Some(pid) = node_stack.pop() {
        let target = node_map[pid];
        let tid = krates.nid_for_kid(pid).context("unable to find crate")?;
        for incoming in krates.graph().edges_directed(tid, pg::Direction::Incoming) {
            let parent = &krates[incoming.source()];
            match node_map.get(&parent.id) {
                Some(pindex) => {
                    graph.update_edge(*pindex, target, incoming.weight().kind);
                }
                None => {
                    let pindex = graph.add_node(&parent.id);

                    graph.update_edge(pindex, target, incoming.weight().kind);

                    node_map.insert(&parent.id, pindex);
                    node_stack.push(&parent.id);
                }
            }
        }
    }

    let mut node_stack = Vec::new();
    let mut dupe_nodes = HashMap::<_, Vec<_>>::new();

    let mut edge_sets = Vec::with_capacity(duplicates.len());

    // Find all of the edges that lead to each duplicate,
    // and also keep track any crate duplicates anywhere, to make
    // them stand out more in the graph
    for id in &duplicates {
        let dup_node = node_map[id];
        let mut set = HashSet::new();

        node_stack.push(dup_node);

        while let Some(nid) = node_stack.pop() {
            let node = &graph[nid];
            let mut iditer = node.repr.splitn(3, ' ');
            let name = iditer.next().unwrap();

            match dupe_nodes.entry(name) {
                Entry::Occupied(it) => {
                    let it = it.into_mut();
                    if !it.contains(&nid) {
                        it.push(nid);
                    }
                }
                Entry::Vacant(it) => {
                    it.insert(vec![nid]);
                }
            }

            for edge in graph.edges_directed(nid, pg::Direction::Incoming) {
                if set.insert(edge.id()) {
                    node_stack.push(edge.source())
                }
            }
        }

        edge_sets.push(set);
    }

    dupe_nodes.retain(|_, v| {
        v.sort();
        // Only keep the actual duplicates
        v.len() > 1
    });

    // Find the version with the least number of total edges to the least common ancestor,
    // this will presumably be the easiest version to "fix"
    // This just returns the first lowest one, there can be multiple with
    // same number of edges
    let smollest = edge_sets
        .iter()
        .min_by(|a, b| a.len().cmp(&b.len()))
        .context("expected shortest edge path")?;

    // The krates are ordered lexicographically by id, so the first duplicate
    // is the one with the lowest version (or at least the lowest source...)
    let lowest = &edge_sets[0];

    print_graph(
        &graph,
        |node| {
            let node_weight = *node.weight();
            let repr = &node_weight.repr;

            let mut i = repr.splitn(3, ' ');
            let name = i.next().unwrap();
            let _version = i.next().unwrap();
            let source = i.next().unwrap();

            if dupe_nodes.contains_key(name) {
                let label = if source != "(registry+https://github.com/rust-lang/crates.io-index)" {
                    &repr[name.len() + 1..]
                } else {
                    &repr[name.len() + 1..repr.len() - source.len() - 1]
                };

                NodeAttributes {
                    label: Some(label),
                    shape: Some(Shape::r#box),
                    color: Some("red"),
                    style: Some(Style::rounded),
                    ..Default::default()
                }
            } else {
                NodeAttributes {
                    label: Some(&repr[0..repr.len() - source.len() - 1]),
                    shape: Some(Shape::r#box),
                    style: Some(Style::rounded),
                    ..Default::default()
                }
            }
        },
        |edge| {
            // Color edges if they are part of the lowest or smollest path,
            // based on the graph highlighting configuration
            let label = match edge.weight() {
                DepKind::Normal => None,
                DepKind::Dev => Some("dev"),
                DepKind::Build => Some("build"),
            };
            if highlight.simplest() && smollest.contains(&edge.id()) {
                EdgeAttributes {
                    color: Some("red"),
                    label,
                }
            } else if highlight.lowest_version() && lowest.contains(&edge.id()) {
                EdgeAttributes {
                    color: Some("blue"),
                    label,
                }
            } else {
                EdgeAttributes { color: None, label }
            }
        },
        |output| {
            use std::fmt::Write;

            for (i, (name, ids)) in dupe_nodes.iter().enumerate() {
                writeln!(output, "{}subgraph cluster_{} {{", INDENT, i)?;

                write!(output, "{}{}{{rank=same ", INDENT, INDENT)?;

                for nid in ids {
                    write!(output, "{} ", nid.index())?;
                }

                writeln!(
                    output,
                    "}}\n{}{}style=\"rounded{}\";\n{}{}label=\"{}\"\n{}}}",
                    INDENT,
                    INDENT,
                    if name == &dup_name { ",filled" } else { "" },
                    INDENT,
                    INDENT,
                    name,
                    INDENT
                )?;
            }

            Ok(())
        },
    )
}

fn print_graph<'a: 'b, 'b, NP, EP, SG>(
    graph: &'a pg::Graph<&'a crate::Kid, DepKind>,
    node_print: NP,
    edge_print: EP,
    subgraphs: SG,
) -> Result<String, Error>
where
    NP: Fn((Id, &'b &'a Kid)) -> NodeAttributes<'b>,
    EP: Fn(&pg::graph::EdgeReference<'_, DepKind, u32>) -> EdgeAttributes<'b>,
    SG: Fn(&mut String) -> Result<(), Error>,
{
    use pg::visit::{EdgeRef, IntoNodeReferences, NodeIndexable, NodeRef};
    use std::fmt::Write;
    let mut output = String::with_capacity(1024);
    writeln!(output, "digraph {{",)?;

    // output all nodes
    for node in graph.node_references() {
        write!(output, "{}{}", INDENT, graph.to_index(node.id()))?;

        let attrs = node_print(node);

        if !attrs.has_attrs() {
            writeln!(output)?;
            continue;
        }

        let mut append = false;
        write!(output, " [")?;

        if let Some(label) = attrs.label {
            write!(output, "label=\"{}\"", label)?;
            append = true;
        }

        if let Some(shape) = attrs.shape {
            write!(
                output,
                "{}shape={:?}",
                if append { ", " } else { "" },
                shape
            )?;
            append = true;
        }

        if let Some(style) = attrs.style {
            write!(
                output,
                "{}style={:?}",
                if append { ", " } else { "" },
                style
            )?;
            append = true;
        }

        if let Some(color) = attrs.color {
            write!(output, "{}color={}", if append { ", " } else { "" }, color)?;
            append = true;
        }

        if let Some(color) = attrs.fill_color {
            write!(
                output,
                "{}fillcolor={}",
                if append { ", " } else { "" },
                color
            )?;
        }

        writeln!(output, "]")?;
    }

    // output all edges
    for edge in graph.edge_references() {
        write!(
            output,
            "{}{} -> {}",
            INDENT,
            graph.to_index(edge.source()),
            graph.to_index(edge.target()),
        )?;

        let attrs = edge_print(&edge);

        write!(output, " [")?;

        let mut append = false;

        if let Some(label) = attrs.label {
            write!(output, "label=\"{}\"", label)?;
            append = true;
        }

        if let Some(color) = attrs.color {
            write!(output, "{}color={}", if append { ", " } else { "" }, color)?;
            //append = true;
        }

        writeln!(output, "]")?;
    }

    subgraphs(&mut output)?;

    writeln!(output, "}}")?;
    Ok(output)
}
