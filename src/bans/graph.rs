use super::cfg::GraphHighlight;
use crate::{DepKind, Kid, Krate};
use anyhow::{Context, Error};
use krates::petgraph as pg;
use semver::Version;
use std::{
    collections::{btree_map::Entry, BTreeMap, HashSet},
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
    diamond,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Style {
    rounded,
}

#[derive(Default)]
struct NodeAttributes<'a> {
    label: Option<&'a str>,
    shape: Option<Shape>,
    style: Option<Style>,
    color: Option<&'static str>,
    fill_color: Option<&'static str>,
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

#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
struct DupNode<'k> {
    kid: &'k Kid,
    feature: Option<&'k str>,
}

pub(crate) fn create_graph(
    dup_name: &str,
    highlight: GraphHighlight,
    krates: &crate::Krates,
    dup_ids: &[usize],
) -> Result<String, Error> {
    use pg::visit::{EdgeRef, NodeRef};

    let mut graph = pg::Graph::new();
    let mut node_map = BTreeMap::new();

    let mut node_stack = Vec::with_capacity(dup_ids.len());

    let duplicates: Vec<_> = dup_ids.iter().map(|di| krates[*di].id.clone()).collect();

    for (index, dupid) in dup_ids.iter().zip(duplicates.iter()) {
        let dn = DupNode {
            kid: dupid,
            feature: None,
        };
        let nid = graph.add_node(dn);
        node_map.insert(dn, nid);
        node_stack.push((krates::NodeId::new(*index), nid));
    }

    {
        let kg = krates.graph();
        let mut visited = HashSet::new();

        if true {
            while let Some((nid, target)) = node_stack.pop() {
                for edge in kg.edges_directed(nid, pg::Direction::Incoming) {
                    match &kg[edge.source()] {
                        krates::Node::Krate { krate, .. } => {
                            if let krates::Edge::Dep { kind, .. }
                            | krates::Edge::DepFeature { kind, .. } = edge.weight()
                            {
                                let dn = DupNode {
                                    kid: &krate.id,
                                    feature: None,
                                };

                                if let Some(pindex) = node_map.get(&dn) {
                                    graph.update_edge(*pindex, target, *kind);
                                } else {
                                    let pindex = graph.add_node(DupNode {
                                        kid: &krate.id,
                                        feature: None,
                                    });

                                    graph.update_edge(pindex, target, *kind);

                                    node_map.insert(dn, pindex);
                                    node_stack.push((edge.source(), pindex));
                                }
                            }
                        }
                        krates::Node::Feature { krate_index, .. } => {
                            if *krate_index == nid && visited.insert(edge.source()) {
                                node_stack.push((edge.source(), target));
                            }
                        }
                    }
                }
            }
        } else {
            while let Some((src_id, tar_id)) = node_stack.pop() {
                let target = tar_id;

                for edge in kg.edges_directed(src_id, pg::Direction::Incoming) {
                    let source = edge.source();
                    match &kg[source] {
                        krates::Node::Krate { krate, .. } => {
                            if let krates::Edge::Dep { kind, .. }
                            | krates::Edge::DepFeature { kind, .. } = edge.weight()
                            {
                                let node = DupNode {
                                    kid: &krate.id,
                                    feature: None,
                                };

                                if let Some(pindex) = node_map.get(&node) {
                                    graph.update_edge(*pindex, target, *kind);
                                } else {
                                    let pindex = graph.add_node(node);

                                    graph.update_edge(pindex, target, *kind);

                                    node_map.insert(node, pindex);
                                    node_stack.push((source, pindex));
                                }
                            }
                        }
                        krates::Node::Feature { krate_index, name } => {
                            let kid = &krates[*krate_index].id;

                            let node = DupNode {
                                kid,
                                feature: Some(name.as_str()),
                            };

                            if let Some(pindex) = node_map.get(&node) {
                                graph.update_edge(*pindex, target, DepKind::Normal);
                            } else {
                                let pindex = graph.add_node(node);

                                graph.update_edge(pindex, target, DepKind::Normal);

                                node_map.insert(node, pindex);
                                node_stack.push((source, pindex));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut node_stack = Vec::new();
    let mut dupe_nodes = BTreeMap::<_, Vec<_>>::new();

    let mut edge_sets = Vec::with_capacity(duplicates.len());

    // Find all of the edges that lead to each duplicate, and also keep track of
    // any additional crate duplicates, to make them stand out more in the dotgraph
    for id in &duplicates {
        let dup_node = node_map[&DupNode {
            kid: id,
            feature: None,
        }];
        let mut set = HashSet::new();

        node_stack.push(dup_node);

        while let Some(nid) = node_stack.pop() {
            let node = &graph[nid];
            let mut iditer = node.kid.repr.splitn(3, ' ');
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
                    node_stack.push(edge.source());
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
    // This just returns the first lowest one, there can be multiple with the
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
            let node_weight = node.weight();

            if let Some(feat) = &node_weight.feature {
                NodeAttributes {
                    label: Some(feat),
                    shape: Some(Shape::diamond),
                    ..Default::default()
                }
            } else {
                let repr = &node_weight.kid.repr;

                let mut i = repr.splitn(3, ' ');
                let name = i.next().unwrap();
                let _version = i.next().unwrap();
                let source = i.next().unwrap();

                if dupe_nodes.contains_key(name) {
                    let label =
                        if source != "(registry+https://github.com/rust-lang/crates.io-index)" {
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
                writeln!(output, "{INDENT}subgraph cluster_{i} {{")?;

                write!(output, "{0}{0}{{rank=same ", INDENT)?;

                for nid in ids {
                    write!(output, "{} ", nid.index())?;
                }

                writeln!(
                    output,
                    "}}\n{0}{0}style=\"rounded{1}\";\n{0}{0}label=\"{2}\"\n{0}}}",
                    INDENT,
                    if name == &dup_name { ",filled" } else { "" },
                    name,
                )?;
            }

            Ok(())
        },
    )
}

fn print_graph<'a: 'b, 'b, NP, EP, SG>(
    graph: &'a pg::Graph<DupNode<'a>, DepKind>,
    node_print: NP,
    edge_print: EP,
    subgraphs: SG,
) -> Result<String, Error>
where
    NP: Fn((Id, &'b DupNode<'a>)) -> NodeAttributes<'b>,
    EP: Fn(&pg::graph::EdgeReference<'_, DepKind, u32>) -> EdgeAttributes<'b>,
    SG: Fn(&mut String) -> Result<(), Error>,
{
    use pg::visit::{EdgeRef, IntoNodeReferences, NodeIndexable, NodeRef};
    use std::fmt::Write;
    let mut output = String::with_capacity(1024);
    writeln!(output, "digraph {{",)?;

    // output all nodes
    for node in graph.node_references() {
        write!(output, "{INDENT}{}", graph.to_index(node.id()))?;

        let attrs = node_print(node);

        if !attrs.has_attrs() {
            writeln!(output)?;
            continue;
        }

        let mut append = false;
        write!(output, " [")?;

        if let Some(label) = attrs.label {
            write!(output, "label=\"{label}\"")?;
            append = true;
        }

        if let Some(shape) = attrs.shape {
            write!(output, "{}shape={shape:?}", if append { ", " } else { "" },)?;
            append = true;
        }

        if let Some(style) = attrs.style {
            write!(output, "{}style={style:?}", if append { ", " } else { "" },)?;
            append = true;
        }

        if let Some(color) = attrs.color {
            write!(output, "{}color={color}", if append { ", " } else { "" })?;
            append = true;
        }

        if let Some(color) = attrs.fill_color {
            write!(
                output,
                "{}fillcolor={color}",
                if append { ", " } else { "" },
            )?;
        }

        writeln!(output, "]")?;
    }

    // output all edges
    for edge in graph.edge_references() {
        write!(
            output,
            "{INDENT}{} -> {}",
            graph.to_index(edge.source()),
            graph.to_index(edge.target()),
        )?;

        let attrs = edge_print(&edge);

        write!(output, " [")?;

        let mut append = false;

        if let Some(label) = attrs.label {
            write!(output, "label=\"{label}\"")?;
            append = true;
        }

        if let Some(color) = attrs.color {
            write!(output, "{}color={color}", if append { ", " } else { "" })?;
            //append = true;
        }

        writeln!(output, "]")?;
    }

    subgraphs(&mut output)?;

    writeln!(output, "}}")?;
    Ok(output)
}
