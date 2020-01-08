use super::cfg::GraphHighlight;
use anyhow::{Context, Error};
use petgraph::Graph;
use semver::Version;
use std::{cmp::Ordering, collections::HashMap, fmt};

#[derive(Hash, Copy, Clone, PartialEq, Eq)]
struct Node<'a> {
    name: &'a str,
    version: &'a Version,
}

impl<'a, 'b: 'a> From<&'b crate::KrateDetails> for Node<'a> {
    fn from(d: &'b crate::KrateDetails) -> Self {
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

type Id = petgraph::graph::NodeIndex<u32>;

// fn append_dependency_chain<'a>(
//     crates: &'a crate::Krates,
//     start: usize,
//     graph: &mut Graph<Node<'a>, &'a str>,
//     node_map: &mut HashMap<Node<'a>, Id>,
// ) {
//     use rayon::prelude::*;

//     let cd = &crates.krates[start];

//     let root_node = Node::from(cd);
//     let root_id = graph.add_node(root_node);

//     node_map.insert(root_node, root_id);

//     let mut node_stack = vec![(root_node, root_id)];

//     while let Some(node) = node_stack.pop() {
//         let parents: Vec<_> = crates
//             .as_ref()
//             .par_iter()
//             .filter_map(|cd| {
//                 crates
//                     .resolved
//                     .nodes
//                     .binary_search_by(|rp| rp.id.cmp(&cd.id))
//                     .ok()
//                     .and_then(|i| {
//                         crates.resolved.nodes[i]
//                             .dependencies
//                             .binary_search_by(|did| {
//                                 let mut iter = did.repr.splitn(3, char::is_whitespace);
//                                 match iter.next() {
//                                     Some(n) => match n.cmp(&node.0.name) {
//                                         Ordering::Equal => iter
//                                             .next()
//                                             .and_then(|version| {
//                                                 version
//                                                     .parse::<Version>()
//                                                     .ok()
//                                                     .map(|v| v.cmp(node.0.version))
//                                             })
//                                             .unwrap_or(Ordering::Less),
//                                         o => o,
//                                     },
//                                     None => Ordering::Less,
//                                 }
//                             })
//                             .ok()
//                             .and_then(|_| crates.crate_by_id(&crates.resolved.nodes[i].id))
//                     })
//             })
//             .collect();

//         for parent in parents.into_iter().map(Node::from) {
//             match node_map.get(&parent) {
//                 Some(id) => {
//                     if !graph.contains_edge(*id, node.1) {
//                         graph.add_edge(*id, node.1, "");
//                     }
//                 }
//                 None => {
//                     let id = graph.add_node(parent);

//                     node_map.insert(parent, id);
//                     graph.add_edge(id, node.1, "");

//                     node_stack.push((parent, id));
//                 }
//             }
//         }
//     }
// }

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
    use petgraph::visit::{EdgeRef, NodeRef};

    let mut graph = Graph::new();
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
        for incoming in krates
            .graph
            .edges_directed(krates[pid], petgraph::Direction::Incoming)
        {
            let parent = &krates[incoming.source()];
            match node_map.get(&parent.id) {
                Some(pindex) => {
                    graph.update_edge(*pindex, target, *incoming.weight());
                }
                None => {
                    let pindex = graph.add_node(&parent.id);

                    graph.update_edge(pindex, target, *incoming.weight());

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
        let mut set = std::collections::HashSet::new();

        node_stack.push(dup_node);

        while let Some(nid) = node_stack.pop() {
            let node = &graph[nid];
            let mut iditer = node.repr.splitn(3, ' ');
            let name = iditer.next().unwrap();

            match dupe_nodes.get_mut(name) {
                Some(v) => {
                    if !v.contains(&nid) {
                        v.push(nid);
                    }
                }
                None => {
                    dupe_nodes.insert(name, vec![nid]);
                }
            }

            for edge in graph.edges_directed(nid, petgraph::Direction::Incoming) {
                set.insert(edge.id());

                node_stack.push(edge.source());
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
            let label = match *edge.weight() {
                crate::DepKind::Normal => None,
                crate::DepKind::Dev => Some("dev"),
                crate::DepKind::Build => Some("build"),
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
    graph: &'a Graph<&'a crate::Pid, crate::DepKind>,
    node_print: NP,
    edge_print: EP,
    subgraphs: SG,
) -> Result<String, Error>
where
    NP: Fn((Id, &'b &'a crate::Pid)) -> NodeAttributes<'b>,
    EP: Fn(&petgraph::graph::EdgeReference<'_, crate::DepKind, u32>) -> EdgeAttributes<'b>,
    SG: Fn(&mut String) -> Result<(), Error>,
{
    use petgraph::visit::{EdgeRef, IntoNodeReferences, NodeIndexable, NodeRef};
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
            append = true;
        }

        writeln!(output, "]")?;
    }

    subgraphs(&mut output)?;

    writeln!(output, "}}")?;
    Ok(output)
}
