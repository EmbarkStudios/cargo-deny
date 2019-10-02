use crate::LintLevel;
use failure::Error;
use rayon::prelude::*;
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::{cmp, collections::HashMap, fmt};

#[derive(Deserialize, Debug, PartialOrd, PartialEq, Ord, Eq)]
pub struct CrateId {
    // The name of the crate
    pub name: String,
    /// The version constraints of the crate
    #[serde(default = "any")]
    pub version: VersionReq,
}

const fn lint_warn() -> LintLevel {
    LintLevel::Warn
}

fn any() -> VersionReq {
    VersionReq::any()
}

const fn highlight() -> GraphHighlight {
    GraphHighlight::All
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GraphHighlight {
    /// Highlights the path to a duplicate dependency with the fewest number
    /// of total edges, which tends to make it the best candidate for removing
    SimplestPath,
    /// Highlights the path to the duplicate dependency with the lowest version
    LowestVersion,
    /// Highlights with all of the other configs
    All,
}

impl GraphHighlight {
    #[inline]
    fn simplest(&self) -> bool {
        *self == GraphHighlight::SimplestPath || *self == GraphHighlight::All
    }

    #[inline]
    fn lowest_version(&self) -> bool {
        *self == GraphHighlight::LowestVersion || *self == GraphHighlight::All
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Disallow multiple versions of the same crate
    #[serde(default = "lint_warn")]
    pub multiple_versions: LintLevel,
    /// How the duplicate graphs are highlighted
    #[serde(default = "highlight")]
    pub highlight: GraphHighlight,
    /// The crates that will cause us to emit failures
    #[serde(default)]
    pub deny: Vec<CrateId>,
    /// If specified, means only the listed crates are allowed
    #[serde(default)]
    pub allow: Vec<CrateId>,
    /// If specified, disregards the crate completely
    #[serde(default)]
    pub skip: Vec<CrateId>,
}

impl Config {
    pub fn validate(
        mut self,
        _cfg_file: codespan::FileId,
        _contents: &str,
    ) -> Result<ValidConfig, Vec<codespan_reporting::diagnostic::Diagnostic>> {
        self.deny.par_sort();
        self.allow.par_sort();
        self.skip.par_sort();

        Ok(ValidConfig {
            multiple_versions: self.multiple_versions,
            highlight: self.highlight,
            deny: self.deny,
            allow: self.allow,
            skip: self.skip,
        })
    }
}

pub struct ValidConfig {
    pub multiple_versions: LintLevel,
    pub highlight: GraphHighlight,
    pub deny: Vec<CrateId>,
    pub allow: Vec<CrateId>,
    pub skip: Vec<CrateId>,
}

fn binary_search<'a>(
    arr: &'a [CrateId],
    details: &crate::KrateDetails,
) -> Result<(usize, &'a CrateId), usize> {
    let lowest = VersionReq::exact(&Version::new(0, 0, 0));

    match arr.binary_search_by(|i| match i.name.cmp(&details.name) {
        cmp::Ordering::Equal => i.version.cmp(&lowest),
        o => o,
    }) {
        Ok(i) => Ok((i, &arr[i])),
        Err(i) => {
            // Backtrack 1 if the crate name matches, as, for instance, wildcards will be sorted
            // before the 0.0.0 version
            let begin = if i > 0 && arr[i - 1].name == details.name {
                i - 1
            } else {
                i
            };

            for (j, crate_) in arr[begin..].iter().enumerate() {
                if crate_.name != details.name {
                    break;
                }

                if crate_.version.matches(&details.version) {
                    return Ok((begin + j, crate_));
                }
            }

            Err(i)
        }
    }
}

use petgraph::Graph;

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

fn append_dependency_chain<'a>(
    crates: &'a crate::Krates,
    start: usize,
    graph: &mut Graph<Node<'a>, &'a str>,
    node_map: &mut HashMap<Node<'a>, Id>,
) {
    let cd = &crates.krates[start];

    let root_node = Node::from(cd);
    let root_id = graph.add_node(root_node);

    node_map.insert(root_node, root_id);

    let mut node_stack = vec![(root_node, root_id)];

    while let Some(node) = node_stack.pop() {
        let parents: Vec<_> = crates
            .as_ref()
            .par_iter()
            .filter_map(|cd| {
                crates
                    .resolved
                    .nodes
                    .binary_search_by(|rp| rp.id.cmp(&cd.id))
                    .ok()
                    .and_then(|i| {
                        crates.resolved.nodes[i]
                            .dependencies
                            .binary_search_by(|did| {
                                let mut iter = did.repr.splitn(3, char::is_whitespace);
                                match iter.next() {
                                    Some(n) => match n.cmp(&node.0.name) {
                                        cmp::Ordering::Equal => iter
                                            .next()
                                            .and_then(|version| {
                                                version
                                                    .parse::<Version>()
                                                    .ok()
                                                    .map(|v| v.cmp(node.0.version))
                                            })
                                            .unwrap_or(cmp::Ordering::Less),
                                        o => o,
                                    },
                                    None => cmp::Ordering::Less,
                                }
                            })
                            .ok()
                            .and_then(|_| crates.crate_by_id(&crates.resolved.nodes[i].id))
                    })
            })
            .collect();

        for parent in parents.into_iter().map(Node::from) {
            match node_map.get(&parent) {
                Some(id) => {
                    if !graph.contains_edge(*id, node.1) {
                        graph.add_edge(*id, node.1, "");
                    }
                }
                None => {
                    let id = graph.add_node(parent);

                    node_map.insert(parent, id);
                    graph.add_edge(id, node.1, "");

                    node_stack.push((parent, id));
                }
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Shape {
    r#box,
    polygon,
    ellipse,
    oval,
    circle,
    point,
    egg,
    triangle,
    plaintext,
    plain,
    diamond,
    trapezium,
    parallelogram,
    house,
    pentagon,
    hexagon,
    septagon,
    octagon,
    doublecircle,
    doubleoctagon,
    tripleoctagon,
    invtriangle,
    invtrapezium,
    invhouse,
    Mdiamond,
    Msquare,
    Mcircle,
    rect,
    rectangle,
    square,
    star,
    none,
    underline,
    cylinder,
    note,
    tab,
    folder,
    box3d,
    component,
    promoter,
    cds,
    terminator,
    utr,
    primersite,
    restrictionsite,
    fivepoverhang,
    threepoverhang,
    noverhang,
    assembly,
    signature,
    insulator,
    ribosite,
    rnastab,
    proteasesite,
    proteinstab,
    rpromoter,
    rarrow,
    larrow,
    lpromoter,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Style {
    filled,
    invisible,
    diagonals,
    rounded,
    dashed,
    dotted,
    solid,
    bold,
}

struct NodeAttributes<'a> {
    label: Option<&'a dyn fmt::Display>,
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
struct EdgeAttributes {
    color: Option<&'static str>,
}

const INDENT: &str = "    ";

fn print_graph<'a: 'b, 'b, NP, EP, SG>(
    graph: &'a Graph<Node<'a>, &'a str>,
    node_print: NP,
    edge_print: EP,
    subgraphs: SG,
) -> Result<String, Error>
where
    NP: Fn((Id, &'b Node<'a>)) -> NodeAttributes<'b>,
    EP: Fn(&petgraph::graph::EdgeReference<'_, &'a str, u32>) -> EdgeAttributes,
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

        if let Some(color) = attrs.color {
            writeln!(output, " [color={}]", color)?;
        } else {
            writeln!(output)?;
        }
    }

    subgraphs(&mut output)?;

    writeln!(output, "}}")?;
    Ok(output)
}

pub struct DupGraph {
    pub duplicate: String,
    pub graph: String,
}

pub fn check_bans<OG>(
    krates: &crate::Krates,
    cfg: ValidConfig,
    output_graph: Option<OG>,
) -> Result<(), Error>
where
    OG: Fn(DupGraph) -> Result<(), Error>,
{
    use petgraph::visit::{EdgeRef, NodeRef};
    use slog::{debug, error, warn};
    let mut multi_detector = (&crates.as_ref()[0].name, 0, 0);
    let mut errors = 0;
    let mut warnings = 0;

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit = vec![0; cfg.skip.len()];

    for (i, crate_) in crates.iter().enumerate() {
        if let Ok((index, skip)) = binary_search(&cfg.skip, crate_) {
            debug!(log, "skipping crate"; "crate" => format!("{}@{}", crate_.name, crate_.version), "version_req" => format!("{}", skip.version));
            skip_hit[index] += 1;
            continue;
        }

        if multi_detector.0 == &crate_.name {
            multi_detector.1 += 1;
        } else {
            if multi_detector.1 > 1 && cfg.multiple_versions != LintLevel::Allow {
                match cfg.multiple_versions {
                    LintLevel::Warn => {
                        warn!(log, "detected multiple versions of crate"; "crate" => multi_detector.0, "count" => multi_detector.1);
                        warnings += 1;
                    }
                    LintLevel::Deny => {
                        error!(log, "detected multiple versions of crate"; "crate" => multi_detector.0, "count" => multi_detector.1);
                        errors += 1;
                    }
                    LintLevel::Allow => unreachable!(),
                }

                if let Some(ref og) = output_graph {
                    let mut graph = Graph::new();
                    let mut node_map = HashMap::new();

                    for duplicate in multi_detector.2..i {
                        append_dependency_chain(crates, duplicate, &mut graph, &mut node_map);
                    }

                    let mut edges = Vec::with_capacity(i - multi_detector.2);
                    let mut dupes: HashMap<&str, Vec<_>> = HashMap::new();

                    for duplicate in multi_detector.2..i {
                        let dest = Node::from(&crates.krates[duplicate]);

                        if let Some(id) = node_map.get(&dest) {
                            let mut nodes = vec![*id];
                            let mut set = std::collections::HashSet::new();
                            while let Some(id) = nodes.pop() {
                                let node = graph.node_weight(id).unwrap();
                                dupes
                                    .entry(node.name)
                                    .and_modify(|v| {
                                        if !v.contains(&node.version) {
                                            v.push(node.version);
                                        }
                                    })
                                    .or_insert_with(|| vec![node.version]);

                                for node in
                                    graph.neighbors_directed(id, petgraph::Direction::Incoming)
                                {
                                    set.insert(graph.find_edge(node, id).unwrap());
                                    nodes.push(node);
                                }
                            }

                            edges.push(set);
                        } else {
                            failure::bail!("failed to find root node for duplicate crate");
                        }
                    }

                    dupes.retain(|_, v| {
                        v.sort();
                        v.len() > 1
                    });

                    // Find the least common ancestor between all of our duplicates, the nodes that have an incoming edge
                    // from that least common ancestor are the root cause packages, mark them as such
                    // for duplicate in multi_detector.2..i {
                    //     let dest = Node::from(&crates.crates[duplicate]);
                    // }

                    // Find the version with the least number of total edges to the least common ancestor,
                    // this will presumably be the easiest version to "fix"
                    // This just returns the first lowest one, there can be multiple with
                    // same number of edges
                    let smollest = edges
                        .iter()
                        .min_by(|a, b| a.len().cmp(&b.len()))
                        .ok_or_else(|| failure::format_err!("expected shortest edge path"))?;
                    let lowest = &edges[0];

                    let graph = print_graph(
                        &graph,
                        |node| {
                            let node_weight = node.weight();

                            if node_weight.name == multi_detector.0
                                || dupes.contains_key(node_weight.name)
                            {
                                NodeAttributes {
                                    label: Some(node_weight.version),
                                    shape: Some(Shape::r#box),
                                    color: Some("red"),
                                    style: Some(Style::rounded),
                                    ..Default::default()
                                }
                            } else {
                                NodeAttributes {
                                    label: Some(node.1),
                                    shape: Some(Shape::r#box),
                                    style: Some(Style::rounded),
                                    ..Default::default()
                                }
                            }
                        },
                        |edge| {
                            if cfg.highlight.simplest() && smollest.contains(&edge.id()) {
                                EdgeAttributes { color: Some("red") }
                            } else if cfg.highlight.lowest_version() && lowest.contains(&edge.id())
                            {
                                EdgeAttributes {
                                    color: Some("blue"),
                                }
                            } else {
                                EdgeAttributes { color: None }
                            }
                        },
                        |output| {
                            use std::fmt::Write;

                            for (i, (name, versions)) in dupes.iter().enumerate() {
                                writeln!(output, "{}subgraph cluster_{} {{", INDENT, i)?;

                                write!(output, "{}{}{{rank=same ", INDENT, INDENT)?;

                                for version in versions {
                                    if let Some(id) = node_map.get(&Node { name, version }) {
                                        write!(output, "{} ", id.index())?;
                                    }
                                }

                                writeln!(
                                    output,
                                    "}}\n{}{}style=\"rounded{}\";\n{}{}label=\"{}\"\n{}}}",
                                    INDENT,
                                    INDENT,
                                    if name == multi_detector.0 {
                                        ",filled"
                                    } else {
                                        ""
                                    },
                                    INDENT,
                                    INDENT,
                                    name,
                                    INDENT
                                )?;
                            }

                            Ok(())
                        },
                    )?;

                    og(DupGraph {
                        duplicate: multi_detector.0.to_owned(),
                        graph,
                    })?;
                }
            }

            multi_detector.0 = &crate_.name;
            multi_detector.1 = 1;
            multi_detector.2 = i;
        }

        if let Ok((_, ban)) = binary_search(&cfg.deny, crate_) {
            error!(log, "detected a banned crate"; "crate" => format!("{}@{}", crate_.name, crate_.version), "ban" => format!("{} = {}", ban.name, ban.version));
            errors += 1;
        } else if !cfg.allow.is_empty() && binary_search(&cfg.allow, crate_).is_ok() {
            error!(log, "detected a crate not explicitly allowed"; "crate" => format!("{}@{}", crate_.name, crate_.version));
            errors += 1;
        }
    }

    for (count, skip) in skip_hit.into_iter().zip(cfg.skip.iter()) {
        if count == 0 {
            warn!(log, "skipped crate not encountered"; "crate" => skip.name.to_owned(), "version_req" => skip.version.to_string());
            warnings += 1;
        }
    }

    if warnings > 0 {
        warn!(log, "encountered {} ban warnings", warnings);
    }

    if errors > 0 {
        error!(log, "encountered {} ban errors", errors);
        failure::bail!("failed ban check");
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn binary_search_() {
        let mut versions = vec![
            CrateId {
                name: "unicase".to_owned(),
                version: VersionReq::parse("=1.4.2").unwrap(),
            },
            CrateId {
                name: "crossbeam-deque".to_owned(),
                version: VersionReq::parse("=0.6.3").unwrap(),
            },
            CrateId {
                name: "parking_lot".to_owned(),
                version: VersionReq::parse("=0.7.1").unwrap(),
            },
            CrateId {
                name: "parking_lot_core".to_owned(),
                version: VersionReq::parse("=0.4.0").unwrap(),
            },
            CrateId {
                name: "lock_api".to_owned(),
                version: VersionReq::parse("=0.1.5").unwrap(),
            },
            CrateId {
                name: "rand".to_owned(),
                version: VersionReq::parse("=0.6.5").unwrap(),
            },
            CrateId {
                name: "rand_chacha".to_owned(),
                version: VersionReq::parse("=0.1.1").unwrap(),
            },
            CrateId {
                name: "rand_core".to_owned(),
                version: VersionReq::parse("=0.4.0").unwrap(),
            },
            CrateId {
                name: "rand_core".to_owned(),
                version: VersionReq::parse("=0.3.1").unwrap(),
            },
            CrateId {
                name: "rand_hc".to_owned(),
                version: VersionReq::parse("=0.1.0").unwrap(),
            },
            CrateId {
                name: "rand_pcg".to_owned(),
                version: VersionReq::parse("=0.1.2").unwrap(),
            },
            CrateId {
                name: "serde".to_owned(),
                version: VersionReq::any(),
            },
            CrateId {
                name: "scopeguard".to_owned(),
                version: VersionReq::parse("=0.3.3").unwrap(),
            },
            CrateId {
                name: "winapi".to_owned(),
                version: VersionReq::parse("=0.2.8").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("=0.1.43").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("<0.1").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("<0.2").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("0.1.*").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse("<0.1.42").unwrap(),
            },
            CrateId {
                name: "num-traits".to_owned(),
                version: VersionReq::parse(">0.1.43").unwrap(),
            },
        ];

        versions.sort();

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "rand_core".to_owned(),
                    version: Version::parse("0.3.1").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("=0.3.1").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "serde".to_owned(),
                    version: Version::parse("1.0.94").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::any())
        );

        assert!(binary_search(
            &versions,
            &crate::KrateDetails {
                name: "nope".to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                ..Default::default()
            }
        )
        .is_err());

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.1.43").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("=0.1.43").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.1.2").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("<0.1.42").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.2.0").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse(">0.1.43").unwrap())
        );

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "num-traits".to_owned(),
                    version: Version::parse("0.0.99").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("<0.1").unwrap())
        );
    }
}
