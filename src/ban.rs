use crate::LintLevel;
use codespan_reporting::diagnostic::Diagnostic;
use failure::Error;
use rayon::prelude::*;
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::{cmp, collections::HashMap, fmt};

#[derive(Deserialize)]
pub struct CrateId {
    // The name of the crate
    pub name: String,
    /// The version constraints of the crate
    #[serde(default = "any")]
    pub version: VersionReq,
}

#[derive(Deserialize)]
pub struct TreeSkip {
    #[serde(flatten)]
    pub id: CrateId,
    pub depth: Option<usize>,
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

#[derive(Deserialize, PartialEq, Eq, Copy, Clone)]
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
    fn simplest(self) -> bool {
        self == Self::SimplestPath || self == Self::All
    }

    #[inline]
    fn lowest_version(self) -> bool {
        self == Self::LowestVersion || self == Self::All
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
    pub deny: Vec<toml::Spanned<CrateId>>,
    /// If specified, means only the listed crates are allowed
    #[serde(default)]
    pub allow: Vec<toml::Spanned<CrateId>>,
    /// If specified, disregards the crate completely
    #[serde(default)]
    pub skip: Vec<toml::Spanned<CrateId>>,
    /// If specified, disregards the crate's transitive dependencies
    /// down to a certain depth
    #[serde(default)]
    pub skip_tree: Vec<toml::Spanned<TreeSkip>>,
}

impl Config {
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
        _contents: &str,
    ) -> Result<ValidConfig, Vec<codespan_reporting::diagnostic::Diagnostic>> {
        use codespan_reporting::diagnostic::Label;

        let from = |s: toml::Spanned<CrateId>| {
            let span = s.start() as u32..s.end() as u32;
            let inner = s.into_inner();
            KrateId {
                name: inner.name,
                version: inner.version,
                span,
            }
        };

        let mut diagnostics = Vec::new();

        let mut denied: Vec<_> = self.deny.into_iter().map(from).collect();
        denied.par_sort();

        let mut allowed: Vec<_> = self.allow.into_iter().map(from).collect();
        allowed.par_sort();

        let mut skipped: Vec<_> = self.skip.into_iter().map(from).collect();
        skipped.par_sort();

        let mut add_diag = |first: (&KrateId, &str), second: (&KrateId, &str)| {
            let flabel = Label::new(
                cfg_file,
                first.0.span.clone(),
                format!("marked as `{}`", first.1),
            );
            let slabel = Label::new(
                cfg_file,
                second.0.span.clone(),
                format!("marked as `{}`", second.1),
            );

            // Put the one that occurs last as the primary label to make it clear
            // that the first one was "ok" until we noticed this other one
            let diag = if flabel.span.start() > slabel.span.start() {
                Diagnostic::new_error(
                    format!(
                        "a license id was specified in both `{}` and `{}`",
                        first.1, second.1
                    ),
                    flabel,
                )
                .with_secondary_labels(std::iter::once(slabel))
            } else {
                Diagnostic::new_error(
                    format!(
                        "a license id was specified in both `{}` and `{}`",
                        second.1, first.1
                    ),
                    slabel,
                )
                .with_secondary_labels(std::iter::once(flabel))
            };

            diagnostics.push(diag);
        };

        for d in &denied {
            if let Ok(ai) = allowed.binary_search(&d) {
                add_diag((d, "deny"), (&allowed[ai], "allow"));
            }
            if let Ok(si) = skipped.binary_search(&d) {
                add_diag((d, "deny"), (&skipped[si], "skip"));
            }
        }

        for a in &allowed {
            if let Ok(si) = skipped.binary_search(&a) {
                add_diag((a, "allow"), (&skipped[si], "skip"));
            }
        }

        if !diagnostics.is_empty() {
            Err(diagnostics)
        } else {
            Ok(ValidConfig {
                file_id: cfg_file,
                multiple_versions: self.multiple_versions,
                highlight: self.highlight,
                denied,
                allowed,
                skipped,
                tree_skipped: self.skip_tree,
            })
        }
    }
}

#[derive(Eq)]
struct KrateId {
    name: String,
    version: VersionReq,
    span: std::ops::Range<u32>,
}

impl Ord for KrateId {
    fn cmp(&self, o: &Self) -> cmp::Ordering {
        match self.name.cmp(&o.name) {
            cmp::Ordering::Equal => self.version.cmp(&o.version),
            o => o,
        }
    }
}

impl PartialOrd for KrateId {
    fn partial_cmp(&self, o: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl PartialEq for KrateId {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == cmp::Ordering::Equal
    }
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,
    pub multiple_versions: LintLevel,
    pub highlight: GraphHighlight,
    denied: Vec<KrateId>,
    allowed: Vec<KrateId>,
    skipped: Vec<KrateId>,
    tree_skipped: Vec<toml::Spanned<TreeSkip>>,
}

fn binary_search<'a>(
    arr: &'a [KrateId],
    details: &crate::KrateDetails,
) -> Result<(usize, &'a KrateId), usize> {
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

            for (j, krate) in arr[begin..].iter().enumerate() {
                if krate.name != details.name {
                    break;
                }

                if krate.version.matches(&details.version) {
                    return Ok((begin + j, krate));
                }
            }

            Err(i)
        }
    }
}

fn binary_search_by_name<'a>(
    arr: &'a [crate::KrateDetails],
    name: &'a str,
) -> Result<std::ops::Range<usize>, usize> {
    let lowest = Version::new(0, 0, 0);

    match arr.binary_search_by(|i| match i.name.as_str().cmp(name) {
        cmp::Ordering::Equal => i.version.cmp(&lowest),
        o => o,
    }) {
        Ok(i) | Err(i) => {
            if arr[i].name != name {
                return Err(i);
            }

            // Backtrack 1 if the crate name matches, as, for instance, wildcards will be sorted
            // before the 0.0.0 version
            let begin = if i > 0 && arr[i - 1].name == name {
                i - 1
            } else {
                i
            };

            let end = arr[begin..].iter().take_while(|kd| kd.name == name).count() + begin;

            Ok(begin..end)
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

fn create_graph(
    dup_name: &str,
    highlight: GraphHighlight,
    krates: &crate::Krates,
    duplicates: &[usize],
) -> Result<String, Error> {
    use petgraph::visit::{EdgeRef, NodeRef};

    let mut graph = Graph::new();
    let mut node_map = HashMap::new();

    for duplicate in duplicates {
        append_dependency_chain(krates, *duplicate, &mut graph, &mut node_map);
    }

    let mut edges = Vec::with_capacity(duplicates.len());
    let mut dupes: HashMap<&str, Vec<_>> = HashMap::new();

    for duplicate in duplicates {
        let dest = Node::from(&krates.krates[*duplicate]);

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

                for node in graph.neighbors_directed(id, petgraph::Direction::Incoming) {
                    set.insert(graph.find_edge(node, id).unwrap());
                    nodes.push(node);
                }
            }

            edges.push(set);
        }
    }

    dupes.retain(|_, v| {
        v.sort();
        v.len() > 1
    });

    // Find the version with the least number of total edges to the least common ancestor,
    // this will presumably be the easiest version to "fix"
    // This just returns the first lowest one, there can be multiple with
    // same number of edges
    let smollest = edges
        .iter()
        .min_by(|a, b| a.len().cmp(&b.len()))
        .ok_or_else(|| failure::format_err!("expected shortest edge path"))?;
    let lowest = &edges[0];

    print_graph(
        &graph,
        |node| {
            let node_weight = node.weight();

            if node_weight.name == dup_name || dupes.contains_key(node_weight.name) {
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
            if highlight.simplest() && smollest.contains(&edge.id()) {
                EdgeAttributes { color: Some("red") }
            } else if highlight.lowest_version() && lowest.contains(&edge.id()) {
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

pub type Pid = cargo_metadata::PackageId;

struct SkipRoot {
    span: std::ops::Range<u32>,
    skip_crates: Vec<Pid>,
    skip_hits: bitvec::vec::BitVec,
}

use bitvec::prelude::*;

fn build_skip_root(
    ts: toml::Spanned<TreeSkip>,
    krate: &crate::KrateDetails,
    krates: &crate::Krates,
) -> SkipRoot {
    let span = ts.start() as u32..ts.end() as u32;
    let ts = ts.into_inner();

    let max_depth = ts.depth.unwrap_or(std::usize::MAX);

    let mut pending = smallvec::SmallVec::<[(Pid, usize); 10]>::new();
    pending.push((krate.id.clone(), 0));

    let mut skip_crates = Vec::with_capacity(10);
    while let Some((pkg_id, depth)) = pending.pop() {
        if depth < max_depth {
            let node = &krates.resolved.nodes[krates
                .resolved
                .nodes
                .binary_search_by(|n| n.id.cmp(&pkg_id))
                .unwrap()];
            for dep in &node.dependencies {
                pending.push((dep.clone(), depth + 1));
            }
        }

        if let Err(i) = skip_crates.binary_search(&pkg_id) {
            skip_crates.insert(i, pkg_id);
        }
    }

    let skip_hits = bitvec![0; skip_crates.len()];

    SkipRoot {
        span,
        skip_crates,
        skip_hits,
    }
}

pub struct DupGraph {
    pub duplicate: String,
    pub graph: String,
}

pub fn check_bans<OG>(
    krates: &crate::Krates,
    cfg: ValidConfig,
    (lock_id, lock_contents): (codespan::FileId, &str),
    output_graph: Option<OG>,
    sender: crossbeam::channel::Sender<crate::DiagPack>,
) -> Result<(), Error>
where
    OG: Fn(DupGraph) -> Result<(), Error>,
{
    use codespan_reporting::diagnostic::{Label, Severity};

    // Get the offset of the beginning of the metadata section
    let metadata_start = lock_contents
        .rfind("[metadata]")
        .ok_or_else(|| failure::format_err!("unable to find metadata section in Cargo.lock"))?
        + 10;

    let mut krate_spans: Vec<Option<std::ops::Range<u32>>> = vec![None; krates.krates.len()];

    let mut cur_offset = metadata_start;

    for (i, krate) in krates.iter().enumerate() {
        // Local crates don't have metadata entries, and it would also be kind of weird to
        // ban your own local crates...
        if krate.source.is_none() {
            continue;
        }

        let krate_start = lock_contents[cur_offset..]
            .find("\"checksum ")
            .ok_or_else(|| {
                failure::format_err!("unable to find metadata entry for krate {}", krate.id)
            })?;

        let id_end = lock_contents[cur_offset + krate_start..]
            .find("\" = \"")
            .ok_or_else(|| failure::format_err!("invalid metadata format"))?;

        let lock_id =
            &lock_contents[cur_offset + krate_start + 10..cur_offset + krate_start + id_end - 1];

        // Git ids can differ, but they have to start the same
        if &krate.id.repr[..lock_id.len()] != lock_id {
            failure::bail!(
                "invalid metadata for package '{}' != '{}'",
                krate.id,
                lock_id
            );
        }

        let krate_end = lock_contents[cur_offset + krate_start..]
            .find('\n')
            .ok_or_else(|| failure::format_err!("unable to find end for krate {}", krate.id))?;

        krate_spans[i] =
            Some((cur_offset + krate_start) as u32..(cur_offset + krate_start + krate_end) as u32);
        cur_offset = cur_offset + krate_start + krate_end;
    }

    struct TreeSkipper {
        roots: Vec<SkipRoot>,
    }

    // If trees are being skipped, walk each one down to the specified depth and add
    // each dependency as a skipped crate at the specific version
    let mut tree_skip = if !cfg.tree_skipped.is_empty() {
        let roots: Vec<_> = cfg
            .tree_skipped
            .into_iter()
            .filter_map(|ts| {
                if let Ok(rng) = binary_search_by_name(&krates.krates, &ts.get_ref().id.name) {
                    for i in rng {
                        if ts.get_ref().id.version.matches(&krates.krates[i].version) {
                            let sr = build_skip_root(ts, &krates.krates[i], krates);
                            return Some(sr);
                        }
                    }
                }

                None
            })
            .collect();

        Some(TreeSkipper { roots })
    } else {
        None
    };

    let file_id = cfg.file_id;

    let mut check_root_filters = |krate: &crate::KrateDetails, diags: &mut Vec<Diagnostic>| {
        if let Some(ref mut tree_skipper) = tree_skip {
            let mut skip = false;

            for root in &mut tree_skipper.roots {
                if let Ok(i) = root.skip_crates.binary_search(&krate.id) {
                    diags.push(Diagnostic::new(
                        Severity::Help,
                        format!("skipping crate {} = {}", krate.name, krate.version),
                        Label::new(file_id, root.span.clone(), "matched root filter"),
                    ));

                    root.skip_hits.as_mut_bitslice().set(i, true);
                    skip = true;
                }
            }

            skip
        } else {
            false
        }
    };

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit = bitvec![0; cfg.skipped.len()];

    struct MultiDetector<'a> {
        name: &'a str,
        dupes: smallvec::SmallVec<[usize; 2]>,
    }

    let mut multi_detector = MultiDetector {
        name: &krates.as_ref()[0].name,
        dupes: smallvec::SmallVec::new(),
    };

    for (i, krate) in krates.iter().enumerate() {
        let mut diagnostics = Vec::new();

        if let Ok((index, skip)) = binary_search(&cfg.skipped, krate) {
            diagnostics.push(Diagnostic::new(
                Severity::Help,
                format!("skipping crate {} = {}", krate.name, krate.version),
                Label::new(cfg.file_id, skip.span.clone(), "matched filter"),
            ));

            // Keep a count of the number of times each skip filter is hit
            // so that we can report unused filters to the user so that they
            // can cleanup their configs as their dependency graph changes over time
            skip_hit.as_mut_bitslice().set(index, true);
        } else if !check_root_filters(krate, &mut diagnostics) {
            if multi_detector.name == krate.name {
                multi_detector.dupes.push(i);
            } else {
                if multi_detector.dupes.len() > 1 && cfg.multiple_versions != LintLevel::Allow {
                    let severity = match cfg.multiple_versions {
                        LintLevel::Warn => Severity::Warning,
                        LintLevel::Deny => Severity::Error,
                        LintLevel::Allow => unreachable!(),
                    };

                    let mut all_start = std::u32::MAX;
                    let mut all_end = 0;

                    let mut dupes = Vec::with_capacity(multi_detector.dupes.len());

                    #[allow(clippy::needless_range_loop)]
                    for dup in multi_detector.dupes.iter().cloned() {
                        if let Some(ref span) = krate_spans[dup] {
                            if span.start < all_start {
                                all_start = span.start
                            }

                            if span.end > all_end {
                                all_end = span.end
                            }

                            let krate = &krates.krates[dup];

                            dupes.push(crate::DiagPack {
                                krate_id: Some(krate.id.clone()),
                                diagnostics: vec![Diagnostic::new(
                                    severity,
                                    format!(
                                        "duplicate #{} ({}) {} = {}",
                                        dupes.len() + 1,
                                        dup,
                                        krate.name,
                                        krate.version
                                    ),
                                    Label::new(lock_id, span.clone(), "lock entry"),
                                )],
                            });
                        }
                    }

                    sender
                        .send(crate::DiagPack {
                            krate_id: None,
                            diagnostics: vec![Diagnostic::new(
                                severity,
                                format!(
                                    "found {} duplicate entries for crate '{}'",
                                    dupes.len(),
                                    multi_detector.name
                                ),
                                Label::new(lock_id, all_start..all_end, "lock entries"),
                            )],
                        })
                        .unwrap();

                    for dup in dupes {
                        sender.send(dup).unwrap();
                    }

                    if let Some(ref og) = output_graph {
                        let graph = create_graph(
                            multi_detector.name,
                            cfg.highlight,
                            krates,
                            &multi_detector.dupes,
                        )?;

                        og(DupGraph {
                            duplicate: multi_detector.name.to_owned(),
                            graph,
                        })?;
                    }
                }

                multi_detector.name = &krate.name;
                multi_detector.dupes.clear();
                multi_detector.dupes.push(i);
            }

            if let Ok((_, ban)) = binary_search(&cfg.denied, krate) {
                diagnostics.push(Diagnostic::new(
                    Severity::Error,
                    format!("detected banned crate {} = {}", krate.name, krate.version),
                    Label::new(cfg.file_id, ban.span.clone(), "matching ban entry"),
                ));
            }

            if !cfg.allowed.is_empty() {
                // Since only allowing specific crates is pretty draconian,
                // also emit which allow filters actually passed each crate
                match binary_search(&cfg.allowed, krate) {
                    Ok((_, allow)) => {
                        diagnostics.push(Diagnostic::new(
                            Severity::Note,
                            format!("allowed {} = {}", krate.name, krate.version),
                            Label::new(cfg.file_id, allow.span.clone(), "matching allow entry"),
                        ));
                    }
                    Err(mut ind) => {
                        if ind >= cfg.allowed.len() {
                            ind = cfg.allowed.len() - 1;
                        }

                        diagnostics.push(Diagnostic::new(
                            Severity::Error,
                            format!(
                                "detected crate not specifically allowed {} = {}",
                                krate.name, krate.version
                            ),
                            Label::new(cfg.file_id, cfg.allowed[ind].span.clone(), "closest match"),
                        ));
                    }
                }
            }
        }

        if !diagnostics.is_empty() {
            sender
                .send(crate::DiagPack {
                    krate_id: Some(krate.id.clone()),
                    diagnostics,
                })
                .unwrap();
        }
    }

    for (hit, skip) in skip_hit.into_iter().zip(cfg.skipped.into_iter()) {
        if !hit {
            sender
                .send(crate::DiagPack {
                    krate_id: None,
                    diagnostics: vec![Diagnostic::new(
                        Severity::Warning,
                        "skipped crate was not encountered",
                        Label::new(cfg.file_id, skip.span, "no crate matched these criteria"),
                    )],
                })
                .unwrap();
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn binary_search_() {
        let versions = [
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
                name: "winapi".to_owned(),
                version: VersionReq::parse("<0.3").unwrap(),
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

        let mut versions: Vec<_> = versions
            .iter()
            .map(|v| super::KrateId {
                name: v.name.clone(),
                version: v.version.clone(),
                span: 0..0,
            })
            .collect();

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

        assert_eq!(
            binary_search(
                &versions,
                &crate::KrateDetails {
                    name: "winapi".to_owned(),
                    version: Version::parse("0.2.8").unwrap(),
                    ..Default::default()
                }
            )
            .map(|(_, s)| &s.version)
            .unwrap(),
            &(VersionReq::parse("<0.3").unwrap())
        );

        assert!(binary_search(
            &versions,
            &crate::KrateDetails {
                name: "winapi".to_owned(),
                version: Version::parse("0.3.8").unwrap(),
                ..Default::default()
            }
        )
        .is_err());
    }

    #[test]
    fn binary_search_by_name_() {
        use crate::KrateDetails;

        macro_rules! kd {
            ($name:expr, $vs:expr) => {
                KrateDetails {
                    name: $name.to_owned(),
                    version: Version::parse($vs).unwrap(),
                    ..Default::default()
                }
            };
        }

        let krates = [
            kd!("adler32", "1.0.4"),
            kd!("aho-corasick", "0.7.6"),
            kd!("alsa-sys", "0.1.2"),
            kd!("andrew", "0.2.1"),
            kd!("android_glue", "0.2.3"),
            kd!("ansi_term", "0.11.0"),
            kd!("anyhow", "1.0.18"),
            kd!("anymap", "0.12.1"),
            kd!("app_dirs2", "2.0.4"),
            kd!("approx", "0.3.2"),
            kd!("arrayref", "0.3.5"),
            kd!("arrayvec", "0.4.12"),
            kd!("arrayvec", "0.5.1"),
            kd!("ash", "0.29.0"),
            kd!("ash-molten", "0.2.0+37"),
            kd!("assert-json-diff", "1.0.1"),
            kd!("async-stream", "0.1.2"),
            kd!("async-stream-impl", "0.1.1"),
            kd!("async-trait", "0.1.17"),
            kd!("atk-sys", "0.6.0"),
            kd!("atty", "0.2.13"),
            kd!("autocfg", "0.1.7"),
            kd!("backoff", "0.1.5"),
            kd!("backtrace", "0.3.40"),
            kd!("backtrace-sys", "0.1.32"),
            kd!("base-x", "0.2.6"),
            kd!("base64", "0.10.1"),
            kd!("bincode", "1.2.0"),
            kd!("bindgen", "0.51.1"),
            kd!("bitflags", "1.2.1"),
            kd!("core-foundation", "0.6.4"),
            kd!("core-foundation-sys", "0.6.2"),
            kd!("core-graphics", "0.17.3"),
            kd!("coreaudio-rs", "0.9.1"),
            kd!("coreaudio-sys", "0.2.3"),
            kd!("crossbeam", "0.7.2"),
            kd!("crossbeam-channel", "0.3.9"),
            kd!("crossbeam-deque", "0.7.1"),
            kd!("crossbeam-epoch", "0.7.2"),
            kd!("crossbeam-queue", "0.1.2"),
            kd!("crossbeam-utils", "0.6.6"),
            kd!("hex", "0.3.2"),
            kd!("hyper", "0.12.35"),
            kd!("hyper", "0.13.0-alpha.4"),
            kd!("hyper-rustls", "0.17.1"),
            kd!("tokio", "0.1.22"),
            kd!("tokio", "0.2.0-alpha.6"),
            kd!("tokio-buf", "0.1.1"),
            kd!("tokio-codec", "0.1.1"),
            kd!("tokio-codec", "0.2.0-alpha.6"),
            kd!("tokio-current-thread", "0.1.6"),
            kd!("tokio-executor", "0.1.8"),
            kd!("tokio-executor", "0.2.0-alpha.6"),
            kd!("tokio-fs", "0.1.6"),
            kd!("tokio-fs", "0.2.0-alpha.6"),
            kd!("tokio-io", "0.1.12"),
            kd!("tokio-io", "0.2.0-alpha.6"),
            kd!("tokio-macros", "0.2.0-alpha.6"),
            kd!("tokio-net", "0.2.0-alpha.6"),
            kd!("tokio-reactor", "0.1.10"),
            kd!("tokio-rustls", "0.10.2"),
            kd!("tokio-sync", "0.1.7"),
            kd!("tokio-sync", "0.2.0-alpha.6"),
            kd!("tokio-tcp", "0.1.3"),
            kd!("tokio-threadpool", "0.1.16"),
            kd!("tokio-timer", "0.2.11"),
            kd!("tokio-timer", "0.3.0-alpha.6"),
            kd!("tokio-udp", "0.1.5"),
            kd!("tokio-uds", "0.2.5"),
            kd!("tonic", "0.1.0-alpha.4"),
            kd!("tonic-build", "0.1.0-alpha.4"),
            kd!("tower", "0.1.1"),
            kd!("tower", "0.3.0-alpha.2"),
            kd!("tower-balance", "0.3.0-alpha.2"),
            kd!("tower-buffer", "0.1.2"),
            kd!("tower-buffer", "0.3.0-alpha.2"),
            kd!("tower-discover", "0.1.0"),
            kd!("tower-discover", "0.3.0-alpha.2"),
            kd!("tower-http-util", "0.1.0"),
            kd!("tower-hyper", "0.1.1"),
            kd!("tower-layer", "0.1.0"),
            kd!("tower-layer", "0.3.0-alpha.2"),
            kd!("tower-limit", "0.1.1"),
            kd!("tower-limit", "0.3.0-alpha.2"),
            kd!("tower-load", "0.3.0-alpha.2"),
            kd!("tower-load-shed", "0.1.0"),
            kd!("tower-load-shed", "0.3.0-alpha.2"),
            kd!("tower-make", "0.3.0-alpha.2a"),
            kd!("tower-reconnect", "0.3.0-alpha.2"),
            kd!("tower-request-modifier", "0.1.0"),
            kd!("tower-retry", "0.1.0"),
            kd!("tower-retry", "0.3.0-alpha.2"),
            kd!("tower-service", "0.2.0"),
            kd!("tower-service", "0.3.0-alpha.2"),
            kd!("tower-timeout", "0.1.1"),
            kd!("tower-timeout", "0.3.0-alpha.2"),
            kd!("tower-util", "0.1.0"),
            kd!("tower-util", "0.3.0-alpha.2"),
            kd!("tracing", "0.1.10"),
            kd!("tracing-attributes", "0.1.5"),
            kd!("tracing-core", "0.1.7"),
        ];

        assert_eq!(binary_search_by_name(&krates, "adler32",), Ok(0..1));
        assert_eq!(
            binary_search_by_name(&krates, "tower-service",)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(binary_search_by_name(&krates, "tracing",).unwrap().len(), 1);
        assert_eq!(
            binary_search_by_name(&krates, "tokio-codec",)
                .unwrap()
                .len(),
            2
        );
    }
}
