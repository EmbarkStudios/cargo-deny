use crate::{prune, KrateDetails, Pid, DepKind};
use anyhow::{Context, Error};
use petgraph::{
    graph::{EdgeIndex, NodeIndex},
    Direction,
};
use rayon::prelude::*;
use std::collections::HashMap;

pub type NodeId = NodeIndex<u32>;
type EdgeId = EdgeIndex<u32>;
pub type Node = KrateDetails;
pub type Edge = DepKind;

// pub(crate) struct Edge {
//     /// The kind of dependency
//     pub(crate) kind: cargo_metadata::DependencyKind,
//     /// The raw cfg() OR target-triple applied to this particular
//     /// dependency
//     cfg: Option<String>,
// }

pub type Graph = petgraph::Graph<Node, Edge>;

pub struct Krates2 {
    pub(crate) graph: Graph,
    node_map: HashMap<Pid, NodeId>,
    workspace_members: Vec<Pid>,
    pub lock_file: std::path::PathBuf,
}

impl Krates2 {
    #[inline]
    pub fn krates_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn krates(&self) -> impl Iterator<Item = &KrateDetails> {
        self.graph.node_indices().map(move |nid| &self.graph[nid])
    }

    pub fn get_node(&self, id: &Pid) -> (&Node, NodeId) {
        let id = self.node_map[id];

        (&self.graph[id], id)
    }

    pub fn get_deps(&self, id: &Pid) -> impl Iterator<Item = (&Node, Edge)> {
        use petgraph::visit::EdgeRef;

        self.graph.edges_directed(self.node_map[id], Direction::Outgoing)
            .map(move |edge| {
                let krate = &self.graph[edge.target()];
                (krate, *edge.weight())
            })
    }

    pub fn workspace_members(&self) -> impl Iterator<Item = &KrateDetails> {
        self.workspace_members.iter().map(move |pid| &self.graph[self.node_map[pid]])
    }

    pub(crate) fn search_match(
        &self,
        name: &str,
        req: &semver::VersionReq,
    ) -> Option<(&Node, NodeId)> {
        self.graph
            .raw_nodes()
            .iter()
            .enumerate()
            .find(|(_i, node)| node.weight.name == name && req.matches(&node.weight.version))
            .map(|(i, node)| (&node.weight, NodeId::new(i)))
    }

    pub(crate) fn get_krate_by_name(&self, name: &str) -> impl Iterator<Item = (usize, &Node)> {
        let lowest = semver::Version::new(0, 0, 0);

        let raw_nodes = self.graph.raw_nodes();

        let rng = match raw_nodes.binary_search_by(|node| match node.weight.name.as_str().cmp(&name) {
            std::cmp::Ordering::Equal => node.weight.version.cmp(&lowest),
            o => o,
        }) {
            Ok(i) | Err(i) => {
                if i >= raw_nodes.len() || raw_nodes[i].weight.name != name {
                    0..0
                } else {
                    // Backtrack 1 if the crate name matches, as, for instance, wildcards will be sorted
                    // before the 0.0.0 version
                    let begin = if i > 0 && raw_nodes[i - 1].weight.name == name {
                        i - 1
                    } else {
                        i
                    };

                    let end = raw_nodes[begin..]
                        .iter()
                        .take_while(|kd| kd.weight.name == name)
                        .count()
                        + begin;

                    begin..end
                }
            }
        };

        let begin = rng.start;
        raw_nodes[rng].iter().enumerate().map(move |(i, n)| (begin + i, &n.weight))
    }
}

impl<'a> std::ops::Index<&'a Pid> for Krates2 {
    type Output = NodeId;
    #[inline]
    fn index(&self, id: &'a Pid) -> &Self::Output {
        &self.node_map[id]
    }
}

impl std::ops::Index<NodeId> for Krates2 {
    type Output = Node;
    #[inline]
    fn index(&self, id: NodeId) -> &Self::Output {
        &self.graph[id]
    }
}

impl std::ops::Index<usize> for Krates2 {
    type Output = Node;
    #[inline]
    fn index(&self, idx: usize) -> &Self::Output {
        &self.graph.raw_nodes()[idx].weight
    }
}

enum TargetFilter {
    /// Ignores dependencies whose target configuration does not match
    /// the specified target. Multiple targets can be supplied, in
    /// which case the dependency will be filtered only if none of them
    /// match.
    ///
    /// If AnyTarget is also used, this inverts, and now any target 
    /// that matches is ignored.
    // Target {
    //     triple: String,
    //     features: Vec<String>,
    // },
    Known(&'static cfg_expr::targets::TargetInfo, Vec<String>),
    Unknown(String, Vec<String>),
    // Target
    // enum TargetFilter {
    //     /// For unknown target triplets, we only filter by the name
    //     Unknown(String),
    //     TargetInfo(, Vec<String>),
    // }
}

pub enum Unless {
    IsWorkspace,
    IsNotWorkspace,
}

impl Into<bool> for Unless {
    fn into(self) -> bool {
        match self {
            Unless::IsWorkspace => true,
            Unless::IsNotWorkspace => false,
        }
    }
}

pub struct GraphBuilder {
    target_filters: Vec<TargetFilter>,
    include_all_targets: bool,
    ignore_kinds: u32,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self {
            target_filters: Vec::new(),
            include_all_targets: true,
            ignore_kinds: 0x0,
        }
    }

    pub fn ignore_kind(&mut self, kind: DepKind, unless: Unless) -> &mut Self {
        let kind_flag = match kind {
            DepKind::Normal => {
                0x1
            }
            DepKind::Dev => 0x4,
            DepKind::Build => 0x10,
        };

        self.ignore_kinds &= kind_flag;
        
        if unless.into() {
            self.ignore_kinds &= kind_flag << 1;
        }

        self
    }

    pub fn include_target(&mut self, triple: String, features: Vec<String>) -> &mut Self {
        self.include_all_targets = false;

        use prune::ALL_TARGETS as all;

        let tf = match all.binary_search_by(|ti| ti.triple.cmp(&triple)) {
            Ok(i) => TargetFilter::Known(&all[i], features),
            Err(_) => TargetFilter::Unknown(triple, features),
        };

        self.target_filters.push(tf);
        self
    }

    pub fn build(self, mut cmd: cargo_metadata::MetadataCommand) -> Result<Krates2, Error> {
        let metadata = cmd.exec()?;
        self.build_with_metadata(metadata)
    }

    pub fn build_with_metadata(self, md: cargo_metadata::Metadata) -> Result<Krates2, Error> {
        let include_all_targets = self.include_all_targets;
        let ignore_kinds = self.ignore_kinds;
        let targets = self.target_filters;

        let mut resolved = md.resolve.context("resolve graph missing")?;
        resolved.nodes.par_sort_by(|a, b| a.id.cmp(&b.id));

        let mut packages = md.packages;
        packages.par_sort_by(|a, b| a.id.cmp(&b.id));

        let mut workspace_members = md.workspace_members;
        workspace_members.sort();

        let mut edge_map = HashMap::new();
        let mut pid_stack = Vec::with_capacity(workspace_members.len());
        pid_stack.extend(workspace_members.iter().cloned());

        while let Some(pid) = pid_stack.pop() {
            let is_in_workspace = workspace_members.binary_search(&pid).is_ok();

            let krate_index = resolved.nodes.binary_search_by(|n| n.id.cmp(&pid)).unwrap();

            let rnode = &resolved.nodes[krate_index];
            let krate = &packages[krate_index];

            let edges: Vec<_> = krate.dependencies.iter().filter_map(|dep| {
                let kind = DepKind::from(dep.kind);

                let ignore_kind = match kind {
                    DepKind::Normal => {
                        ignore_kinds & 0x1 != 0 && ignore_kinds & 0x2 != 0 && is_in_workspace
                    }
                    DepKind::Dev => {
                        ignore_kinds & 0x4 != 0 && ignore_kinds & 0x8 != 0 && is_in_workspace
                    }
                    DepKind::Build => {
                        ignore_kinds & 0x10 != 0 && ignore_kinds & 0x20 != 0 && is_in_workspace
                    }
                };

                if ignore_kind {
                    log::debug!("ignoring dependency {}({}) from {}", dep.name, kind, krate.id);
                    return None;
                }

                // if krate.name.contains("cpal") {
                //     panic!("WHAT HAVE WE HERE!?!? {:#?} {:#?}", krate, rnode);
                // }

                // TODO: Once 1.41 comes out, this won't be necessary as the dependency
                // info will be filled out in the node already, but until then we fill it
                // out ourselves
                rnode.deps.iter().find(|d| {
                    // We have to get the name from the package id, the name for the node
                    // itself can in fact differ, for example, the crate can be named
                    // coreaudio-rs, but the name for the dependency will be coreaudio, because
                    // that is the name of the lib that is created, not the name of the crate
                    let name = &d.pkg.repr[..d.pkg.repr.find(' ').unwrap()];
                    name == dep.name
                })
                    .and_then(|rdep| {
                        match &dep.target {
                            None => return Some((kind, rdep.pkg.clone())),
                            Some(cfg) => {
                                if include_all_targets {
                                    return Some((kind, rdep.pkg.clone()));
                                }

                                // cargo_metdata::Platform only implements Display :(
                                let target_cfg = format!("{}", cfg);
                                let matched = if target_cfg.starts_with("cfg(") {
                                    match cfg_expr::Expression::parse(&target_cfg) {
                                        Ok(expr) => {
                                            // We only need to focus on target predicates because they are
                                            // the only kind allowed by cargo, at least for now
                                            let matched = expr.eval(|pred| match pred {
                                                cfg_expr::expr::Predicate::Target(tp) => {
                                                    for t in targets.iter().filter_map(|tf| {
                                                        match tf {
                                                            TargetFilter::Known(ti, _) => Some(ti),
                                                            _ => None,
                                                        }
                                                     }) {
                                                        if tp.matches(t) {
                                                            return true;
                                                        }
                                                    }

                                                    false
                                                }
                                                cfg_expr::expr::Predicate::TargetFeature(feat) => {
                                                    for f in targets.iter().filter_map(|tf| {
                                                        match tf {
                                                            TargetFilter::Known(_, f) => Some(f),
                                                            TargetFilter::Unknown(_, f) => Some(f),
                                                            _ => None,
                                                        }
                                                     }) {
                                                        if f.iter().find(|f| f == feat).is_some() {
                                                            return true;
                                                        }
                                                    }
        
                                                    // If we don't actually find the feature, print out a debug
                                                    // message that we encountered a target_feature due to their
                                                    // relative rarity and "specialness" to hopefully reduce confusion
                                                    // about why the dependency *might* be pruned (if no other predicate
                                                    // matches)
                                                    log::debug!(
                                                        "encountered target_feature = '{}' for dependency '{}' -> '{}'",
                                                        feat,
                                                        krate.id,
                                                        rdep.pkg,
                                                    );
                                                    false
                                                }
                                                _ => false,
                                            });

                                            matched
                                        }
                                        Err(pe) => {
                                            log::warn!(
                                                "failed to parse '{}' for '{}' -> '{}': {}",
                                                target_cfg,
                                                krate.id,
                                                rdep.pkg,
                                                pe
                                            );
        
                                            true
                                        }
                                    }
                                } else {
                                    let mut matched = false;
                                    for triple in targets.iter().map(|tf| {
                                        match tf {
                                            TargetFilter::Unknown(t, _) => t,
                                            TargetFilter::Known(ti, _) => ti.triple,
                                        }
                                    }) {
                                        if triple == target_cfg {
                                            matched = true;
                                            break;
                                        }
                                    }

                                    matched
                                };

                                if matched {
                                    Some((kind, rdep.pkg.clone()))
                                } else {
                                    log::debug!(
                                        "ignoring dependency {} from {}, no match for {}",
                                        rdep.pkg,
                                        krate.id,
                                        target_cfg,
                                    );

                                    None
                                }
                            }
                        }})
                    }).collect();

            for pid in edges.iter().map(|(_, pid)| pid) {
                if !edge_map.contains_key(pid) {
                    pid_stack.push(pid.clone());
                }
            }

            edge_map.insert(pid, edges);
        }

        let mut node_map = HashMap::new();

        let mut graph = Graph::new();
        graph.reserve_nodes(packages.len());

        let mut edge_count = 0;

        // Preserve the ordering of the krates when inserting them into the graph
        for krate in packages {
            if let Some(edges) = edge_map.get(&krate.id) {
                let id = krate.id.clone();
                let krate = KrateDetails::new(krate);
                node_map.insert(id, graph.add_node(krate));

                edge_count += edges.len();
            }
        }

        graph.reserve_edges(edge_count);

        for (kid, edges) in edge_map {
            let source = node_map[&kid];

            for (kind, pid) in edges {
                let target = node_map[&pid];

                graph.add_edge(source, target, kind);
            }
        }

        Ok(Krates2 {
            graph,
            workspace_members,
            node_map,
            lock_file: md.workspace_root.join("Cargo.lock"),
        })
    }
}

// impl Krates2 {
//     pub fn new(md: cargo_metadata::Metadata) -> Result<Self, Error> {
//         let mut graph = Graph::new();
//         graph.reserve_nodes(md.packages.len());

//         let mut node_map = HashMap::new();

//         let mut resolved = md.resolve.context("resolve graph missing")?;

//         let mut workspace_members = md.workspace_members;
//         workspace_members.sort();

//         // Just in case they aren't already sorted
//         resolved.nodes.par_sort_by(|a, b| a.id.cmp(&b.id));
//         md.packages.par_sort_by(|a, b| a.id.cmp(&b.id));

//         // Maps a unique edge from a -> b to its custom config, if applicable
//         let mut edge_infos = HashMap::new();

//         for (ki, krate) in md.packages.into_iter().map(KrateDetails::new).enumerate() {
//             let id = krate.id.clone();
//             let is_in_workspace = workspace_members.binary_search(&id).is_ok();

//             let rnode = &resolved.nodes[resolved
//                 .nodes
//                 .binary_search_by(|n| n.id.cmp(&krate.id))
//                 .unwrap()];

//             for dep in krate.deps.iter().filter(|d| {
//                 is_in_workspace || d.kind != cargo_metadata::DependencyKind::Development
//             }) {
//                 let name = dep.rename.as_ref().unwrap_or(&dep.name);
//                 if let Some((di, rdep)) =
//                     rnode.deps.iter().enumerate().find(|(_, d)| d.name == *name)
//                 {
//                     // TODO: Once 1.41 comes out, this won't be necessary as the dependency
//                     // info will be filled out in the node already, but until then we fill it
//                     // out ourselves
//                     edge_infos.insert(
//                         (ki, di),
//                         Edge {
//                             kind: dep.kind,
//                             cfg: dep.target.map(|t| format!("{}", t)),
//                         },
//                     );
//                 }
//             }

//             let index = graph.add_node(krate);

//             node_map.insert(id, index);
//         }

//         for (ki, rnode) in resolved.nodes.into_iter().enumerate() {
//             let nid = node_map[&rnode.id];
//             for (di, dep) in rnode.deps.into_iter().enumerate() {
//                 let did = node_map[&dep.pkg];

//                 let edge = edge_infos.remove(&(ki, di)).unwrap();

//                 // TODO: Use dep_kinds once 1.41 comes out
//                 graph.update_edge(nid, did, edge);
//             }
//         }

//         Ok(Self {
//             graph,
//             node_map,
//             workspace_members,
//             //lock_file: md.workspace_root.join("Cargo.lock"),
//         })
//     }

//     pub fn prune(&mut self, which: Option<prune::Prune<'_>>) -> Result<usize, Error> {
//         let which = match which {
//             Some(which) => which,
//             None => return Ok(0),
//         };

//         self.graph
//             .retain_edges(|graph, eid| Self::retain_edge(&which, graph, eid));

//         let mut nuked = 0;
//         let mut remove_stack = Vec::new();

//         // Now continuously prune nodes that no longer have any incoming edges
//         // until our graph stabilizes
//         loop {
//             for nid in self.graph.externals(Direction::Incoming).filter(|nid| {
//                 // Ignore crates in the workspace, as each one is essentially
//                 // a root itself
//                 self.workspace_members
//                     .binary_search(&self.graph[*nid].id)
//                     .is_err()
//             }) {
//                 remove_stack.push(nid);
//             }

//             if remove_stack.is_empty() {
//                 break;
//             }

//             nuked += remove_stack.len();

//             while let Some(nid) = remove_stack.pop() {
//                 self.graph.remove_node(nid);
//             }
//         }

//         if nuked > 0 {
//             // If we removed any nodes we need to recompute our node_map
//             // as the underlying node indices have changed, as well as no
//             // longer needing references to removed nodes
//             self.node_map.clear();

//             for nid in self.graph.node_indices() {
//                 self.node_map.insert(self.graph[nid].id.clone(), nid);
//             }
//         }

//         Ok(nuked)
//     }

//     fn retain_edge(
//         which: &prune::Prune<'_>,
//         graph: petgraph::graph::Frozen<'_, Graph>,
//         eid: EdgeId,
//     ) -> bool {
//         use prune::ALL_TARGETS as all;

//         match &graph[eid].cfg {
//             // If none, the dependency doesn't have any target configuration,
//             // so we keep it
//             None => true,
//             Some(target_cfg) => {
//                 let (s, t) = graph.edge_endpoints(eid).unwrap();

//                 let src = &graph[s];
//                 let tar = &graph[t];

//                 match which {
//                     prune::Prune::All => {
//                         log::debug!("pruning dependency '{}' -> '{}'", src.id.repr, tar.id.repr);
//                         false
//                     }
//                     prune::Prune::Except(targets) => {
//                         if target_cfg.starts_with("cfg(") {
//                             match cfg_expr::Expression::parse(&target_cfg) {
//                                 Ok(expr) => {
//                                     // We only need to focus on target predicates because they are
//                                     // the only kind allowed by cargo, at least for now
//                                     let matched = expr.eval(|pred| match pred {
//                                         cfg_expr::expr::Predicate::Target(tp) => {
//                                             for t in *targets {
//                                                 if tp.matches(t.target) {
//                                                     return true;
//                                                 }
//                                             }

//                                             false
//                                         }
//                                         cfg_expr::expr::Predicate::TargetFeature(feat) => {
//                                             for t in *targets {
//                                                 if t.features.iter().find(|f| f == feat).is_some() {
//                                                     return true;
//                                                 }
//                                             }

//                                             // If we don't actually find the feature, print out a debug
//                                             // message that we encountered a target_feature due to their
//                                             // relative rarity and "specialness" to hopefully reduce confusion
//                                             // about why the dependency *might* be pruned (if no other predicate
//                                             // matches)
//                                             log::debug!(
//                                                 "encountered target_feature = '{}' for dependency '{}' -> '{}'",
//                                                 feat,
//                                                 src.id.repr,
//                                                 tar.id.repr,
//                                             );
//                                             false
//                                         }
//                                         _ => false,
//                                     });

//                                     if !matched {
//                                         log::debug!(
//                                             "pruning dependency '{}' -> '{}', no match for {}",
//                                             src.id.repr,
//                                             tar.id.repr,
//                                             target_cfg,
//                                         );
//                                     }

//                                     matched
//                                 }
//                                 Err(pe) => {
//                                     log::warn!(
//                                         "failed to parse '{}' for '{}' -> '{}': {}",
//                                         target_cfg,
//                                         src.id.repr,
//                                         tar.id.repr,
//                                         pe
//                                     );

//                                     true
//                                 }
//                             }
//                         } else {
//                             // Ensure it's a target we can recognize
//                             match all.binary_search_by(|ti| ti.triple.cmp(&target_cfg)) {
//                                 Ok(_) => {
//                                     let retain = targets
//                                         .iter()
//                                         .find(|ti| ti.target.triple == target_cfg)
//                                         .is_some();

//                                     if !retain {
//                                         log::warn!(
//                                             "pruning dependency '{}' -> '{}', target {} not provided",
//                                             src.id.repr,
//                                             tar.id.repr,
//                                             target_cfg,
//                                         );
//                                     }

//                                     retain
//                                 }
//                                 Err(_) => {
//                                     log::warn!(
//                                         "unknown target '{}' specified for dependency '{}' -> '{}'",
//                                         target_cfg,
//                                         src.id.repr,
//                                         tar.id.repr
//                                     );

//                                     true
//                                 }
//                             }
//                         }
//                     }
//                 }
//             }
//         }
//     }
// }
