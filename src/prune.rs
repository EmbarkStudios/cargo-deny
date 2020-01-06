use crate::Pid;
use anyhow::Error;
use rayon::prelude::*;
use std::collections::HashSet;

pub use cfg_expr::targets::{TargetInfo, ALL_TARGETS};

pub struct Target {
    pub target: &'static TargetInfo,
    pub features: Vec<String>,
}

pub enum Prune<'a> {
    All,
    Except(&'a [Target]),
}

// impl crate::Krates {
//     /// Prunes target specific crates from the crate graph if they don't match
//     /// one or more of the supplied target filters
//     pub fn prune(&mut self, which: Option<Prune<'_>>) -> Result<usize, Error> {
//         let which = match which {
//             Some(which) => which,
//             None => return Ok(0),
//         };

//         use cfg_expr::targets::ALL_TARGETS as all;
//         let mut filtered = Vec::new();

//         // The platform cfg is not available in the resolution graph
//         // until 1.41, so we do it against the crate dependencies directly
//         // and fixup the resolve graph later
//         for krate in &mut self.krates {
//             let mut i = 0;
//             while i < krate.deps.len() {
//                 let is_filtered = match krate.deps[i].target.as_ref().map(|t| format!("{}", t)) {
//                     Some(target) => {
//                         match which {
//                             Prune::All => true,
//                             Prune::Except(targets) => {
//                                 // The platform can be in either a cfg(...), or a full target triplet form
//                                 if target.starts_with("cfg(") {
//                                     match cfg_expr::Expression::parse(&target) {
//                                         Err(e) => {
//                                             log::warn!(
//                                                 "unable to parse cfg() for dependency {} of crate {}: {}",
//                                                 krate.deps[i].rename.as_ref().unwrap_or(&krate.deps[i].name),
//                                                 krate.id.repr,
//                                                 e
//                                             );

//                                             false
//                                         }
//                                         Ok(expr) => {
//                                             // We only need to focus on target predicates because they are
//                                             // the only kind allowed by cargo, at least for now
//                                             !expr.eval(|pred| match pred {
//                                                 cfg_expr::expr::Predicate::Target(tp) => {
//                                                     for t in targets {
//                                                         if tp.matches(t.target) {
//                                                             return true;
//                                                         }
//                                                     }

//                                                     false
//                                                 }
//                                                 cfg_expr::expr::Predicate::TargetFeature(feat) => {
//                                                     for t in targets {
//                                                         if t.features.iter().any(|f| f == feat) {
//                                                             return true;
//                                                         }
//                                                     }

//                                                     // If we don't actually find the feature, print out a debug
//                                                     // message that we encountered a target_feature due to their
//                                                     // relative rarity and "specialness" to hopefully reduce confusion
//                                                     // about why the dependency *might* be pruned (if no other predicate
//                                                     // matches)
//                                                     false
//                                                 }
//                                                 _ => false,
//                                             })
//                                         }
//                                     }
//                                 } else {
//                                     // Ensure it's a target we can recognize
//                                     match all.binary_search_by(|ti| ti.triple.cmp(&target)) {
//                                         Err(_) => {
//                                             log::warn!("unknown target triple `{}` encountered for crate {} dependency {}",
//                                                 target,
//                                                 krate.id.repr,
//                                                 krate.deps[i].rename.as_ref().unwrap_or(&krate.deps[i].name),
//                                             );

//                                             false
//                                         }
//                                         Ok(_) => targets
//                                             .iter()
//                                             .find(|ti| ti.target.triple == target)
//                                             .is_none(),
//                                     }
//                                 }
//                             }
//                         }
//                     }
//                     None => {
//                         i += 1;
//                         continue;
//                     }
//                 };

//                 if is_filtered {
//                     let dep = krate.deps.remove(i);

//                     filtered.push((
//                         dep.rename.as_ref().unwrap_or(&dep.name).clone(),
//                         krate.id.clone(),
//                     ));
//                 } else {
//                     i += 1;
//                 }
//             }
//         }

//         // Remove the filtered dependencies recursively until we stabilize
//         let mut nuked = HashSet::new();
//         loop {
//             if filtered.is_empty() {
//                 break;
//             }

//             filtered = self.inner_prune(filtered, &mut nuked)?;
//         }

//         let num_nuked = nuked.len();

//         // Final step, remove any crates from the graph that
//         for nuke in nuked {
//             if let Ok(i) = self.resolved.nodes.binary_search_by(|rn| rn.id.cmp(&nuke)) {
//                 self.resolved.nodes.remove(i);
//             }

//             if let Ok(i) = self.krates.binary_search_by(|k| k.id.cmp(&nuke)) {
//                 self.krates.remove(i);
//             }
//         }

//         self.krate_map.clear();
//         for (i, krate) in self.krates.iter().enumerate() {
//             self.krate_map.insert(krate.id.clone(), i);
//         }

//         Ok(num_nuked)
//     }

//     fn inner_prune(
//         &mut self,
//         filtered: Vec<(String, Pid)>,
//         nuked: &mut HashSet<Pid>,
//     ) -> Result<Vec<(String, Pid)>, Error> {
//         let mut filtered_ids = Vec::with_capacity(filtered.len());

//         // Clean a dependecy from the package identifier referring to it from the resolve graph
//         for (dep_name, pid) in filtered {
//             match self.resolved.nodes.binary_search_by(|n| n.id.cmp(&pid)) {
//                 Ok(i) => {
//                     let node = &mut self.resolved.nodes[i];

//                     match node.deps.iter().position(|d| d.name == dep_name) {
//                         Some(i) => {
//                             let ndep = node.deps.remove(i);

//                             match node.dependencies.binary_search(&ndep.pkg) {
//                                 Ok(i) => {
//                                     node.dependencies.remove(i);
//                                 }
//                                 Err(_) => {
//                                     log::warn!(
//                                         "failed to find resolved dependency {} for crate {}",
//                                         ndep.pkg.repr,
//                                         pid.repr
//                                     );
//                                 }
//                             }

//                             filtered_ids.push((ndep.pkg, 0));
//                         }
//                         None => {
//                             log::warn!(
//                                 "failed to find resolved dependency {} for crate {}",
//                                 dep_name,
//                                 pid.repr
//                             );
//                         }
//                     }
//                 }
//                 Err(_) => {
//                     log::warn!("failed to find resolved crate {}", pid.repr);
//                 }
//             }
//         }

//         filtered_ids.sort();
//         filtered_ids.dedup();

//         // Check to see if there are any remaining references to any of the package ids
//         // we just removed the resolution graph. If there are none, remove the entire pid
//         // from the graph
//         filtered_ids.par_iter_mut().for_each(|(pkg, count)| {
//             for node in &self.resolved.nodes {
//                 if node.dependencies.binary_search(pkg).is_ok() {
//                     *count += 1;
//                 }
//             }
//         });

//         let mut new_filtered = Vec::new();

//         for to_remove in
//             filtered_ids
//                 .into_iter()
//                 .filter_map(|(pkg, count)| if count == 0 { Some(pkg) } else { None })
//         {
//             if let Ok(i) = self
//                 .resolved
//                 .nodes
//                 .binary_search_by(|n| n.id.cmp(&to_remove))
//             {
//                 let node = &self.resolved.nodes[i];
//                 for dep in &node.deps {
//                     new_filtered.push((dep.name.clone(), to_remove.clone()));
//                 }

//                 nuked.insert(to_remove);
//             }
//         }

//         Ok(new_filtered)
//     }
// }
