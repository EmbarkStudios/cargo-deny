use super::LoweringContext;
use crate::prelude::*;
use crate::source;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

impl LoweringContext {
    pub(crate) fn simplify(&mut self) -> Result<ControlFlow<()>> {
        let all_schemas = || {
            let schemas_in_root = self.root.schema.entries();
            let schemas_in_defs = self
                .root
                .definitions
                .values()
                .flat_map(source::Schema::entries);
            itertools::chain(schemas_in_root, schemas_in_defs)
        };

        let definition_ref_counts = all_schemas()
            .filter_map(|entry| entry.schema.referenced_uninlined_definition())
            .counts();

        let unused_defs: Vec<_> = self
            .root
            .definitions
            .iter()
            .filter(|(def_name, _)| !definition_ref_counts.contains_key(def_name.as_str()))
            .collect();

        if !unused_defs.is_empty() {
            crate::error::fail_or_warn(
                self.allow_unused_definitions,
                format_err!("Found unused definitions: {unused_defs:#?}"),
            )?;
        }

        let single_references: BTreeMap<_, _> = definition_ref_counts
            .into_iter()
            // For schemas that are referenced only once, we want to inline them
            // directly in the containing schema object instead. This is done to
            // reduce the "Type Index" and make it clear that the definition is
            // only used in one place, where it is defined inline.
            .filter(|(_, count)| *count == 1)
            .map(|(def_name, _)| def_name.to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|definition_name| {
                let definition = self.root.remove_definition(&definition_name)?;
                Ok::<_, Error>((definition_name, definition))
            })
            .try_collect()?;

        if single_references.is_empty() {
            // nothing to simplify anymore
            return Ok(ControlFlow::Break(()));
        }

        let mut ctx = SimplificationContext { single_references };

        ctx.simplify(self)?;

        Ok(ControlFlow::Continue(()))
    }
}

struct SimplificationContext {
    single_references: BTreeMap<String, source::Schema>,
}

impl SimplificationContext {
    fn simplify(&mut self, lowering: &mut LoweringContext) -> Result {
        // We simplify in a loop because inlining a definition may introduce new
        // opportunities for further simplification. It is a fixed-point iteration
        // where we keep simplifying until eventually no more simplifications can
        // be made.
        while !self.single_references.is_empty() {
            lowering.root.traverse_mut(&mut |schema| {
                self.inline_single_reference(schema);
                Ok(())
            })?;
            dbg!(&self.single_references.keys().collect_vec());
        }

        Ok(())
    }

    fn inline_single_reference(&mut self, schema: &mut source::Schema) {
        let Some(definition) = schema.referenced_uninlined_definition() else {
            return;
        };
        let Some(definition) = self.single_references.remove(definition) else {
            return;
        };

        schema.inline_reference(&definition);
    }
}
