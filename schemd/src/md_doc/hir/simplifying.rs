use super::LoweringContext;
use crate::prelude::*;
use crate::source::{self, Traverse};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use indexmap::IndexMap;

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
            .filter_map(|entry| entry.schema.referenced_definition_name())
            .counts();

        let unused_defs: IndexMap<_, _> = self
            .root
            .definitions
            .iter()
            .filter(|(def_name, _)| !definition_ref_counts.contains_key(def_name.as_str()))
            .collect();

        if !unused_defs.is_empty() {
            let unused_defs = crate::serdex::json::to_string_pretty(unused_defs);
            crate::error::fail_or_warn(
                self.allow_unused_definitions,
                format_err!("Found unused definitions: {unused_defs}"),
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

        ctx.simplify(&mut self.root);

        assert_eq!(
            ctx.single_references.len(),
            0,
            "All single references should have been inlined at this point, but got: {:#?}",
            ctx.single_references
        );

        Ok(ControlFlow::Continue(()))
    }
}

struct SimplificationContext {
    single_references: BTreeMap<String, source::Schema>,
}

impl SimplificationContext {
    fn simplify(&mut self, tree: &mut impl Traverse<source::Schema>) {
        tree.traverse_mut(&mut |schema| self.inline_single_reference(schema));
    }

    fn inline_single_reference(&mut self, schema: &mut source::Schema) {
        let Some(definition_name) = schema.referenced_definition_name() else {
            return;
        };
        let Some(mut definition) = self.single_references.remove(definition_name) else {
            return;
        };

        // Recursively simplify the inlined definition itself.
        self.simplify(&mut definition);

        schema.inline_reference(&definition);
    }
}
