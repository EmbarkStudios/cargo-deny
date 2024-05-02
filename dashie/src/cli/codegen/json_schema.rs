use crate::source::{EnumVariantSchema, RootSchema, Schema};
use crate::prelude::*;
use crate::serdex;

/// Generate the JSON schema based on the input YML schema.
pub(crate) fn gen(root: &RootSchema) -> Result {
    let ctx = GenContext::new(root);
    let root = ctx.gen()?;

    let output = serdex::json::to_string_pretty(&root);

    std::fs::write("deny.schema.json", output)?;

    Ok(())
}

struct GenContext<'a> {
    root: &'a RootSchema,
}

impl<'a> GenContext<'a> {
    fn new(root: &'a RootSchema) -> Self {
        Self { root }
    }

    fn gen(self) -> Result<RootSchema> {
        let schema = self.gen_schema(&self.root.schema)?;
        let definitions = self
            .root
            .definitions
            .iter()
            .map(|(name, def)| {
                let def = self.gen_schema(def)?;
                Ok((name.clone(), def))
            })
            .collect::<Result<_>>()?;

        Ok(RootSchema {
            definitions,
            schema,
            misc: self.root.misc.clone(),
        })
    }

    fn gen_schema(&self, schema: &Schema) -> Result<Schema> {
        let mut schema = schema.clone();

        schema.traverse_mut(&mut |schema| self.normalize_enum(schema))?;

        Ok(schema)
    }

    /// Normalize the [`EnumSchema::Custom`] to [`EnumSchema::Standard`] format
    /// plus generate some extensions for specific TOML language servers
    fn normalize_enum(&self, schema: &mut Schema) -> Result {
        let mut inlined = self.root.inline_referenced_definition(schema)?;

        let Some(enum_variants) = &mut inlined.enum_schema else {
            return Ok(());
        };

        let (values, descriptions): (Vec<_>, Vec<_>) = enum_variants
            .iter_mut()
            .map(|variant| {
                let (value, description) = variant.value_and_description();

                let description = description.unwrap_or_default();

                (EnumVariantSchema::Undocumented(value), description)
            })
            .unzip();

        inlined.x_taplo = Some(serde_json::json!({
            "docs": { "enumValues": descriptions }
        }));

        *enum_variants = values;

        *schema = inlined;

        Ok(())
    }
}
