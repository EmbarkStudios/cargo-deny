use super::input::{EnumSchema, RootSchema, Schema};
use anyhow::Result;
use std::mem;

/// Generate the JSON schema based on the input YML schema.
pub(crate) fn gen(root: &RootSchema) -> Result<()> {
    let ctx = GenContext::new(root);
    let root = ctx.gen()?;

    let output = serde_json::to_string_pretty(&root)?;

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
            other: self.root.other.clone(),
        })
    }

    fn gen_schema(&self, schema: &Schema) -> Result<Schema> {
        let mut schema = schema.clone();

        schema.traverse_mut(|schema| self.normalize_enum(schema))?;

        Ok(schema)
    }

    /// Normalize the [`EnumSchema::Custom`] to [`EnumSchema::Standard`] format
    /// plus generate some extensions for specific TOML language servers
    fn normalize_enum(&self, schema: &mut Schema) -> Result<()> {
        let mut inlined = self.root.inline_referenced_definition(schema)?;

        let Some(enum_schema) = &mut inlined.enum_schema else {
            return Ok(());
        };

        let EnumSchema::Custom(custom) = enum_schema else {
            return Ok(());
        };

        let (values, descriptions): (Vec<_>, Vec<_>) = custom
            .iter_mut()
            .map(|custom| {
                (
                    mem::take(&mut custom.value).into(),
                    mem::take(&mut custom.description),
                )
            })
            .unzip();

        inlined.x_taplo = Some(serde_json::json!({
            "docs": { "enumValues": descriptions }
        }));

        *enum_schema = EnumSchema::Standard(values);

        *schema = inlined;

        Ok(())
    }
}
