mod source;
mod json_schema;
mod md_doc;

use std::fs;

/// Update generated code that is checked in to source control.
#[derive(clap::Args, Debug)]
pub(crate) struct CodegenCommand {}

impl CodegenCommand {
    pub(crate) fn run(self) -> anyhow::Result<()> {
        // Maybe we'll need CLI params here in the future
        let Self {} = self;

        let input = fs::read_to_string("deny.schema.yml")?;
        let input: source::RootSchema = serde_yaml::from_str(&input)?;

        md_doc::gen(&input)?;
        json_schema::gen(&input)?;

        Ok(())
    }
}
