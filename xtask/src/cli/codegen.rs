mod jsonschema;

/// Update generated code that is checked in to source control.
#[derive(clap::Args, Debug)]
pub(crate) struct CodegenCommand {}

impl CodegenCommand {
    pub(crate) fn run(self) -> anyhow::Result<()> {
        jsonschema::codegen()?;

        Ok(())
    }
}
