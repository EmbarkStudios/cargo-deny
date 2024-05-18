mod json_schema;

use crate::source;
use crate::prelude::*;
use camino::Utf8PathBuf;

/// Update generated code that is checked in to source control.
#[derive(clap::Args, Debug)]
pub(crate) struct CodegenCommand {
    /// Path to file containing the Schemd schema that we need to process.
    schemd_schema: Utf8PathBuf,
}

impl CodegenCommand {
    pub(crate) fn run(self) -> Result {
        let schemd_schema = source::RootSchema::from_file(self.schemd_schema)?;

        json_schema::gen(&schemd_schema)?;

        Ok(())
    }
}
