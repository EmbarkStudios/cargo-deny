mod preprocessor;

use crate::prelude::*;

/// Update generated code that is checked in to source control.
#[derive(clap::Subcommand, Debug)]
pub(crate) enum MdbookCommand {
    /// Implements an proprocessor for the mdbook.
    /// Details: <https://rust-lang.github.io/mdBook/for_developers/preprocessors.html>
    Preprocessor(preprocessor::PreprocessorCommand),
}

impl MdbookCommand {
    pub(crate) fn run(self) -> Result {
        match self {
            Self::Preprocessor(cmd) => cmd.run(),
        }
    }
}
