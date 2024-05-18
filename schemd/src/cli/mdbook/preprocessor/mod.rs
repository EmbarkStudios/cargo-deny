mod preprocess;

use crate::prelude::*;
use std::io::Write;

#[derive(clap::Args, Debug)]
pub(crate) struct PreprocessorCommand {
    #[command(subcommand)]
    subcommand: Option<PreprocessorSubcommand>,
}

#[derive(clap::Subcommand, Debug)]
enum PreprocessorSubcommand {
    /// Check if a renderer is supported by this preprocessor
    Supports(SupportsCommand),
}

impl PreprocessorSubcommand {
    fn run(self) -> Result {
        match self {
            Self::Supports(cmd) => cmd.run(),
        }
    }
}

impl PreprocessorCommand {
    pub(crate) fn run(self) -> Result {
        self.subcommand
            .map(PreprocessorSubcommand::run)
            .unwrap_or_else(Self::preprocess)
    }

    fn preprocess() -> Result {
        let input = std::io::read_to_string(std::io::stdin())?;

        let (ctx, book) = serde_json::from_str(&input)
            .with_context(|| format!("Unable to parse the input at stdin: ```\n{input}\n```"))?;

        let processed_book = preprocess::run(ctx, book)?;
        let output = serde_json::to_vec(&processed_book)?;

        std::io::stdout().write_all(&output)?;

        Ok(())
    }
}

#[derive(clap::Args, Debug)]
struct SupportsCommand {
    renderer: String,
}

impl SupportsCommand {
    pub(crate) fn run(self) -> Result {
        info!(
            self.renderer,
            "Any renderer is supported. Responding with a yes."
        );
        Ok(())
    }
}
