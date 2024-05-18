mod codegen;
mod mdbook;

use crate::prelude::*;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Codegen(codegen::CodegenCommand),

    #[command(subcommand)]
    Mdbook(mdbook::MdbookCommand),
}

pub(crate) fn run() -> Result {
    let cli = Cli::parse();

    debug!(cli = format_args!("{cli:#?}"), "Invoked with CLI params");

    match cli.command {
        Command::Codegen(cmd) => cmd.run(),
        Command::Mdbook(cmd) => cmd.run(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]

    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
