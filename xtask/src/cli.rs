mod codegen;

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
}

pub(crate) fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Codegen(cmd) => cmd.run(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]

    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}
