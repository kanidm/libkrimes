use clap::{Parser, Subcommand};
use opt::{CcacheDumpOpt, ConfigCheckOpt};

mod ccache;
mod config;
mod opt;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    commands: KToolCommands,
}

#[derive(Debug, Clone, Subcommand)]
enum KToolCommands {
    Ccache {
        #[clap(subcommand)]
        command: CcacheOpt,
    },
    Config {
        #[clap(subcommand)]
        command: ConfigOpt,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum CcacheOpt {
    Dump(CcacheDumpOpt),
}

#[derive(Debug, Clone, Subcommand)]
enum ConfigOpt {
    Check(ConfigCheckOpt),
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.commands {
        KToolCommands::Ccache { command } => match command {
            CcacheOpt::Dump(opt) => ccache::dump(opt),
        },
        KToolCommands::Config { command } => match command {
            ConfigOpt::Check(opt) => config::check(opt),
        },
    }
}
