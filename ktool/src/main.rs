use clap::{Parser, Subcommand};
use opt::CcacheDumpOpt;

mod ccache;
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
}

#[derive(Debug, Clone, Subcommand)]
enum CcacheOpt {
    Dump(CcacheDumpOpt),
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.commands {
        KToolCommands::Ccache { command } => match command {
            CcacheOpt::Dump(opt) => ccache::dump(opt),
        },
    }
}
