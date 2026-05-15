use clap::Args;

#[derive(Debug, Clone, Args)]
pub(crate) struct CcacheCommonOpt {
    #[clap(short, long)]
    pub(crate) name: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct CcacheDumpOpt {
    #[clap(flatten)]
    pub(crate) common: CcacheCommonOpt,
    #[arg(short, long, help = "Dump all credential caches in the collection")]
    pub(crate) all: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ConfigCheckOpt {
    #[clap(short, long)]
    pub(crate) path: Option<String>,
    #[clap(long, help = "Pretty print the parsing result")]
    pub(crate) pretty: bool,
}
