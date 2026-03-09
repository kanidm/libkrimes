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
}
