use crate::opt::CcacheDumpOpt;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    if let Ok(mut ccache) = libkrimes::ccache::resolve(opt.common.name.as_deref()) {
        if let Ok(ccname) = ccache.name() {
            println!("Dumping credential cache {:?}", ccname);
            if let Err(e) = ccache.dump() {
                println!("Error: {e:?}");
            }
        }
    }
}
