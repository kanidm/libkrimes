use crate::opt::CcacheDumpOpt;
use libkrimes::ccache::ResolvedCredentialCache;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    let ccache = libkrimes::ccache::resolve(opt.common.name.as_deref()).unwrap();
    match ccache {
        ResolvedCredentialCache::Collection(mut cccol) => {
            if let Ok(primary) = cccol.primary() {
                print!("Primary credential cache is {primary}\n\n");
            } else {
                print!("Failed to read primary subsidiary name\n\n");
            }

            for cc in cccol
                .try_iter()
                .inspect_err(|e| print!("Failed to iterate the collection: {:?}\n\n", e))
                .unwrap_or_default()
            {
                print!("{:?}", cc.dump());
            }
        }
        ResolvedCredentialCache::Subsidiary(cc) => {
            println!("Dumping credential cache {:?}", cc.name());
            if let Err(e) = cc.dump() {
                println!("Error: {e:?}");
            }
        }
    }
}
