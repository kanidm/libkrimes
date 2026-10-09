use crate::opt::CcacheDumpOpt;
use libkrimes::ccache::ResolvedCredentialCache;
use std::ffi::OsString;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    let ccache_name = opt.common.name.as_deref().map(OsString::from);

    let Ok(ccache) = libkrimes::ccache::resolve(ccache_name.as_ref()).inspect_err(|e| {
        print!("Failed to resolve credential cache: {e:?}");
    }) else {
        return;
    };

    match ccache {
        ResolvedCredentialCache::Collection(cccol) => {
            if let Ok(primary) = cccol.primary() {
                match primary.name() {
                    Ok(name) => {
                        print!("Primary credential cache is {}\n\n", name.display())
                    }
                    Err(e) => print!("Failed to read primary subsidiary name: {:?}\n\n", e),
                }
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
    };
}
