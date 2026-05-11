use crate::opt::CcacheDumpOpt;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    if opt.all {
        if let Ok(mut col) = libkrimes::ccache::resolve_collection(opt.common.name.as_deref()) {
            print!(
                "Collection contains {} credential caches\n\n",
                col.iter().count()
            );

            if let Ok(primary) = col.primary() {
                print!("Primary credential cache is {primary}\n\n");
            }

            for cc in col.deref_mut() {
                if let Ok(ccname) = cc.name() {
                    println!("Dumping credential cache {:?}", ccname);
                    if let Err(e) = cc.dump() {
                        println!("Failed to dump credential cache: {e:?}");
                    }
                    println!();
                }
            }
        }
    } else if let Ok(mut ccache) = libkrimes::ccache::resolve(opt.common.name.as_deref()) {
        if let Ok(ccname) = ccache.name() {
            println!("Dumping credential cache {:?}", ccname);
            if let Err(e) = ccache.dump() {
                println!("Error: {e:?}");
            }
        }
    }
}
