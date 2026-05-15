use crate::opt::ConfigCheckOpt;
use libkrimes::client::conf::KerberosConfig;
use std::path::PathBuf;

pub(crate) fn check(opt: ConfigCheckOpt) {
    let path = opt.path.map(PathBuf::from);

    let config = match path {
        Some(p) => KerberosConfig::from_file(p),
        None => KerberosConfig::from_defaults(),
    };

    if opt.pretty {
        println!("{:#?}", config);
    } else {
        println!("{:?}", config);
    }
}
