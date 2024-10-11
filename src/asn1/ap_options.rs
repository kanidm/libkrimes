use der::flagset::flags;
use der::flagset::FlagSet;

flags! {
    #[repr(u32)]
    pub enum ApFlags: u32 {
        Reserved        = 1 << 0,
        // The USE-SESSION-KEY option indicates that the ticket the client is
        // presenting to a server is encrypted in the session key from the
        // server's TGT.  When this option is not specified, the ticket is
        // encrypted in the server's secret key.
        UseSessionKey   = 1 << 1,
        // The MUTUAL-REQUIRED option tells the server that the client requires
        // mutual authentication, and that it must respond with a KRB_AP_REP
        // message.
        MutualRequired  = 1 << 2,
    }
}

pub type ApOptions = FlagSet<ApFlags>;
