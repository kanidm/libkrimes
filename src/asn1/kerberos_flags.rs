use der::flagset::flags;

flags! {
    /// ```text
    /// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
    ///                     -- minimum number of bits shall be sent,
    ///                     -- but no fewer than 32
    /// ````
    #[repr(u32)]
    pub(crate) enum KerberosFlags: u32 {
        Reserved        = 1 << 0,
        Forwardable     = 1 << 1,
        Forwarded       = 1 << 2,
        Proxiable       = 1 << 3,
        Proxy           = 1 << 4,
        AllowPostdate   = 1 << 5,
        Postdated       = 1 << 6,
        Unused7         = 1 << 7,
        Renewable       = 1 << 8,
        Unused9         = 1 << 9,
        Unused10        = 1 << 10,
        OptHardwareAuth = 1 << 11,
        Unused12        = 1 << 12,
        Unused13        = 1 << 13,
        Unused14        = 1 << 14,
        Canonicalize    = 1 << 15,
        Unused16        = 1 << 16,
        Unused17        = 1 << 17,
        Unused18        = 1 << 18,
        Unused19        = 1 << 19,
        Unused20        = 1 << 20,
        Unused21        = 1 << 21,
        Unused22        = 1 << 22,
        Unused23        = 1 << 23,
        Unused24        = 1 << 24,
        Unused25        = 1 << 25,
        // -- 26 was unused in 1510
        DisableTransitedCheck = 1 << 26,
        RenewableOk     = 1 << 27,
        EncTktInSkey    = 1 << 28,
        Unused29        = 1 << 29,
        Renew           = 1 << 30,
        Validate        = 1 << 31
    }
}
