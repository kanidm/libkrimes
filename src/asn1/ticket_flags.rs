use der::flagset::flags;

flags! {
    /// ```text
    /// TicketFlags     ::= KerberosFlags
    ///         -- reserved(0),
    ///         -- forwardable(1),
    ///         -- forwarded(2),
    ///         -- proxiable(3),
    ///         -- proxy(4),
    ///         -- may-postdate(5),
    ///         -- postdated(6),
    ///         -- invalid(7),
    ///         -- renewable(8),
    ///         -- initial(9),
    ///         -- pre-authent(10),
    ///         -- hw-authent(11),
    ///         -- transited-policy-checked(12),
    ///         -- ok-as-delegate(13)
    /// ````
    #[repr(u32)]
    pub(crate) enum TicketFlags: u32 {
        Reserved               = 1 << 0,
        Forwardable            = 1 << 1,
        Forwarded              = 1 << 2,
        Proxiable              = 1 << 3,
        Proxy                  = 1 << 4,
        MayPostdate            = 1 << 5,
        Postdated              = 1 << 6,
        Invalid                = 1 << 7,
        Renewable              = 1 << 8,
        Initial                = 1 << 9,
        PreAuthent             = 1 << 10,
        HwAuthent              = 1 << 11,
        TransitedPolicyChecked = 1 << 12,
        OkAsDelegate           = 1 << 13,
    }
}
