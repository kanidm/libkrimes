use num_enum::{IntoPrimitive, TryFromPrimitive};



#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(i32)]
pub enum PrincipalNameType {
    NtUnknown = 0,          /* Name type not known */
    NtPrincipal = 1,        /* Just the name of the principal as in DCE, or for users */
    NtSrvInst = 2,          /* Service and other unique instance (krbtgt) */
    NtSrvHst = 3,           /* Service with host name as instance (telnet, rcommands) */
    NtSrvXhst = 4,          /* Service with host as remaining components */
    NtUid = 5,              /* Unique ID */
    NtX500Principal = 6,    /* Encoded X.509 Distinguished name [RFC2253] */
    NtSmtpName = 7,         /* Name in form of SMTP email name (e.g., user@example.com) */
    NtEnterprise = 10,      /* Enterprise name - may be mapped to principal name */
}
