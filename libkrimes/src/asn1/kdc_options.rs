use super::kerberos_flags::KerberosFlags;

/// ```text
/// KDCOptions      ::= KerberosFlags
/// ````
pub(crate) type KdcOptions = KerberosFlags;
