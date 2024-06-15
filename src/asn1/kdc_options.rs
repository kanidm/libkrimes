use super::kerberos_flags::KerberosFlags;
use der::flagset::FlagSet;

/// ```text
/// KDCOptions      ::= KerberosFlags
/// ````
pub(crate) type KdcOptions = FlagSet<KerberosFlags>;
