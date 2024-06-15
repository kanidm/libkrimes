use super::kerberos_string::KerberosString;

/// ```text
/// Realm           ::= KerberosString
/// ````
pub(crate) type Realm = KerberosString;
