use super::kerberos_string::KerberosString;
use der::Sequence;

/// ```text
///   PrincipalName   ::= SEQUENCE {
///           name-type       [0] Int32,
///           name-string     [1] SEQUENCE OF KerberosString
///   }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct PrincipalName {
    #[asn1(context_specific = "0")]
    pub(crate) name_type: i32,
    #[asn1(context_specific = "1")]
    pub(crate) name_string: Vec<KerberosString>,
}
