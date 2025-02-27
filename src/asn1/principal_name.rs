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
    // This field specifies the type of name that follows.  Pre-defined
    // values for this field are specified in Section 6.2.  The name-type
    // SHOULD be treated as a hint.  Ignoring the name type, no two names
    // can be the same (i.e., at least one of the components, or the
    // realm, must be different).
    pub(crate) name_type: i32,
    #[asn1(context_specific = "1")]
    // This field encodes a sequence of components that form a name, each
    // component encoded as a KerberosString. Taken together, a
    // PrincipalName and a Realm form a principal identifier. Most
    // PrincipalNames will have only a few components (typically one or
    // two).
    pub(crate) name_string: Vec<KerberosString>,
}

impl Into<String> for PrincipalName {
    fn into(self) -> String {
        let v: Vec<String> = self.name_string.iter().map(|x| x.0.to_string()).collect();
        v.join("/").clone()
    }
}

impl From<(i32, String)> for PrincipalName {
    fn from(value: (i32, String)) -> Self {
        let name_type = value.0;
        let name_string: Vec<KerberosString> = value.1.split("/").map(|x| x.into()).collect();
        Self {
            name_type,
            name_string,
        }
    }
}

impl From<(i32, &str)> for PrincipalName {
    fn from(value: (i32, &str)) -> Self {
        let name_type = value.0;
        let name_string: Vec<KerberosString> = value.1.split("/").map(|x| x.into()).collect();
        Self {
            name_type,
            name_string,
        }
    }
}
