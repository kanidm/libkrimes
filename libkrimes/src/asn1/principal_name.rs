use super::kerberos_string::KerberosString;
use crate::error::KrbError;
use der::Sequence;
use std::str::FromStr;

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

impl From<PrincipalName> for String {
    fn from(value: PrincipalName) -> Self {
        let v: Vec<&str> = value.name_string.iter().map(|x| x.as_ref()).collect();
        v.join("/")
    }
}

impl<T> TryFrom<(i32, T)> for PrincipalName
where
    T: AsRef<str>,
{
    type Error = KrbError;

    fn try_from((name_type, name_str): (i32, T)) -> Result<Self, Self::Error> {
        let name_string = name_str
            .as_ref()
            .split("/")
            .map(KerberosString::from_str)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name_type,
            name_string,
        })
    }
}
