use der::asn1::GeneralizedTime;

/// ```text
/// KerberosTime    ::= GeneralizedTime
/// ````
pub(crate) type KerberosTime = GeneralizedTime;
