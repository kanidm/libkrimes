use super::kerberos_string::KerberosString;
use super::kerberos_time::KerberosTime;
use super::microseconds::Microseconds;
use super::pa_data::PaData;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///            pvno            [0] INTEGER (5),
///            msg-type        [1] INTEGER (30),
///            ctime           [2] KerberosTime OPTIONAL,
///            cusec           [3] Microseconds OPTIONAL,
///            stime           [4] KerberosTime,
///            susec           [5] Microseconds,
///            error-code      [6] Int32,
///            crealm          [7] Realm OPTIONAL,
///            cname           [8] PrincipalName OPTIONAL,
///            realm           [9] Realm -- service realm --,
///            sname           [10] PrincipalName -- service name --,
///            e-text          [11] KerberosString OPTIONAL,
///            e-data          [12] OCTET STRING OPTIONAL
///    }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct KrbError {
    #[asn1(context_specific = "0")]
    pub(crate) pvno: u8,
    #[asn1(context_specific = "1")]
    pub(crate) msg_type: u8,
    #[asn1(context_specific = "2", optional = "true")]
    pub(crate) ctime: Option<KerberosTime>,
    #[asn1(context_specific = "3", optional = "true")]
    pub(crate) cusec: Option<Microseconds>,
    #[asn1(context_specific = "4")]
    pub(crate) stime: KerberosTime,
    #[asn1(context_specific = "5")]
    pub(crate) susec: Microseconds,
    #[asn1(context_specific = "6")]
    pub(crate) error_code: i32,
    #[asn1(context_specific = "7", optional = "true")]
    pub(crate) crealm: Option<Realm>,
    #[asn1(context_specific = "8", optional = "true")]
    pub(crate) cname: Option<PrincipalName>,
    #[asn1(context_specific = "9")]
    pub(crate) service_realm: Realm,
    #[asn1(context_specific = "10")]
    pub(crate) service_name: PrincipalName,
    #[asn1(context_specific = "11", optional = "true")]
    pub(crate) error_text: Option<KerberosString>,
    #[asn1(context_specific = "12", optional = "true")]
    pub(crate) error_data: Option<OctetString>,
}

/// ```text
///    If the errorcode is KDC_ERR_PREAUTH_REQUIRED, then the e-data field will
///    contain an encoding of a sequence of padata fields, each
///    corresponding to an acceptable pre-authentication method and
///    optionally containing data for the method:
///
///      METHOD-DATA     ::= SEQUENCE OF PA-DATA
///
///   For error codes defined in this document other than
///   KDC_ERR_PREAUTH_REQUIRED, the format and contents of the e-data field
///   are implementation-defined.  Similarly, for future error codes, the
///   format and contents of the e-data field are implementation-defined
///   unless specified otherwise.  Whether defined by the implementation or
///   in a future document, the e-data field MAY take the form of TYPED-
///   DATA:
///
///   TYPED-DATA      ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///           data-type       [0] Int32,
///           data-value      [1] OCTET STRING OPTIONAL
///   }
/// ```
pub(crate) type MethodData = Vec<PaData>;

#[cfg(test)]
mod tests {
    use crate::asn1::constants::{KrbErrorCode, KrbMessageType, PaDataType};
    use crate::asn1::kerberos_time::KerberosTime;
    use crate::asn1::krb_error::{KrbError, MethodData};
    use core::iter::zip;
    use der::DateTime;
    use der::{Decode, DecodeValue, EncodeValue, FixedTag, Tag, TagNumber};

    #[derive(Debug, Eq, PartialEq)]
    struct TaggedKrbError(KrbError);

    impl FixedTag for TaggedKrbError {
        const TAG: Tag = Tag::Application {
            constructed: true,
            number: TagNumber(30),
        };
    }

    impl<'a> DecodeValue<'a> for TaggedKrbError {
        type Error = der::Error;

        fn decode_value<R: der::Reader<'a>>(
            reader: &mut R,
            _header: der::Header,
        ) -> der::Result<Self> {
            let e: KrbError = KrbError::decode(reader)?;
            Ok(Self(e))
        }
    }

    impl EncodeValue for TaggedKrbError {
        fn value_len(&self) -> der::Result<der::Length> {
            KrbError::value_len(&self.0)
        }
        fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
            KrbError::encode_value(&self.0, encoder)
        }
    }

    #[test]
    fn krb_err_response_too_big() {
        let blob = "7e5a3058a003020105a10302011ea411180f32303234303631323131343830355aa505020301dc66a603020134a90c1b0a41464f524553542e4144aa1f301da003020102a11630141b066b72627467741b0a41464f524553542e4144";
        let blob = hex::decode(blob).expect("Failed to decode sample");
        let e = TaggedKrbError::from_der(&blob).expect("Failed to decode");

        assert_eq!(e.0.pvno, 5);
        assert_eq!(e.0.msg_type, KrbMessageType::KrbError.into());
        assert_eq!(
            e.0.stime,
            KerberosTime::from_date_time(
                DateTime::new(2024, 6, 12, 11, 48, 5).expect("Failed to build datetime")
            )
        );
        assert_eq!(e.0.susec, 121958);
        assert_eq!(e.0.error_code, KrbErrorCode::KrbErrResponseTooBig.into());
        assert_eq!(e.0.service_realm.0.as_str(), "AFOREST.AD");
        assert_eq!(e.0.service_name.name_type, 2);
        assert_eq!(e.0.service_name.name_string[0].0.as_str(), "krbtgt");
        assert_eq!(e.0.service_name.name_string[1].0.as_str(), "AFOREST.AD");
    }

    #[test]
    fn krb_err_preauth_required() {
        let blob = "7e81a93081a6a003020105a10302011ea411180f32303234303631323131343830355aa505020301dc66a603020119a90c1b0a41464f524553542e4144aa1f301da003020102a11630141b066b72627467741b0a41464f524553542e4144ac4c044a30483025a103020113a21e041c301a3018a003020112a1111b0f41464f524553542e414475736572313009a103020102a20204003009a103020110a20204003009a10302010fa2020400";
        let blob = hex::decode(blob).expect("Failed to decode sample");
        let e = TaggedKrbError::from_der(&blob).expect("Failed to decode");

        assert_eq!(e.0.pvno, 5);
        assert_eq!(e.0.msg_type, KrbMessageType::KrbError.into());
        assert_eq!(
            e.0.stime,
            KerberosTime::from_date_time(
                DateTime::new(2024, 6, 12, 11, 48, 5).expect("Failed to build datetime")
            )
        );
        assert_eq!(e.0.susec, 121958);
        assert_eq!(e.0.error_code, KrbErrorCode::KdcErrPreauthRequired.into());
        assert_eq!(e.0.service_realm.0.as_str(), "AFOREST.AD");
        assert_eq!(e.0.service_name.name_type, 2);
        assert_eq!(e.0.service_name.name_string[0].0.as_str(), "krbtgt");
        assert_eq!(e.0.service_name.name_string[1].0.as_str(), "AFOREST.AD");

        assert!(e.0.error_data.is_some());
        let edata = e.0.error_data.as_ref().unwrap();
        let edata = MethodData::from_der(edata.as_bytes()).expect("Failed to decode");

        let tedata = vec![
            (
                PaDataType::PaEtypeInfo2,
                Some("301a3018a003020112a1111b0f41464f524553542e41447573657231"),
            ),
            (PaDataType::PaEncTimestamp, None),
            (PaDataType::PaPkAsReq, None),
            (PaDataType::PaPkAsRepOld, None),
        ];
        assert_eq!(edata.len(), tedata.len());

        let iter = zip(edata, &tedata);
        for (pa, tpa) in iter {
            assert_eq!(pa.padata_type, tpa.0 as u32);
            if tpa.1.is_some() {
                let tbytes = hex::decode(tpa.1.unwrap()).expect("Failed to decode bytes");
                assert_eq!(pa.padata_value.as_bytes(), tbytes);
            }
        }
    }
}
