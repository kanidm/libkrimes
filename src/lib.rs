use tracing::*;

use der::asn1::GeneralizedTime;
use der::asn1::Ia5String;
use der::asn1::OctetString;
use der::flagset::{flags, FlagSet};
use der::DecodeValue;
use der::EncodeValue;
use der::FixedTag;
use der::Sequence;
use der::Tag;
use der::TagNumber;

flags! {
    /// ```text
    /// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
    ///                     -- minimum number of bits shall be sent,
    ///                     -- but no fewer than 32
    /// ````
    enum KerberosFlags: u32 {
        Reserved = 0,
        Forwardable = 1,
        Forwarded = 2,
        Proxiable = 3,
        Proxy = 4,
        AllowPostdate = 5,
        Postdated = 6,
        Unused7 = 7,
        Renewable = 8,
        Unused9 = 9,
        Unused10 = 10,
        OptHardwareAuth = 11,
        Unused12 = 12,
        Unused13 = 13,
        // -- 15 is reserved for canonicalize
        Unused15 = 15,
        // -- 26 was unused in 1510
        DisableTransitedCheck = 26,
        RenewableOk = 27,
        EncTktInSkey = 28,
        Renew = 30,
        Validate = 31
    }
}

/// ```text
/// KDCOptions      ::= KerberosFlags
/// ````
type KdcOptions = FlagSet<KerberosFlags>;

/// ```text
/// KerberosString  ::= GeneralString (IA5String)
/// ````
#[derive(Clone, Debug, Eq, PartialEq)]
struct KerberosString(Ia5String);

impl FixedTag for KerberosString {
    const TAG: Tag = Tag::GeneralString;
}

impl<'a> DecodeValue<'a> for KerberosString {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let r: Ia5String = der::asn1::Ia5String::decode_value(reader, header)?;
        Ok(Self(r))
    }
}

impl<'a> EncodeValue for KerberosString {
    fn value_len(&self) -> der::Result<der::Length> {
        Ia5String::value_len(&self.0)
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ia5String::encode_value(&self.0, encoder)
    }
}

/// ```text
///   PrincipalName   ::= SEQUENCE {
///           name-type       [0] Int32,
///           name-string     [1] SEQUENCE OF KerberosString
///   }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct PrincipalName {
    #[asn1(context_specific = "0")]
    name_type: i32,
    #[asn1(context_specific = "1")]
    name_string: Vec<KerberosString>,
}

/// ```text
/// Realm           ::= KerberosString
/// ````
type Realm = KerberosString;

/// ```text
/// KerberosTime    ::= GeneralizedTime
/// ````
type KerberosTime = GeneralizedTime;

/// ```text
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct HostAddresses {
    #[asn1(context_specific = "0")]
    addr_type: i32,
    #[asn1(context_specific = "1")]
    address: OctetString,
}

/// ```text
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct EncryptedData {
    #[asn1(context_specific = "0")]
    etype: i32,
    #[asn1(context_specific = "1")]
    kvno: u32,
    #[asn1(context_specific = "2")]
    cipher: OctetString,
}

/// ```text
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct Ticket {
    #[asn1(context_specific = "0")]
    tkt_vno: i8,
    #[asn1(context_specific = "1")]
    realm: Realm,
    #[asn1(context_specific = "2")]
    sname: PrincipalName,
    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

#[derive(Debug, Eq, PartialEq)]
struct TaggedTicket(Ticket);

impl FixedTag for TaggedTicket {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N1,
    };
}

impl<'a> DecodeValue<'a> for TaggedTicket {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let t: Ticket = Ticket::decode_value(reader, header)?;
        Ok(Self(t))
    }
}

impl<'a> EncodeValue for TaggedTicket {
    fn value_len(&self) -> der::Result<der::Length> {
        Ticket::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ticket::encode_value(&self.0, encoder)
    }
}

/// ```text
/// PA-DATA         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct PaData {
    #[asn1(context_specific = "1")]
    padata_type: u32,
    #[asn1(context_specific = "2")]
    padata_value: OctetString,
}

/// ```text
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                         -- NOTE: not empty
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
struct KdcReqBody {
    #[asn1(context_specific = "0")]
    kdc_options: KdcOptions,
    #[asn1(context_specific = "1", optional = "true")]
    cname: Option<PrincipalName>,
    #[asn1(context_specific = "2")]
    realm: Realm,
    #[asn1(context_specific = "3", optional = "true")]
    sname: Option<PrincipalName>,
    #[asn1(context_specific = "4", optional = "true")]
    from: Option<KerberosTime>,
    #[asn1(context_specific = "5")]
    till: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    rtime: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    nonce: u32,
    #[asn1(context_specific = "8")]
    etype: Vec<i32>,
    #[asn1(context_specific = "9", optional = "true")]
    addresses: Option<HostAddresses>,
    #[asn1(context_specific = "10", optional = "true")]
    enc_authorization_data: Option<EncryptedData>,
    #[asn1(context_specific = "11", optional = "true")]
    additional_tickets: Option<Vec<TaggedTicket>>,
}

/// ```text
/// KDC-REQ         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
struct KdcReq {
    #[asn1(context_specific = "1")]
    pvno: u8,
    #[asn1(context_specific = "2")]
    msg_type: u8,
    #[asn1(context_specific = "3", optional = "true")]
    padata: Option<Vec<PaData>>,
    #[asn1(context_specific = "4")]
    req_body: KdcReqBody,
}

#[derive(Debug, Eq, PartialEq)]
enum KrbKdcReq {
    AsReq(KdcReq),
}

impl<'a> ::der::Decode<'a> for KrbKdcReq {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        println!("Position {:?}", decoder.position());
        let _tag_as_req: ::der::Tag = der::TagNumber::N10.application(true);
        let tag: der::Tag = decoder.decode()?;
        println!("{:?}", tag);
        println!("Position {:?}", decoder.position());
        let len: der::Length = decoder.decode()?;
        println!("{:?}", len);
        println!("Position {:?}", decoder.position());

        match tag {
            _tag_as_req => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::AsReq(kdc_req))
            }
        }
    }
}

impl<'a> ::der::Encode for KrbKdcReq {
    fn encoded_len(&self) -> ::der::Result<::der::Length> {
        todo!();
    }

    fn encode(&self, encoder: &mut impl ::der::Writer) -> ::der::Result<()> {
        todo!();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct KdcProxyMessage {
    #[asn1(context_specific = "0")]
    pub kerb_message: OctetString,
    #[asn1(optional = "true", context_specific = "1")]
    pub target_domain: Option<Realm>,
    #[asn1(optional = "true", context_specific = "2")]
    pub dclocator_hint: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::BASE64_STANDARD;
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    use der::{Decode, Encode};
    use std::time::SystemTime;

    #[tokio::test]
    async fn basic_klient_to_kdc() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let _ = tracing_subscriber::fmt::try_init();

        // For now this just yeets raw bytes, we'll do a tokio codec after
        // this is ironed out.

        // Connect to the Server
        let mut stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to kdc.");

        /*
        KdcReq {
            pvno: 5,
            msg_type: 10,
            padata: Some([PaData { padata_type: 150, padata_value: OctetString { inner: [] } },
            PaData { padata_type: 149, padata_value: OctetString { inner: [] } }]),
            req_body: KdcReqBody {
                kdc_options: FlagSet(Reserved),
                cname: Some(PrincipalName { name_type: 1, name_string: [KerberosString(Ia5String("william"))] }),
                realm: KerberosString(Ia5String("KKDCP.DEV")),
                sname: Some(PrincipalName { name_type: 2, name_string: [KerberosString(Ia5String("krbtgt")), KerberosString(Ia5String("KKDCP.DEV"))] }),
                from: None,
                till: GeneralizedTime(DateTime { year: 2024, month: 4, day: 17, hour: 4, minutes: 15, seconds: 49, unix_duration: 1713327349s }),
                rtime: None,
                nonce: 2143135662,
                etype: [18, 17, 20, 19, 16, 23, 25, 26],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None
            }
        }
        */

        let till = Some(
            GeneralizedTime::from_system_time(SystemTime::now() + Duration::from_secs(3600))
                .unwrap(),
        );

        // Build an AS-REQ
        let as_req = KrbKdcReq::AsReq(KdcReq {
            pvno: 5,
            // I think it's 10 on asreq?
            msg_type: 10,
            padata: None,
            req_body: KdcReqBody {
                // No flags
                kdc_options: KerberosFlags::Reserved.into(),
                cname: Some(PrincipalName {
                    // Should be some kind of enum probably?
                    name_type: 1,
                    name_string: vec![KerberosString(Ia5String::new("testuser").unwrap())],
                }),
                realm: KerberosString(Ia5String::new("EXAMPLE.COM").unwrap()),
                sname: Some(PrincipalName {
                    name_type: 2,
                    name_string: vec![KerberosString(Ia5String::new("testuser").unwrap())],
                }),
                from: None,
                till: None,
                rtime: None,
                nonce: 12345,
                // What enc types we support, also should be an enum.
                etype: vec![18, 17, 20, 19, 16, 23, 25, 26],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        });

        let enc_len = as_req.encoded_len().unwrap();

        let mut as_req_bytes = Vec::with_capacity(enc_len + 4);

        // First four bytes are length of the AS-REQ
        let (l, d) = as_req_bytes.split_at_mut(4);

        let enc_len_bytes = u32::from(enc_len).to_be_bytes();
        l.copy_from_slice(&enc_len_bytes);

        // Remaining bytes are the AS-REQ
        as_req.encode_to_slice(d).unwrap();

        stream
            .write_all(as_req_bytes.as_slice())
            .await
            .expect("Unable to send as-req.");

        // Parse the response.

        // Read 4 bytes.
        // Then read that many more bytes.
    }

    #[test]
    fn basic_kkdcp_der_parse() {
        let _ = tracing_subscriber::fmt::try_init();

        // https://asn1.jsteel.dev/#MIHMoIG8BIG5AAAAtWqBsjCBr6EDAgEFogMCAQqjGjAYMAqhBAICAJaiAgQAMAqhBAICAJWiAgQApIGGMIGDoAcDBQAAAAAQoRQwEqADAgEBoQswCRsHd2lsbGlhbaILGwlLS0RDUC5ERVajHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUtLRENQLkRFVqURGA8yMDI0MDQxNzA0MTU0OVqnBgIEf72nrqgaMBgCARICARECARQCARMCARACARcCARkCARqhCxsJS0tEQ1AuREVW

        /*
        SEQUENCE (2 elem)
          [0] (1 elem)
            OCTET STRING (185 byte) 000000B56A81B23081AFA103020105A20302010AA31A3018300AA10402020096A2020…
          [1] (1 elem)
            GeneralString KKDCP.DEV
        */

        let sample = URL_SAFE.decode(b"MIHMoIG8BIG5AAAAtWqBsjCBr6EDAgEFogMCAQqjGjAYMAqhBAICAJaiAgQAMAqhBAICAJWiAgQApIGGMIGDoAcDBQAAAAAQoRQwEqADAgEBoQswCRsHd2lsbGlhbaILGwlLS0RDUC5ERVajHjAcoAMCAQKhFTATGwZrcmJ0Z3QbCUtLRENQLkRFVqURGA8yMDI0MDQxNzA0MTU0OVqnBgIEf72nrqgaMBgCARICARECARQCARMCARACARcCARkCARqhCxsJS0tEQ1AuREVW")
            .expect("Unable to decode sample");

        tracing::warn!(?sample);

        let kdc_proxy_message =
            KdcProxyMessage::from_der(&sample).expect("Failed to decode Kdc Proxy Message");

        tracing::warn!(?kdc_proxy_message);

        // The first 4 bytes of this are a length.

        assert!(kdc_proxy_message.kerb_message.as_bytes().len() >= 4);
        let (length, message) = kdc_proxy_message.kerb_message.as_bytes().split_at(4);

        let krb_message_b64 = URL_SAFE.encode(message);

        tracing::warn!(?krb_message_b64);

        // https://asn1.jsteel.dev/#aoGyMIGvoQMCAQWiAwIBCqMaMBgwCqEEAgIAlqICBAAwCqEEAgIAlaICBACkgYYwgYOgBwMFAAAAABChFDASoAMCAQGhCzAJGwd3aWxsaWFtogsbCUtLRENQLkRFVqMeMBygAwIBAqEVMBMbBmtyYnRndBsJS0tEQ1AuREVWpREYDzIwMjQwNDE3MDQxNTQ5WqcGAgR_vaeuqBowGAIBEgIBEQIBFAIBEwIBEAIBFwIBGQIBGg

        let as_req = KrbKdcReq::from_der(message).expect("Unable to decode as_req");
    }

    #[test]
    fn krb_kdc_req_parse() {
        let sample = b"aoGyMIGvoQMCAQWiAwIBCqMaMBgwCqEEAgIAlqICBAAwCqEEAgIAlaICBACkgYYwgYOgBwMFAAAAABChFDASoAMCAQGhCzAJGwd3aWxsaWFtogsbCUtLRENQLkRFVqMeMBygAwIBAqEVMBMbBmtyYnRndBsJS0tEQ1AuREVWpREYDzIwMjQwNDE3MDQxNTQ5WqcGAgR/vaeuqBowGAIBEgIBEQIBFAIBEwIBEAIBFwIBGQIBGg==";
        let sample = BASE64_STANDARD
            .decode(sample)
            .expect("Failed to decode sample");
        let message = KrbKdcReq::from_der(&sample).expect("Failed to decode");
        match message {
            KrbKdcReq::AsReq(asreq) => {
                info!("{:?}", asreq);
                assert_eq!(asreq.pvno, 5);
                let ref cname = &asreq.req_body.cname.as_ref().unwrap();
                assert_eq!(cname.name_type, 1);
                assert_eq!(cname.name_string[0].0.to_string(), "william");

                assert_eq!(asreq.req_body.realm.0.to_string(), "KKDCP.DEV");

                let ref sname = &asreq.req_body.sname.as_ref().unwrap();
                assert_eq!(sname.name_type, 2);
                assert_eq!(sname.name_string[0].0.to_string(), "krbtgt");
                assert_eq!(sname.name_string[1].0.to_string(), "KKDCP.DEV");
            }
        }
    }
}
