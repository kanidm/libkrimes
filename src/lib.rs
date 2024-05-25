

use tracing::*;

use der::{
    asn1::{Any, ContextSpecific, Ia5String, Int, KerbString, OctetString},
    Decode, Encode, Sequence,
};

pub type KerbRealm = KerbString;

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct KdcProxyMessage {
    #[asn1(context_specific = "0")]
    pub kerb_message: OctetString,
    #[asn1(optional = "true", context_specific = "1")]
    pub target_domain: Option<KerbRealm>,
    #[asn1(optional = "true", context_specific = "2")]
    pub dclocator_hint: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdcReq {
    pub pvno: Int,
}

impl<'a> ::der::Decode<'a> for KdcReq {
    fn decode<R: ::der::Reader<'a>>(reader: &mut R) -> ::der::Result<Self> {
        let tag_pvno: der::Tag = der::TagNumber::N1.context_specific(false);
        warn!(?tag_pvno);

        let tag: der::Tag = reader.peek_tag()?;
        warn!(?tag);

        let pvno = reader
            .context_specific(der::TagNumber::new(1), der::TagMode::Explicit)?
            .ok_or_else(|| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))?;

        Ok(KdcReq { pvno })
    }
}

impl<'a> ::der::EncodeValue for KdcReq {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        todo!();
    }

    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        todo!();
    }
}

pub enum KerbMessage {
    AsReq(KdcReq),
    // TgsReq(KdcReq),
}

impl<'a> ::der::Decode<'a> for KerbMessage {
    fn decode<R: ::der::Reader<'a>>(reader: &mut R) -> ::der::Result<Self> {
        let tag_as_req: der::Tag = der::TagNumber::N10.application(true);

        // Check the tag.
        // let tag: der::Tag = reader.peek_tag()?;
        let tag: der::Tag = reader.decode()?;
        warn!(?tag);

        assert_eq!(tag, tag_as_req);

        match tag {
            tag_as_req => {
                let kdc_req: KdcReq = reader.decode()?;
                Ok(KerbMessage::AsReq(kdc_req))
            }
            _ => unimplemented!(),
        }
    }
}

impl<'a> ::der::EncodeValue for KerbMessage {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        todo!();
    }

    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        todo!();
    }
}


// TODO: https://github.com/RustCrypto/formats/issues/1385#issuecomment-2063924028


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn basic_klient_to_kdc() {
        use tokio::net::TcpStream;
        use tokio::io::AsyncWriteExt;

        let _ = tracing_subscriber::fmt::try_init();

        // For now this just yeets raw bytes, we'll do a tokio codec after
        // this is ironed out.

        // Connect to the Server
        let mut stream = TcpStream::connect("127.0.0.1:55000").await
            .expect("Unable to connect to kdc.");

        // Build an AS-REQ
        let as_req = 

        // First four bytes are length of the AS-REQ

        // Remaining bytes are the AS-REQ

        stream.write_all(b"hello world!").await
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

        /*
        Application 10 (1 elem)
          SEQUENCE (4 elem)
            [1] (1 elem)
              INTEGER 5
            [2] (1 elem)
              INTEGER 10
            [3] (1 elem)
              SEQUENCE (2 elem)
                SEQUENCE (2 elem)
                  [1] (1 elem)
                    INTEGER 150
                  [2] (1 elem)
                    OCTET STRING (0 byte)
                SEQUENCE (2 elem)
                  [1] (1 elem)
                    INTEGER 149
                  [2] (1 elem)
                    OCTET STRING (0 byte)
            [4] (1 elem)
              SEQUENCE (7 elem)
                [0] (1 elem)
                  BIT STRING (32 bit) 00000000000000000000000000010000
                [1] (1 elem)
                  SEQUENCE (2 elem)
                    [0] (1 elem)
                      INTEGER 1
                    [1] (1 elem)
                      SEQUENCE (1 elem)
                        GeneralString william
                [2] (1 elem)
                  GeneralString KKDCP.DEV
                [3] (1 elem)
                  SEQUENCE (2 elem)
                    [0] (1 elem)
                      INTEGER 2
                    [1] (1 elem)
                      SEQUENCE (2 elem)
                        GeneralString krbtgt
                        GeneralString KKDCP.DEV
                [5] (1 elem)
                  GeneralizedTime 2024-04-17 04:15:49 UTC
                [7] (1 elem)
                  INTEGER 2143135662
                [8] (1 elem)
                  SEQUENCE (8 elem)
                    INTEGER 18
                    INTEGER 17
                    INTEGER 20
                    INTEGER 19
                    INTEGER 16
                    INTEGER 23
                    INTEGER 25
                    INTEGER 26
            */

        // How to pop a tag off?

        let as_req = KerbMessage::from_der(message).expect("Unable to decode as_req");
    }

}
