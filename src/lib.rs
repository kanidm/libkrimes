#![deny(warnings)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

pub mod asn1;
pub mod ccache;
pub(crate) mod constants;
pub(crate) mod crypto;
pub mod error;
pub mod keytab;
pub mod proto;

use bytes::Buf;
use bytes::BytesMut;
use der::{Decode, Encode};
use proto::{KerberosReply, KerberosRequest};
use std::io::{self, Read};
use tokio_util::codec::{Decoder, Encoder};

use crate::asn1::{krb_kdc_rep::KrbKdcRep, krb_kdc_req::KrbKdcReq};

use crate::constants::DEFAULT_IO_MAX_SIZE;

pub struct KdcTcpCodec {
    max_size: usize,
}

pub struct KerberosTcpCodec {
    max_size: usize,
}

impl Default for KerberosTcpCodec {
    fn default() -> Self {
        KerberosTcpCodec {
            max_size: DEFAULT_IO_MAX_SIZE,
        }
    }
}

impl Decoder for KerberosTcpCodec {
    type Item = KerberosReply;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() > self.max_size {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "request limit",
            ));
        }

        let mut reader = buf.reader();
        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.
        let mut xdr_hdr: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        let nread = reader.read(&mut xdr_hdr)?;
        if nread == 0 {
            // Connection closed
            return Ok(None);
        }

        // Reset end-of-record flag before parsing header into record length
        xdr_hdr[0] &= 0xEF;

        let xdr_record_len = u32::from_be_bytes(xdr_hdr);
        let mut xdr_record_buf = vec![0; xdr_record_len as usize];
        reader.read_exact(&mut xdr_record_buf)?;

        let krb_kdc_rep = KrbKdcRep::from_der(&xdr_record_buf)
            .map_err(|x| io::Error::new(io::ErrorKind::InvalidData, x.to_string()))
            .expect("Failed to decode");

        buf.clear();

        KerberosReply::try_from(krb_kdc_rep)
            .map(Some)
            .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "Data"))
    }
}

impl Encoder<KerberosRequest> for KerberosTcpCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: KerberosRequest, buf: &mut BytesMut) -> io::Result<()> {
        let req: KrbKdcReq = msg.try_into().unwrap();

        let der_bytes = req
            .to_der()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.
        let d_len = der_bytes.len() as u32;
        let xdr_hdr: [u8; 4] = d_len.to_be_bytes();

        buf.clear();
        buf.extend_from_slice(&xdr_hdr);
        buf.extend_from_slice(&der_bytes);

        Ok(())
    }
}

impl Default for KdcTcpCodec {
    fn default() -> Self {
        KdcTcpCodec {
            max_size: DEFAULT_IO_MAX_SIZE,
        }
    }
}

impl Decoder for KdcTcpCodec {
    type Item = KerberosRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() > self.max_size {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "request limit",
            ));
        }

        let mut reader = buf.reader();

        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.
        let mut xdr_hdr: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        let nread = reader.read(&mut xdr_hdr)?;
        if nread == 0 {
            // Connection closed
            return Ok(None);
        }

        // Reset end-of-record flag before parsing header into record length
        xdr_hdr[0] &= 0xEF;

        let xdr_record_len = u32::from_be_bytes(xdr_hdr);
        let mut xdr_record_buf = vec![0; xdr_record_len as usize];
        reader.read_exact(&mut xdr_record_buf)?;

        let krb_kdc_req = KrbKdcReq::from_der(&xdr_record_buf)
            .map_err(|x| io::Error::new(io::ErrorKind::InvalidData, x.to_string()))
            .expect("Failed to decode");

        buf.clear();

        KerberosRequest::try_from(krb_kdc_req)
            .map(Some)
            .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "Data"))
    }
}

impl Encoder<KerberosReply> for KdcTcpCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: KerberosReply, buf: &mut BytesMut) -> io::Result<()> {
        let krb_kdc_rep: KrbKdcRep = msg.try_into().unwrap();
        let der_bytes = krb_kdc_rep
            .to_der()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        // XDR record marking (RFC1831):
        //   A record is composed of one or more fragments. Each fragment has a 32 bit
        //   header where the leftmost bit is a boolean indicating if this is the last
        //   fragment of a record, and next 31 bits are the length of the fragment.
        //
        //   MIT does not set the end-of-record flag, assumes that a KRB PDU fits in a
        //   fragment, i.e, its length is always less that (2**31)-1.

        let d_len = der_bytes.len() as u32;
        let xdr_hdr: [u8; 4] = d_len.to_be_bytes();

        buf.clear();
        buf.extend_from_slice(&xdr_hdr);
        buf.extend_from_slice(&der_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::KerberosReply;
    use futures::SinkExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::Framed;

    use std::time::{Duration, SystemTime};

    use super::KerberosTcpCodec;
    use crate::proto::{AuthenticationReply, DerivedKey, KerberosRequest, Name, PreauthReply};
    use futures::StreamExt;
    use tracing::trace;

    #[tokio::test]
    async fn test_localhost_kdc_no_preauth() {
        let _ = tracing_subscriber::fmt::try_init();

        let stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let now = SystemTime::now();
        let client_name = Name::principal("testuser", "EXAMPLE.COM");
        let as_req = KerberosRequest::build_as(
            &client_name,
            Name::service_krbtgt("EXAMPLE.COM"),
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .build();

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream.next().await;

        let (ticket, cleartext) = match response {
            Some(Ok(KerberosReply::AS(AuthenticationReply {
                name,
                enc_part,
                pa_data,
                ticket,
            }))) => {
                assert_eq!(name, client_name);

                let etype_info = pa_data
                    .as_ref()
                    .map(|pa_inner| pa_inner.etype_info2.as_slice());

                let base_key = DerivedKey::from_encrypted_reply(
                    &enc_part,
                    etype_info,
                    "EXAMPLE.COM",
                    "testuser",
                    "password",
                )
                .expect("Failed to derive base key");

                (
                    ticket,
                    enc_part
                        .decrypt_enc_kdc_rep(&base_key)
                        .expect("Failed to decrypt"),
                )
            }
            _ => unreachable!(),
        };

        // MIT expects UDP over TCP...
        let stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let session_key = cleartext.key;

        let now = SystemTime::now();
        let tgs_req = KerberosRequest::build_tgs(
            Name::service("host", "pepper.example.com", "EXAMPLE.COM"),
            now,
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .preauth_ap_req(&client_name, &ticket, &session_key)
        .expect("Failed to build PREAUTH-AP-REQ")
        .build()
        .expect("Failed to build AP-REQ");

        krb_stream
            .send(tgs_req)
            .await
            .expect("Failed to transmit request");
        let response = krb_stream.next().await;
        let _cleartext = match response {
            Some(Ok(KerberosReply::TGS(_))) => {}
            _ => unreachable!(),
        };
    }

    #[tokio::test]
    async fn test_localhost_kdc_preauth() {
        let _ = tracing_subscriber::fmt::try_init();

        let stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        let now = SystemTime::now();

        let client_name = Name::principal("testuser_preauth", "EXAMPLE.COM");
        let as_req = KerberosRequest::build_as(
            &client_name,
            Name::service_krbtgt("EXAMPLE.COM"),
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .build();

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream.next().await;

        trace!(?response);
        assert!(response.is_some());
        let response = response.unwrap();
        assert!(response.is_ok());
        let response = response.unwrap();

        let (_service, pa_data) = match response {
            KerberosReply::PA(PreauthReply {
                service,
                pa_data,
                stime: _,
            }) => (service, pa_data),
            _ => unreachable!(),
        };

        // The PA-ENC-TIMESTAMP method MUST be supported by
        // clients, but whether it is enabled by default MAY be determined on
        // a realm-by-realm basis.
        // If the method is not used in the initial request and the error
        // KDC_ERR_PREAUTH_REQUIRED is returned specifying PA-ENC-TIMESTAMP
        // as an acceptable method, the client SHOULD retry the initial
        // request using the PA-ENC-TIMESTAMP pre- authentication method.
        //
        // The ETYPE-INFO2 method MUST be supported; this method is used to
        // communicate the set of supported encryption types, and
        // corresponding salt and string to key parameters.

        // Assert returned preauth data contains PA-ENC-TIMESTAMP and PA-ETYPE-INFO2
        assert!(pa_data.enc_timestamp);

        // Assert returned preauth data contains PA-ETYPE-INFO2
        assert!(!pa_data.etype_info2.is_empty());

        // This gets the highest encryption strength item.
        let einfo2 = pa_data.etype_info2.last().unwrap();

        // Compute the pre-authentication.
        let base_key =
            DerivedKey::from_etype_info2(einfo2, "EXAMPLE.COM", "testuser_preauth", "password")
                .expect("Failed to derive user key");

        let now = SystemTime::now();
        let seconds_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let client_name = Name::principal("testuser_preauth", "EXAMPLE.COM");
        let as_req = KerberosRequest::build_as(
            &client_name,
            Name::service_krbtgt("EXAMPLE.COM"),
            now + Duration::from_secs(3600),
        )
        .renew_until(Some(now + Duration::from_secs(86400 * 7)))
        .preauth_enc_ts(&pa_data, seconds_since_epoch, &base_key)
        .map(|b| b.build())
        .expect("Unable to build as req");

        /*
        let pre_auth = pa_rep
            .perform_enc_timestamp(
                password,
                "EXAMPLE.COM",
                "testuser_preauth",
                seconds_since_epoch,
            )
            .unwrap();

        let as_req = KerberosRequest::build_asreq(
            Name::principal("testuser_preauth", "EXAMPLE.COM"),
            Name::service_krbtgt("EXAMPLE.COM"),
            None,
            now + Duration::from_secs(3600),
            Some(now + Duration::from_secs(86400 * 7)),
        )
        .add_preauthentication(pre_auth)
        .build();
        */

        // Now, because MIT KRB is *silly* we have to re-open the connection. Because apparently
        // the MIT KRB TCP transport is just "lets pretend to be UDP with with TCP" instead of
        // doing something sensible. I can only imagine that KKDCP also does similar ... sillyness.

        let stream = TcpStream::connect("127.0.0.1:55000")
            .await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

        // Write a request
        krb_stream
            .send(as_req)
            .await
            .expect("Failed to transmit request");

        let response = krb_stream.next().await.unwrap().unwrap();

        trace!(?response);
        assert!(matches!(response, KerberosReply::AS(_)));
    }
}
