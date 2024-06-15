use tracing::*;

mod asn1;
pub mod proto;

use std::io;
use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::proto::{KerberosRequest};

const DEFAULT_MAX_SIZE: usize = 32 * 1024;

pub struct KerberosCodec {
    max_size: usize,
}

impl Default for KerberosCodec {
    fn default() -> Self {
        KerberosCodec {
            max_size: DEFAULT_MAX_SIZE
        }
    }
}


impl Decoder for KerberosCodec {
    type Item = KerberosRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // How many bytes to consume?
        todo!();
    }
}

impl Encoder<KerberosRequest> for KerberosCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: KerberosRequest, buf: &mut BytesMut) -> io::Result<()> {
        debug_assert!(buf.is_empty());

        msg.write_to(buf);

        todo!();
    }
}



#[cfg(test)]
mod tests {
    use tracing::*;
    use tokio::net::TcpStream;
    use futures::SinkExt;
    use futures::StreamExt;
    use tokio_util::codec::Framed;

    use std::time::{SystemTime, Duration};

    use crate::proto::KerberosRequest;
    use super::KerberosCodec;

    #[tokio::test]
    async fn test_localhost_kdc() {
        let _ = tracing_subscriber::fmt::try_init();

        let mut stream = TcpStream::connect("127.0.0.1:55000").await
            .expect("Unable to connect to localhost:55000");

        let mut krb_stream = Framed::new(stream, KerberosCodec::default());

        let as_req = KerberosRequest::build_asreq(
            "testuser".to_string(),
            "krbtgt".to_string(),
            SystemTime::now() + Duration::from_secs(3600)
        )
        .build();

        // Write a request
        krb_stream.send(as_req).await
            .expect("Failed to transmit request");

        // What did we get back?
        let response = krb_stream.next().await;

        trace!(?response);
    }
}



