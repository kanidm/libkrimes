use bitmask_enum::bitmask;
use der::asn1::BitStringRef;
use der::{Decode, EncodeValue, Length, Result, Tagged, Writer};

// NOTE: Can't use der::Flagset because it strips all leading zeros and RFC4120
// section 5.8.2 says at least 32 bit must be sent.
#[bitmask(u32)]
pub enum ApFlags {
    Reserved = 1 << 0,
    // The USE-SESSION-KEY option indicates that the ticket the client is
    // presenting to a server is encrypted in the session key from the
    // server's TGT.  When this option is not specified, the ticket is
    // encrypted in the server's secret key.
    UseSessionKey = 1 << 1,
    // The MUTUAL-REQUIRED option tells the server that the client requires
    // mutual authentication, and that it must respond with a KRB_AP_REP
    // message.
    MutualRequired = 1 << 2,
}

pub type ApOptions = ApFlags;

impl ApFlags {
    fn from_bits(val: u32) -> Self {
        let mut tf = ApFlags::none();
        tf.bits = val;
        tf
    }
}

impl<'a> Decode<'a> for ApFlags {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> Result<Self> {
        let bs = BitStringRef::decode(decoder)?;
        let bytes: [u8; 4] = bs.raw_bytes().try_into().map_err(|_| {
            der::Error::new(
                der::ErrorKind::Incomplete {
                    expected_len: Length::new(4),
                    actual_len: decoder.position(),
                },
                decoder.position(),
            )
        })?;
        let bits = u32::from_be_bytes(bytes);
        let mut swap = 0u32;
        for i in 0..32 {
            let on = bits & (1 << i);
            swap |= on >> i << (32 - i - 1);
        }
        Ok(ApFlags::from_bits(swap))
    }
}

impl Tagged for ApFlags {
    fn tag(&self) -> der::Tag {
        der::Tag::BitString
    }
}

impl EncodeValue for ApFlags {
    fn value_len(&self) -> Result<Length> {
        let bits = self.bits();
        let buff = &bits.to_be_bytes();
        let bs = BitStringRef::from_bytes(buff)?;
        bs.value_len()
    }
    fn encode_value(&self, encoder: &mut impl Writer) -> Result<()> {
        let bits = self.bits();
        let mut reversed = 0u32;
        for i in 0..32 {
            let on = bits & (1 << i);
            reversed |= on >> i << (32 - i - 1);
        }
        let buff = &reversed.to_be_bytes();
        let bs = BitStringRef::from_bytes(buff)?;
        bs.encode_value(encoder)
    }
}
