use bitmask_enum::bitmask;
use der::asn1::BitStringRef;
use der::{Decode, EncodeValue, Length, Result, Tagged, Writer};

/// ```text
/// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
///                     -- minimum number of bits shall be sent,
///                     -- but no fewer than 32
/// ````
// NOTE: Can't use der::Flagset because it strips all leading zeros and RFC4120
// section 5.8.2 says at least 32 bit must be sent.
#[bitmask(u32)]
pub enum KerberosFlags {
    Reserved = 1 << 0,
    Forwardable = 1 << 1,
    Forwarded = 1 << 2,
    Proxiable = 1 << 3,
    Proxy = 1 << 4,
    AllowPostdate = 1 << 5,
    Postdated = 1 << 6,
    Unused7 = 1 << 7,
    Renewable = 1 << 8,
    Unused9 = 1 << 9,
    Unused10 = 1 << 10,
    OptHardwareAuth = 1 << 11,
    Unused12 = 1 << 12,
    Unused13 = 1 << 13,
    Unused14 = 1 << 14,
    Canonicalize = 1 << 15,
    Unused16 = 1 << 16,
    Unused17 = 1 << 17,
    Unused18 = 1 << 18,
    Unused19 = 1 << 19,
    Unused20 = 1 << 20,
    Unused21 = 1 << 21,
    Unused22 = 1 << 22,
    Unused23 = 1 << 23,
    Unused24 = 1 << 24,
    Unused25 = 1 << 25,
    // -- 26 was unused in 1510
    DisableTransitedCheck = 1 << 26,
    RenewableOk = 1 << 27,
    EncTktInSkey = 1 << 28,
    Unused29 = 1 << 29,
    Renew = 1 << 30,
    Validate = 1 << 31,
}

impl KerberosFlags {
    fn from_bits(val: u32) -> Self {
        let mut tf = KerberosFlags::none();
        tf.bits = val;
        tf
    }
}

impl<'a> Decode<'a> for KerberosFlags {
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
        Ok(KerberosFlags::from_bits(swap))
    }
}

impl Tagged for KerberosFlags {
    fn tag(&self) -> der::Tag {
        der::Tag::BitString
    }
}

impl EncodeValue for KerberosFlags {
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
