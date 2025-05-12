use bitmask_enum::bitmask;
use der::asn1::BitStringRef;
use der::{Decode, EncodeValue, Length, Result, Tagged, Writer};

/// ```text
/// TicketFlags     ::= KerberosFlags
///         -- reserved(0),
///         -- forwardable(1),
///         -- forwarded(2),
///         -- proxiable(3),
///         -- proxy(4),
///         -- may-postdate(5),
///         -- postdated(6),
///         -- invalid(7),
///         -- renewable(8),
///         -- initial(9),
///         -- pre-authent(10),
///         -- hw-authent(11),
///         -- transited-policy-checked(12),
///         -- ok-as-delegate(13)
/// ````
// NOTE: Can't use der::Flagset because it strips all leading zeros and RFC4120
// section 5.8.2 says at least 32 bit must be sent.
#[bitmask(u32)]
pub enum TicketFlags {
    Reserved = 1 << 0,
    Forwardable = 1 << 1,
    Forwarded = 1 << 2,
    Proxiable = 1 << 3,
    Proxy = 1 << 4,
    MayPostdate = 1 << 5,
    Postdated = 1 << 6,
    Invalid = 1 << 7,
    Renewable = 1 << 8,
    Initial = 1 << 9,
    PreAuthent = 1 << 10,
    HwAuthent = 1 << 11,
    TransitedPolicyChecked = 1 << 12,
    OkAsDelegate = 1 << 13,
    Test = 1 << 31,
}

impl TicketFlags {
    fn from_bits(val: u32) -> Self {
        let mut tf = TicketFlags::none();
        tf.bits = val;
        tf
    }
}

impl<'a> Decode<'a> for TicketFlags {
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
        Ok(TicketFlags::from_bits(swap))
    }
}

impl Tagged for TicketFlags {
    fn tag(&self) -> der::Tag {
        der::Tag::BitString
    }
}

impl EncodeValue for TicketFlags {
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

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[test]
    fn ticket_flags_min_encoded_length() {
        let flags = TicketFlags::none();
        let der_bytes = flags.to_der().expect("Failed to encode");
        assert_eq!(der_bytes.len(), 7);
        assert_eq!(der_bytes, [0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let flags = TicketFlags::Renewable;
        let der_bytes = flags.to_der().expect("Failed to encode");
        assert_eq!(der_bytes.len(), 7);
        assert_eq!(der_bytes, [0x03, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00]);

        let mut flags = TicketFlags::none();
        flags |= TicketFlags::OkAsDelegate;
        flags |= TicketFlags::Renewable;
        flags |= TicketFlags::Forwardable;
        let der_bytes = flags.to_der().expect("Failed to encode");
        assert_eq!(der_bytes.len(), 7);
        assert_eq!(der_bytes, [0x03, 0x05, 0x00, 0x40, 0x84, 0x00, 0x00]);

        let flags = TicketFlags::from_der(&der_bytes).expect("Failed to decode");
        assert_eq!(
            flags,
            TicketFlags::OkAsDelegate | TicketFlags::Renewable | TicketFlags::Forwardable
        );
        assert!(flags.contains(TicketFlags::Renewable));
        assert!(flags.contains(TicketFlags::OkAsDelegate));
        assert!(flags.contains(TicketFlags::Forwardable));
    }
}
