use bitmask_enum::bitmask;
use der::asn1::BitStringRef;
use der::{Decode, EncodeValue, Length, Result, Tagged, Writer};
use serde::{Deserialize, Serialize};
use std::fmt;

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
    EncPaRep = 1 << 15,
    Test = 1 << 31,
}
impl fmt::Display for TicketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut str_flags: Vec<String> = vec![];
        let mut flags = *self;
        if flags.contains(TicketFlags::Reserved) {
            str_flags.push("Reserved".to_string());
            flags &= TicketFlags::Reserved.not();
        }
        if flags.contains(TicketFlags::Forwardable) {
            str_flags.push("Forwardable".to_string());
            flags &= TicketFlags::Forwardable.not();
        }
        if flags.contains(TicketFlags::Forwarded) {
            str_flags.push("Forwarded".to_string());
            flags &= TicketFlags::Forwarded.not();
        }
        if flags.contains(TicketFlags::Proxiable) {
            str_flags.push("Proxiable".to_string());
            flags &= TicketFlags::Proxiable.not();
        }
        if flags.contains(TicketFlags::Proxy) {
            str_flags.push("Proxy".to_string());
            flags &= TicketFlags::Proxy.not();
        }
        if flags.contains(TicketFlags::MayPostdate) {
            str_flags.push("MayPostdate".to_string());
            flags &= TicketFlags::MayPostdate.not();
        }
        if flags.contains(TicketFlags::Postdated) {
            str_flags.push("Postdated".to_string());
            flags &= TicketFlags::Postdated.not();
        }
        if flags.contains(TicketFlags::Invalid) {
            str_flags.push("Invalid".to_string());
            flags &= TicketFlags::Invalid.not();
        }
        if flags.contains(TicketFlags::Renewable) {
            str_flags.push("Renewable".to_string());
            flags &= TicketFlags::Renewable.not();
        }
        if flags.contains(TicketFlags::Initial) {
            str_flags.push("Initial".to_string());
            flags &= TicketFlags::Initial.not();
        }
        if flags.contains(TicketFlags::PreAuthent) {
            str_flags.push("PreAuthent".to_string());
            flags &= TicketFlags::PreAuthent.not();
        }
        if flags.contains(TicketFlags::HwAuthent) {
            str_flags.push("HwAuthent".to_string());
            flags &= TicketFlags::HwAuthent.not();
        }
        if flags.contains(TicketFlags::TransitedPolicyChecked) {
            str_flags.push("TransitedPolicyChecked".to_string());
            flags &= TicketFlags::TransitedPolicyChecked.not();
        }
        if flags.contains(TicketFlags::OkAsDelegate) {
            str_flags.push("OkAsDelegate".to_string());
            flags &= TicketFlags::OkAsDelegate.not();
        }
        if flags.contains(TicketFlags::EncPaRep) {
            str_flags.push("EncPaRep".to_string());
            flags &= TicketFlags::EncPaRep.not();
        }
        if flags.contains(TicketFlags::Test) {
            str_flags.push("Test".to_string());
            flags &= TicketFlags::Test.not();
        }
        if flags.bits != 0 {
            str_flags.push(format!("(unknown bits 0x{:08X})", flags.bits));
        }
        if str_flags.is_empty() {
            write!(f, "<empty>")?;
        } else {
            write!(f, "{}", str_flags.join(" | "))?;
        }
        Ok(())
    }
}

impl TicketFlags {
    pub fn from_bits(bits: u32) -> Self {
        let mut swap = 0u32;
        for i in 0..32 {
            let on = bits & (1 << i);
            swap |= on >> i << (32 - i - 1);
        }

        let mut tf = TicketFlags::none();
        tf.bits = swap;
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
        Ok(TicketFlags::from_bits(bits))
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

impl Serialize for TicketFlags {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for TicketFlags {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(Self::from_bits(bits))
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
