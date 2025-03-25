use super::encrypted_data::EncryptedData;
use super::pa_data::PaData;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use super::tagged_ticket::TaggedTicket;
use der::Sequence;

/// ```text
///   KDC-REP         ::= SEQUENCE {
///           pvno            [0] INTEGER (5),
///           msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///           padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                   -- NOTE: not empty --,
///           crealm          [3] Realm,
///           cname           [4] PrincipalName,
///           ticket          [5] Ticket,
///           enc-part        [6] EncryptedData
///                                   -- EncASRepPart or EncTGSRepPart,
///                                   -- as appropriate
///   }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct KdcRep {
    #[asn1(context_specific = "0")]
    pub(crate) pvno: u8,
    #[asn1(context_specific = "1")]
    pub(crate) msg_type: u8,
    #[asn1(context_specific = "2", optional = "true")]
    pub(crate) padata: Option<Vec<PaData>>,
    #[asn1(context_specific = "3")]
    pub(crate) crealm: Realm,
    #[asn1(context_specific = "4")]
    pub(crate) cname: PrincipalName,
    #[asn1(context_specific = "5")]
    pub(crate) ticket: TaggedTicket,
    #[asn1(context_specific = "6")]
    pub(crate) enc_part: EncryptedData,
}

#[cfg(test)]
mod tests {
    use crate::asn1::krb_kdc_rep::KrbKdcRep;
    use der::Decode;
    use tracing::*;

    #[test]
    fn krb_kdc_rep_parse() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "6b8203513082034da003020105a10302010ba22d302b3029a103020113a2220420301e301ca003020112a1151b134558414d504c452e434f4d7465737475736572a30d1b0b4558414d504c452e434f4da4153013a003020101a10c300a1b087465737475736572a58201ba618201b6308201b2a003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da382017830820174a003020112a103020101a282016604820162eac20712018638db059fc4580cb6aad87fbc722c85219b83574df7a6cee9ee5f6d83569c8ddfcd0695bd9ec215540200f905ec11f91353d6724be7fbfe9444606d39b4d85e4ae084a72a14a0f652a922da109e652b68dae1a519d2c2087b07c7d8f738738fe2276ead3c31d83bd3f8cbcc6c6ca8b5133a1cca5f09bfb45489fca80cecfc754d13f93418dc6385475400795d7f06f8ae9a146e21eeccd10f2efaa0bf1d3acde3f8d1c71cb7a555eedb1ce333a32941141c8ed7552a31df706d11be06b21c02178d2ac8bbed10964ff67b0b06e7f56f1c2422be26ac862521bf1be90b3977975a3346f2d2404342bf53b9c45d83a56c45fef0a7386ed82ffc0c4b23e10e9cb51ab18076d8fe9fc3d66d0ad9cd44764f2af929a181fe008d99de0acc44d689874ad433f1b04d129c2bb65f3070aa7c0343d9b07a44c9d031f950119f90744ff0085b0f4c08b29b281d376525736f9dd292eec03c16d2f5a681eb24bb56a682012c30820128a003020112a282011f0482011b602fe69bf3c949b575e0303ebec6975c3921b38a7479c16e68fd18d18972e670296ce1f6d005df8f423f44f9f8efcaafc8a148a141f706ddd24a2ded22f85b85c41ffe6168ba887a85f3b514e4f670818bf0f402c245cd167ef5136a72edd19e0536d0ea1863e27a227dd7207aa0d1c3d13526936636574f604bb57492feb534c1d8b15610bcce035a4de2d259103f9e63968f8b4e3f8b1e7120ef31bd390344bfabacf657ff062c8a50f12ffdf045df03d98bbc5f324b7a7eb48e4e656ceb5ee1325a394de51bb7617d6db4cda242c0aba97612dcf23816e08ca41bea80f4b2dc144422ed832c2395b61fdd9437f08fd2a3a1dd2475d61d61a102d1a38292afaded12f26318a6550328f60addb0542ac8e287d7a1c96f3593ca04";
        let blob = hex::decode(data).expect("Failed to decode sample");
        let message = KrbKdcRep::from_der(&blob).expect("Failed to decode");
        trace!(?message);

        match message {
            KrbKdcRep::AsRep(asrep) => trace!(?asrep),
            KrbKdcRep::TgsRep(_) | KrbKdcRep::ErrRep(_) => todo!(),
        }
    }
}
