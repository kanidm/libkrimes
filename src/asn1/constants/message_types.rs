use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum KrbMessageType {
    KrbAsReq = 10,      // Request for initial authentication
    KrbAsRep = 11,      // Response to KrbAsReq request
    KrbTgsReq = 12,     // Request for authentication based on Tgt
    KrbTgsRep = 13,     // Response to KrbTgsReq request
    KrbApReq = 14,      // Application request to server
    KrbApRep = 15,      // Response to KrbApReqMutual
    KrbReserved16 = 16, // Reserved for user-to-user krb_tgt_request
    KrbReserved17 = 17, // Reserved for user-to-user krb_tgt_reply
    KrbSafe = 20,       // Safe (checksummed) application message
    KrbPriv = 21,       // Private (encrypted) application message
    KrbCred = 22,       // Private (encrypted) message to forward credentials
    KrbError = 30,      // Error response
}
