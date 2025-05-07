use super::constants::message_types::KrbMessageType;
use super::{ap_options::ApOptions, encrypted_data::EncryptedData, tagged_ticket::TaggedTicket};
use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, Tag, TagNumber};

/// ```text
/// AP-REQ          ::= [APPLICATION 14] SEQUENCE {
///            pvno            [0] INTEGER (5),
///            msg-type        [1] INTEGER (14),
///            ap-options      [2] APOptions,
///            ticket          [3] Ticket,
///            authenticator   [4] EncryptedData -- Authenticator
///    }
///```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ApReqInner {
    #[asn1(context_specific = "0")]
    pub(crate) pvno: u8,
    #[asn1(context_specific = "1")]
    pub(crate) msg_type: u8,
    #[asn1(context_specific = "2")]
    // The flags affect the way the request is processed.
    pub(crate) ap_options: ApOptions,
    #[asn1(context_specific = "3")]
    // This field is a ticket authenticating the client to the server.
    pub(crate) ticket: TaggedTicket,
    #[asn1(context_specific = "4")]
    // This contains the encrypted authenticator, which includes the client's choice of a subkey.
    pub(crate) authenticator: EncryptedData,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ApReq(ApReqInner);

impl ApReq {
    pub fn new(ap_options: ApOptions, ticket: TaggedTicket, authenticator: EncryptedData) -> Self {
        let inner = ApReqInner {
            pvno: 5,
            msg_type: KrbMessageType::KrbApReq as u8,
            ap_options,
            ticket,
            authenticator,
        };
        Self(inner)
    }
}

impl FixedTag for ApReq {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber(14),
    };
}

impl<'a> DecodeValue<'a> for ApReq {
    type Error = der::Error;

    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner: ApReqInner = ApReqInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl EncodeValue for ApReq {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(encoder)?;
        Ok(())
    }
}

impl From<ApReq> for ApReqInner {
    fn from(value: ApReq) -> ApReqInner {
        value.0
    }
}

impl AsRef<ApReqInner> for ApReq {
    fn as_ref(&self) -> &ApReqInner {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::ApReq;
    use super::ApReqInner;
    use crate::asn1::ap_options::ApOptions;
    use crate::asn1::constants::KrbMessageType;
    use der::Decode;

    struct TestApReq {
        blob: String,
        options: ApOptions,
    }

    #[test]
    fn ap_req_decode() {
        let samples: Vec<TestApReq> = vec![
            TestApReq {
                blob: "6e82053730820533a003020105a10302010ea20703050000000000a382045a6182045630820452a003020105a10c1b0a41464f524553542e4144a21f301da003020102a11630141b066b72627467741b0a41464f524553542e4144a382041a30820416a003020112a103020102a282040804820404047182f3a44f625897c7818b8cb5196127d569250ae4eae113609572e3aa228ce468402cd83d8297ace99a53859168bae937f739a5c6be86591839f4d361a9d9991ea87d1acc41e16262e12372a528c605957597fd5547da8335fff479d423dee607cb0321cda03774c7371762feb1b54b96809917f3663f9788964a5c32aa2414a1707f13fb444efc0dac0ea440f70ff6a0f6b005e48eb5204a423eda036b079ab217a3c28a1905ca239a784caa59835ce9ce3c68101bd737fad1bd0208afd142267645d5adc5fc2916e6c78b440e9542f248dc9fd19b553b26b7bca5466e9a22f8dcddd7c1a52e186663b948471c48466372cbcf5fbda9865d5171790bc5d94eb7025895dffc06144a1aae5958e979ec45bd9c16033999d847740c79134d0768c3561ee3dba6572f31686ce0d2367d2fb19cc3cfbd8848515666fab5689ac6c71ecb2892f7d6e932d42708b908c991fde2c7ed69d741755cd350e599c25cd52c2e6df1a0786ef0fe4522db3739dfdd7c87f155bd5092312047ea47932210c27e9feaaaeb64e2f2ed9a64fa0286b7497bae02b94b9595bf61819dbaf5159e126e485a7d081262726e400bce1a37d7be868bb9b37a69e813f19cd2baf8ca6783b9193f1568888f50ac3a1633daecc45087add270b79c93f58b25860eda60e986a5fae52af55e37bee4e89609a382dccd9de468e68723c745da355745ab7993f391be333a9174406e1fb73e5f6c43d57dd1dedca470ab468d737dee0c773d228711f72bdd4066d2facfb5e297eb0cbe36a3e666fe0759a21b62b0b382fc5f5b4d0b792721d75ba54f7c80e5746c7c80162ef407ed5c91365e9c7da59b8f232ad59a006b4c6be12a23b0ce3327691c979cb6091aa9c13196de3e513296d3946c72d1ecb5279fe4f8a3fb5b90aa218e95723dcade056df4e2e4a5ea93611577969848980c7895f9410c03c26043cf802d42c5f75fec61539d32a99fb31f440bfff144e70e5b236198c0b9baeb3681e43c883b1efb55d165ed593bc850352f257217377677aa5af13231b900ee8586c4bd4a26c490dde68a192e835c3dcede4e32c4e551c66bed360e49b86c976a689bbf0378259cb081b8b6ff61168ef48b18bf8d5ffca324e729d30e368d986251a3587e6ebeda15ada37bb14e9934fb6bd239c2fba489ef5605f8e9d97f21d8d1b178c4483f10e4f9e5c6b7ff6ddd511b24e5f02d9574025228770fce424c527c639545e30d4a9fe5a8c0b0b2e625e42ba81a37bc73173b4690708db8e086310c2b681e83b27e5acb0e482dec7d58b768a0b335608c11a9427a6e1ea42e293e0780808ba0ea18ca4fa665c92da73de64f2467fb2fa26e97e4d2e9d1a9d701e6ea9cc0fbf6dde52beac846d4afd9228139b486dbd14ee3e430c7b46ab554bec0f8a85c4959535755598f8942d176dd6a0a1b7acd55de57fca481bf3081bca003020112a281b40481b13d920e7f4264b8bf505dbde39eec7434d4feb7d8136ca12538364c2fce983df838d837c9ee3d58b23112fec7243ff0c9609b56709a52f06d4223558b789e082d43024444725be842761dee4fcdc4fda3bfbd3973936b7224e5f92a72736c4a073621abaaebbbf824a28408e08f2e2dfbfb7d157046aa6aeba6045e763ac62c0aaea68ea7bac1dab531bb118303e1e1e49b0eaed8412513aca6a23c74a61e545f8864b492d716459a936066bac831ef3806".to_string(),
                options: ApOptions::new(0b0).expect("Failed to build flagset")
            }
        ];

        for sample in samples {
            let blob = hex::decode(&sample.blob).expect("Failed to decode sample");
            let ap_req: ApReqInner = ApReq::from_der(&blob).expect("Failed to decode").into();

            assert_eq!(ap_req.pvno, 5);
            assert_eq!(ap_req.msg_type, KrbMessageType::KrbApReq as u8);
            assert_eq!(ap_req.ap_options, sample.options);
        }
    }
}
