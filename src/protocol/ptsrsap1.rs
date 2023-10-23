use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType};
use crate::protocol::*;

use rsa::RsaPublicKey;

use serde::{Deserialize, Serialize};

use pretzel::{
    generate_secret_shares, generate_verification, key_gen, PublicPackage, RSAThresholdPrivateKey,
    RsaSecretShare, SecretPackage,
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
}

// FIXME Align the KeygenRound in such a way that it fits the dealer-receiver
#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum KeygenRound {
    R0,
    // NOTE:The Options here are required for the trusted dealer setup.
    //       The dealer saves the information while the rest waits for the next
    //       round to receive it.
    R1(Option<u16>, Option<SecretPackage>, Option<PublicPackage>),
    // A this point everyone has access to the data.
    Done(SecretPackage, PublicPackage),
}

impl KeygenContext {
    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolGroupInit::decode(data)?;

        if msg.protocol_type != ProtocolType::Ptsrsap1 as i32 {
            return Err("wrong protocol type".into());
        }

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let mut msgs: Vec<Vec<u8>> = serialize_bcast(
            &(None::<u16>, None::<SecretPackage>, None::<PublicPackage>),
            (parties - 1) as usize,
        )?;
        // The 0th party is implicitly the dealer
        // TODO: Make it so that the dealer can be chosen by the user?
        if index == 0 {
            let mut share_data = vec![];
            // TODO do the dealing
            // FIXME change the key_size to 2048
            let sk = key_gen(32, parties.into(), threshold.into()).unwrap();
            let shares = generate_secret_shares(&sk, parties.into(), threshold.into());
            let (v, vks) = generate_verification(&sk.get_public(), shares.clone());

            let public_pkg = PublicPackage {
                v: v,
                verification_keys: vks,
                public_key: RsaPublicKey::from(sk),
            };
            for (i, share) in shares.iter().enumerate() {
                if i != (index as usize) {
                    // Each party receives their share and the verification base value `v` and the
                    // verification keys
                    let secret_pkg = SecretPackage {
                        uid: i,
                        gid: None,
                        share: share.clone(),
                    };
                    share_data.push((Some(index), secret_pkg, &public_pkg));
                    // share_data.push(&public_pkg);
                }
            }
            msgs = serialize_uni(share_data)?;
            self.round = KeygenRound::R1(
                Some(index),
                Some(SecretPackage {
                    uid: index as usize,
                    // The server cannot have the gid available at this point
                    gid: None,
                    share: shares[0].clone(),
                }),
                Some(public_pkg),
            );
        } else {
            self.round = KeygenRound::R1(Some(index), None, None);
        }
        Ok(pack(msgs, ProtocolType::Ptsrsap1))
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let (c, msgs) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),

            // This is the dealer case that already has its values generated.
            KeygenRound::R1(Some(id), Some(secret_pkg), Some(public_pkg)) => {
                let no_msgs: Vec<u8> = vec![0u8; 32];
                // assert_eq!(*id, 0u16);
                (
                    KeygenRound::Done(secret_pkg.clone(), public_pkg.clone()),
                    serialize_uni(no_msgs)?,
                )
            }

            // Those are the other parties
            KeygenRound::R1(Some(id), None, None) => {
                let data: Vec<(Option<u16>, Option<SecretPackage>, Option<PublicPackage>)> =
                    deserialize_vec(&unpack(data)?)?;
                let (Some(id_rcv), Some(spkg), Some(ppkg)) = &data[0] else {
                    todo!()
                };
                (
                    KeygenRound::Done(spkg.clone(), ppkg.clone()),
                    serialize_uni(vec![0u8; 32])?,
                )
            }

            // Those are the missing combinations, which are all unexpected
            KeygenRound::R1(_, _, _) => {
                panic!("Ended in an unexpected KeygenRound::R1, nor dealer or other party.");
            }

            KeygenRound::Done(_, _) => return Err("protocol already finished".into()),
        };
        self.round = c;

        Ok(pack(msgs, ProtocolType::Ptsrsap1))
    }
}

#[typetag::serde(name = "ptsrsap1_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }?;
        Ok(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        // let sp = SecretPackage {};
        match self.round {
            KeygenRound::Done(secret_pkg, public_pkg) => {
                Ok(serde_json::to_vec(&(secret_pkg, public_pkg))?)
            }
            _ => Err("protocol not finished".into()),
        }
    }
}

impl KeygenProtocol for KeygenContext {
    fn new() -> Self {
        Self {
            round: KeygenRound::R0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::KeygenProtocolTest;
    use itertools::Itertools;
    use serde::{Deserialize, Serialize};
    use std::iter::zip;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Ptsrsap1;
        const ROUNDS: usize = 2;
        // NOTE this index is suuper important!
        const INDEX_OFFSET: u32 = 0;
    }

    #[test]
    fn that_each_party_ends_up_with_the_same_public_and_unique_secret_material() {
        let max_parties = 10;

        for threshold in 2..=max_parties {
            for parties in threshold..=max_parties {
                let (_, last_rounds) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);

                let results: Vec<(SecretPackage, PublicPackage)> =
                    deserialize_vec(&last_rounds).unwrap();

                let (_, dealer_public): (SecretPackage, PublicPackage) = match results.first() {
                    None => panic!("the first value (the dealer) is always expected"),
                    Some((x, y)) => (x.clone(), y.clone()),
                };

                // assert parties share the public material
                assert!(results
                    .clone()
                    .into_iter()
                    .skip(1)
                    .all(|(_, party_public)| party_public == dealer_public));

                for i in 0..results.len() - 1 {
                    for j in i + 1..results.len() {
                        // assert everyone has unique secret material
                        assert_ne!(results[i].0, results[j].0);
                    }
                }
            }
        }
    }
}
