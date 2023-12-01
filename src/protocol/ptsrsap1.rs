use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType};
use crate::protocol::*;
use num_bigint::*;
use pretzel::*;
use rayon::prelude::*;
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub struct GroupParams {
    min_signers: u16,
    max_signers: u16,
    signer_idx: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeygenContext {
    round: KeygenRound,
}

// FIXME Align the KeygenRound in such a way that it fits the dealer-receiver
#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum KeygenRound {
    R0,
    // NOTE:The Options here are required for the trusted dealer setup.
    //       The dealer saves the information while the rest waits for the next
    //       round to receive it.
    // TODO the GroupParams are not optional, all parties have them
    R1(
        Option<GroupParams>,
        Option<SecretPackage>,
        Option<PublicPackage>,
    ),
    // A this point everyone has access to the data.
    Done(GroupParams, SecretPackage, PublicPackage),
}

// TODO add logging

impl KeygenContext {
    fn init(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let msg = ProtocolGroupInit::decode(data)?;

        if msg.protocol_type != ProtocolType::Ptsrsap1 as i32 {
            return Err("wrong protocol type".into());
        }

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let group_params = GroupParams {
            max_signers: parties,
            min_signers: threshold,
            signer_idx: index,
        };

        let mut msgs: Vec<Vec<u8>> = serialize_bcast(
            &(
                None::<GroupParams>,
                None::<SecretPackage>,
                None::<PublicPackage>,
            ),
            (group_params.max_signers - 1) as usize,
        )?;
        // The 0th party is implicitly the dealer
        // TODO: Make it so that the dealer can be chosen by the user?
        if index == 0 {
            let mut share_data = vec![];
            // TODO Use generate_with_dealer:
            // TODO generate_with_dealer gives indices already, there might be a conflict
            // FIXME change the key_size to 2048
            // save_key(&sk);
            let sk = match cfg!(test) {
                true => load_key().unwrap(),
                false => key_gen(2048, parties.into(), threshold.into()).unwrap(),
            };
            let shares = generate_secret_shares(&sk, parties.into(), threshold.into());
            let (v, vks) = generate_verification(&RSAThresholdPublicKey::from(&sk), shares.clone());

            let public_pkg = PublicPackage {
                v: v,
                verification_keys: vks,
                public_key: RsaPublicKey::from(sk),
                group_size: parties as usize,
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
                    share_data.push((Some(group_params), secret_pkg, &public_pkg));
                }
            }
            msgs = serialize_uni(share_data)?;
            self.round = KeygenRound::R1(
                Some(group_params),
                Some(SecretPackage {
                    uid: group_params.signer_idx as usize,
                    // The server cannot have the gid available at this point
                    gid: None,
                    share: shares[0].clone(),
                }),
                Some(public_pkg),
            );
        } else {
            self.round = KeygenRound::R1(Some(group_params), None, None);
        }
        Ok((pack(msgs, ProtocolType::Ptsrsap1), Recipient::Server))
    }

    fn update(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let (c, msgs) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),

            // This is the dealer case that already has its values generated, so the values are
            // only passed to the Done state.
            KeygenRound::R1(Some(group_params), Some(secret_pkg), Some(public_pkg)) => {
                let msgs = inflate(
                    public_pkg.public_key.to_pkcs1_der().unwrap().to_vec(),
                    (group_params.max_signers - 1) as usize,
                );
                (
                    KeygenRound::Done(*group_params, secret_pkg.clone(), public_pkg.clone()),
                    msgs,
                )
            }

            // Those are the other parties
            KeygenRound::R1(Some(group_params), None, None) => {
                let data: Vec<(
                    Option<GroupParams>,
                    Option<SecretPackage>,
                    Option<PublicPackage>,
                )> = deserialize_vec(&unpack(data)?)?;
                let (Some(group_params), Some(secret_pkg), Some(public_pkg)) = &data[0] else {
                    todo!()
                };
                let msgs = inflate(
                    public_pkg.public_key.to_pkcs1_der().unwrap().to_vec(),
                    (group_params.max_signers - 1) as usize,
                );
                (
                    KeygenRound::Done(*group_params, secret_pkg.clone(), public_pkg.clone()),
                    msgs,
                )
            }

            // Those are the missing combinations, which are all unexpected
            KeygenRound::R1(_, _, _) => {
                panic!("Ended in an unexpected KeygenRound::R1, nor dealer or other party.");
            }

            KeygenRound::Done(_, _, _) => return Err("protocol already finished".into()),
        };
        self.round = c;

        Ok((pack(msgs, ProtocolType::Ptsrsap1), Recipient::Server))
    }
}

#[typetag::serde(name = "ptsrsap1_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(group_params, secret_pkg, public_pkg) => {
                // TODO ok also group_params?
                Ok(serde_json::to_vec(&(group_params, secret_pkg, public_pkg))?)
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

#[derive(Serialize, Deserialize)]
pub struct SignContext {
    key_share: SecretPackage,
    public_pkg: PublicPackage,
    message: Option<Vec<u8>>,
    indices: Option<Vec<u16>>,
    round: SignRound,
    // NOTE should padding_scheme be bound to the context?
    padding_scheme: PaddingScheme,
}

#[derive(Serialize, Deserialize)]
enum SignRound {
    R0,
    // The first is the message, but we shoudln't store it here, maybe just the hash
    R1(PartialMessageSignature),
    // TODO this should be changed to Signature and not BigInt
    Done(Vec<u8>),
}

impl SignContext {
    // fn local_index(&self) -> Result<usize> {
    //     let identifier = self.key_share.uid;
    //     self.indices
    //         .as_ref()
    //         .and_then(|indices| indices.iter().position(|x| *x == identifier as u16))
    //         .ok_or("participant index not included".into())
    // }

    fn init(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let msg = ProtocolInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Ptsrsap1 as i32 {
            return Err("wrong protocol type".into());
        }

        self.indices = Some(msg.indices.iter().map(|i| *i as u16).collect());
        self.message = Some(msg.data);

        // FIXME
        self.padding_scheme = PaddingScheme::PKCS1v15;
        // FIXME calculating factorials is possible DoS vector
        let delta = factorial(self.public_pkg.group_size);
        let message = match &self.message {
            None => return Err("no message provided".into()),
            // FIXME we should be able to sign any bytes not just strings.
            Some(value) => value,
        };
        // self.message = message;
        let pms = sign_with_share(
            message,
            delta,
            &self.key_share.share,
            &self.public_pkg.v,
            // TODO provide index
            &self.public_pkg.verification_keys[self.key_share.uid],
            self.padding_scheme,
        );

        // Each party has the self.key_share and therefore can sign with the share. Then it also
        // needs to generate the proof and broadcast all of these.

        let msgs = serialize_bcast(&pms, self.indices.as_ref().unwrap().len() - 1)?;
        self.round = SignRound::R1(pms);
        Ok((pack(msgs, ProtocolType::Ptsrsap1), Recipient::Server))
    }

    fn update(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match &self.round {
            SignRound::R0 => Err("protocol not initialized".into()),
            SignRound::R1(pms) => {
                let mut data: Vec<PartialMessageSignature> = deserialize_vec(&unpack(data)?)?;
                // Iterate over partialSignatures
                // assert_eq!(Some(msg.as_bytes().to_vec()), self.message);
                // let local_index = self.local_index()?;
                let delta = factorial(self.public_pkg.group_size);
                data.push(pms.clone());
                let message = match &self.message {
                    None => return Err("no message provided".into()),
                    // FIXME we should be able to sign any bytes not just strings.
                    Some(value) => value,
                };
                let some_invalid_proof = data
                    .clone()
                    .into_par_iter()
                    .find_any(|i_pms| {
                        !verify_proof(
                            message,
                            &self.public_pkg.v,
                            delta,
                            // FIXME the indexing has to match self.indices
                            &self.public_pkg.verification_keys[i_pms.id - 1],
                            &i_pms,
                            &self.key_share.share.n,
                            self.key_share.share.key_bytes_size,
                            self.padding_scheme,
                        )
                    })
                    .is_some();

                // let valid_proofs = data.clone().into_iter().enumerate().all(|(_ind, i_pms)| {
                //     verify_proof(
                //         message,
                //         &self.public_pkg.v,
                //         delta,
                //         // FIXME the indexing has to match self.indices
                //         &self.public_pkg.verification_keys[i_pms.id - 1],
                //         &i_pms,
                //         &self.key_share.share.n,
                //         self.key_share.share.key_bytes_size,
                //         self.padding_scheme,
                //     )
                // });
                match some_invalid_proof {
                    true => Err("verification proofs failed".into()),
                    false => {
                        match combine_shares(
                            message,
                            delta,
                            data,
                            &self.key_share.share,
                            self.public_pkg.group_size,
                            self.padding_scheme,
                        ) {
                            Ok(signature) => {
                                self.round = SignRound::Done(signature.clone());
                                // FIXME signature needs to be tested more, because once the BigInts are
                                // not used in pretzel taking .1 will likely fail
                                let msgs =
                                    inflate(signature, self.indices.as_ref().unwrap().len() - 1);
                                Ok((pack(msgs, ProtocolType::Ptsrsap1), Recipient::Server))
                            }
                            Err(__) => Err("combining shares failed".into()),
                        }
                    }
                }
            }
            SignRound::Done(_) => Err("protocol already finished".into()),
        }
    }
}

#[typetag::serde(name = "ptsrsap1_sign")]
impl Protocol for SignContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match self.round {
            SignRound::R0 => self.init(data),
            _ => self.update(data),
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            SignRound::Done(sig) => Ok(serde_json::to_vec(&sig)?),
            _ => Err("protocol not finished".into()),
        }
    }
}

impl ThresholdProtocol for SignContext {
    fn new(group: &[u8]) -> Self {
        let (_group_params, key_share, public_pkg): (GroupParams, SecretPackage, PublicPackage) =
            serde_json::from_slice(group).expect("could not deserialize group context");
        Self {
            key_share: key_share,
            public_pkg: public_pkg,
            message: None,
            indices: None,
            round: SignRound::R0,
            padding_scheme: PaddingScheme::PKCS1v15,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::{KeygenProtocolTest, ThresholdProtocolTest};
    use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};
    use itertools::Itertools;
    use rand::distributions::Uniform;
    use rand::rngs::OsRng;
    use rand::seq::IteratorRandom;
    use rand::Rng;
    use rsa::{hazmat::pkcs1v15_generate_prefix, Pkcs1v15Sign};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::iter::zip;
    use std::mem;

    const INDEX_OFFSET: u32 = 0;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Ptsrsap1;
        // // Minus one because we do not count the R0 round
        // const ROUNDS: usize = mem::variant_count::<KeygenRound>() - 1;
        const ROUNDS: usize = 2;
        const INDEX_OFFSET: u32 = INDEX_OFFSET;
    }

    impl ThresholdProtocolTest for SignContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Ptsrsap1;
        // Minus one because we do not count the R0 round
        // const ROUNDS: usize = mem::variant_count::<SignRound>() - 1;
        const ROUNDS: usize = 2;
        const INDEX_OFFSET: u32 = INDEX_OFFSET;
    }

    #[test]
    // TODO The tests take a long time to finish as such it would be better to have them
    // parametrized so that the results would be reported sooner than when the whole tests
    // finishes.
    fn that_each_party_ends_up_with_the_same_public_and_unique_secret_material() {
        let max_parties = 5;

        (2..=max_parties).into_par_iter().for_each(|threshold| {
            // for threshold in 2..=max_parties {
            (threshold..=max_parties)
                .into_par_iter()
                .for_each(|parties| {
                    // for parties in threshold..=max_parties {
                    let (_, last_rounds_ctxs) = <KeygenContext as KeygenProtocolTest>::run(
                        threshold as u32,
                        parties as u32,
                    );

                    let results: Vec<(GroupParams, SecretPackage, PublicPackage)> =
                        deserialize_vec(&last_rounds_ctxs).unwrap();

                    let (_, _, dealer_public): (GroupParams, SecretPackage, PublicPackage) =
                        match results.first() {
                            None => panic!("the first value (the dealer) is always expected"),
                            Some((g, x, y)) => (*g, x.clone(), y.clone()),
                        };

                    assert!(results
                        .clone()
                        .into_par_iter()
                        .skip(1)
                        .all(|(_, _, party_public)| party_public == dealer_public));

                    for i in 0..results.len() - 1 {
                        for j in i + 1..results.len() {
                            assert_ne!(results[i].1, results[j].1);
                        }
                    }
                });
        });
    }

    #[inline]
    fn random_message() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let message_size = rng.gen_range(0..100);
        let range = Uniform::from(0..=255);
        rng.sample_iter(&range).take(message_size).collect()
    }

    #[test]
    fn that_threshold_groups_create_valid_signatures() {
        let max_parties = 5;
        // TODO FIXME the scheme is not working for 1-out-of-1 type of setting. That is kinda OK,
        // but it could mean that there is something slightly off.

        // for threshold in 2..max_parties {
        //     for parties in threshold..max_parties {
        (2..=max_parties).into_par_iter().for_each(|threshold| {
            // for threshold in 2..=max_parties {
            (threshold..=max_parties)
                .into_par_iter()
                .for_each(|parties| {
                    let (_, last_rounds_ctxs) = <KeygenContext as KeygenProtocolTest>::run(
                        threshold as u32,
                        parties as u32,
                    );

                    let results: Vec<(GroupParams, SecretPackage, PublicPackage)> =
                        deserialize_vec(&last_rounds_ctxs).unwrap();

                    let mut indices = (0..parties as u16).choose_multiple(&mut OsRng, threshold);
                    indices.sort();

                    let msg = random_message();
                    let results = <SignContext as ThresholdProtocolTest>::run(
                        last_rounds_ctxs.clone(),
                        indices,
                        msg.clone(),
                    );
                    let signature: Vec<u8> = serde_json::from_slice(&results[0]).unwrap();
                    let packages: Vec<(GroupParams, SecretPackage, PublicPackage)> =
                        deserialize_vec(&last_rounds_ctxs).unwrap();

                    // let hashed = Sha256::digest(msg);

                    // FIXME: The verification sometimes fails
                    assert_eq!(
                        packages[0].2.public_key.verify(
                            // FIXME we are currently not hashing the messages
                            Pkcs1v15Sign::new_unprefixed(),
                            &msg,
                            // Pkcs1v15Sign {
                            //     hash_len: Some(<Sha256>::output_size()),
                            //     prefix: pkcs1v15_generate_prefix::<Sha256>().into(),
                            // },
                            // &hashed,
                            &signature,
                        ),
                        Ok(()),
                    );
                });
        });
    }
}
