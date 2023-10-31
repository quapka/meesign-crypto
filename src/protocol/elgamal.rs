use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType};
use crate::protocol::*;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use elastic_elgamal::{
    dkg::*,
    group::{ElementOps, Ristretto},
    sharing::{ActiveParticipant, Params},
    Ciphertext, LogEqualityProof, PublicKey, VerifiableDecryption,
};
use rand::rngs::OsRng;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    Aes128Gcm,
};
use prost::Message;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(ParticipantCollectingCommitments<Ristretto>, u16),
    R2(ParticipantCollectingPolynomials<Ristretto>, u16),
    R3(ParticipantExchangingSecrets<Ristretto>, u16),
    Done(ActiveParticipant<Ristretto>),
}

impl KeygenContext {
    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolGroupInit::decode(data)?;

        if msg.protocol_type != ProtocolType::Elgamal as i32 {
            return Err("wrong protocol type".into());
        }

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let params = Params::new(parties.into(), threshold.into());

        let dkg =
            ParticipantCollectingCommitments::<Ristretto>::new(params, index.into(), &mut OsRng);
        let c = dkg.commitment();
        let ser = serialize_bcast(&c, msg.parties as usize - 1)?;
        self.round = KeygenRound::R1(dkg, index);
        Ok(pack(ser, ProtocolType::Elgamal))
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msgs = unpack(data)?;
        let n = msgs.len();

        let (c, ser) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R1(dkg, idx) => {
                let mut dkg = dkg.clone();
                let data = deserialize_vec(&msgs)?;
                for (mut i, msg) in data.into_iter().enumerate() {
                    if i >= *idx as usize {
                        i += 1;
                    }
                    dkg.insert_commitment(i, msg);
                }
                if dkg.missing_commitments().next().is_some() {
                    return Err("not enough commitments".into());
                }
                let dkg = dkg.finish_commitment_phase();
                let public_info = dkg.public_info();
                let ser = serialize_bcast(&public_info, n)?;

                (KeygenRound::R2(dkg, *idx), ser)
            }
            KeygenRound::R2(dkg, idx) => {
                let mut dkg = dkg.clone();
                let data = deserialize_vec(&msgs)?;
                for (mut i, msg) in data.into_iter().enumerate() {
                    if i >= *idx as usize {
                        i += 1;
                    }
                    dkg.insert_public_polynomial(i, msg)?
                }
                if dkg.missing_public_polynomials().next().is_some() {
                    return Err("not enough polynomials".into());
                }
                let dkg = dkg.finish_polynomials_phase();

                let mut shares = Vec::new();
                for mut i in 0..n {
                    if i >= *idx as usize {
                        i += 1;
                    }
                    let secret_share = dkg.secret_share_for_participant(i);
                    shares.push(secret_share);
                }
                let ser = serialize_uni(shares)?;

                (KeygenRound::R3(dkg, *idx), ser)
            }
            KeygenRound::R3(dkg, idx) => {
                let mut dkg = dkg.clone();
                let data = deserialize_vec(&msgs)?;
                for (mut i, msg) in data.into_iter().enumerate() {
                    if i >= *idx as usize {
                        i += 1;
                    }
                    dkg.insert_secret_share(i, msg)?;
                }
                if dkg.missing_shares().next().is_some() {
                    return Err("not enough shares".into());
                }
                let dkg = dkg.complete()?;
                let ser = inflate(dkg.key_set().shared_key().as_bytes().to_vec(), n);

                (KeygenRound::Done(dkg), ser)
            }
            KeygenRound::Done(_) => return Err("protocol already finished".into()),
        };

        self.round = c;
        Ok(pack(ser, ProtocolType::Elgamal))
    }
}

#[typetag::serde(name = "elgamal_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let data = match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }?;
        Ok((data, Recipient::Server))
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(ctx) => Ok(serde_json::to_vec(&ctx)?),
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
pub(crate) struct DecryptContext {
    ctx: ActiveParticipant<Ristretto>,
    encrypted_key: Ciphertext<Ristretto>,
    data: (Vec<u8>, Vec<u8>, Vec<u8>),
    indices: Vec<u16>,
    shares: Vec<(usize, VerifiableDecryption<Ristretto>)>,
    result: Option<Vec<u8>>,
}

impl DecryptContext {
    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolInit::decode(data)?;

        if msg.protocol_type != ProtocolType::Elgamal as i32 {
            return Err("wrong protocol type".into());
        }

        self.indices = msg.indices.clone().into_iter().map(|i| i as u16).collect();
        self.data = serde_json::from_slice(&msg.data)?;
        self.encrypted_key = serde_json::from_slice(&self.data.0)?;

        let (share, proof) = self.ctx.decrypt_share(self.encrypted_key, &mut OsRng);

        let ser = serialize_bcast(
            &serde_json::to_string(&(share, proof))?.as_bytes(),
            self.indices.len() - 1,
        )?;

        let share = (self.ctx.index(), share);
        self.shares.push(share);

        Ok(pack(ser, ProtocolType::Elgamal))
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.shares.is_empty() {
            return Err("protocol not initialized".into());
        }
        if self.result.is_some() {
            return Err("protocol already finished".into());
        }

        let msgs = unpack(data)?;

        let data: Vec<Vec<u8>> = deserialize_vec(&msgs)?;
        let local_index = self
            .indices
            .iter()
            .position(|x| *x as usize == self.ctx.index())
            .ok_or("participant index not included")?;
        assert_eq!(self.ctx.index(), self.indices[local_index] as usize);

        for (mut i, msg) in data.into_iter().enumerate() {
            if i >= local_index {
                i += 1;
            }
            let msg: (VerifiableDecryption<Ristretto>, LogEqualityProof<Ristretto>) =
                serde_json::from_slice(&msg)?;
            self.ctx
                .key_set()
                .verify_share(
                    msg.0.into(),
                    self.encrypted_key,
                    self.indices[i].into(),
                    &msg.1,
                )
                .unwrap();
            self.shares.push((self.indices[i].into(), msg.0));
        }

        let mut key = [0u8; 16];
        key.copy_from_slice(&decode(
            self.encrypted_key.blinded_element()
                - self
                    .ctx
                    .key_set()
                    .params()
                    .combine_shares(self.shares.clone())
                    .unwrap()
                    .as_element(),
        ));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.data.1);

        let cipher = Aes128Gcm::new(&key.into());

        let msg = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &self.data.2,
                    aad: &self.data.0,
                },
            )
            .unwrap();

        self.result = Some(msg.clone());

        let ser = inflate(msg, self.indices.len() - 1);
        Ok(pack(ser, ProtocolType::Elgamal))
    }
}

#[typetag::serde(name = "elgamal_decrypt")]
impl Protocol for DecryptContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let data = if self.shares.is_empty() {
            self.init(data)
        } else {
            self.update(data)
        }?;
        Ok((data, Recipient::Server))
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        if self.result.is_none() {
            return Err("protocol not finished".into());
        }
        Ok(self.result.unwrap())
    }
}

impl ThresholdProtocol for DecryptContext {
    fn new(group: &[u8]) -> Self {
        Self {
            ctx: serde_json::from_slice(group).expect("could not deserialize group context"),
            encrypted_key: Ciphertext::zero(),
            data: (Vec::new(), Vec::new(), Vec::new()),
            indices: Vec::new(),
            shares: Vec::new(),
            result: None,
        }
    }
}

fn try_encode(message: &[u8]) -> Option<RistrettoPoint> {
    if message.len() > 30 {
        return None;
    }

    let mut message_buffer = [0u8; 32];
    message_buffer[0] = message.len() as u8;
    message_buffer[1..(message.len() + 1)].copy_from_slice(message);
    let mut scalar = Scalar::from_bytes_mod_order(message_buffer);

    let offset = Scalar::from(2u32.pow(8));
    scalar *= offset;
    let mut d = Scalar::ZERO;
    while d != offset {
        if let Some(p) = CompressedRistretto((scalar + d).to_bytes()).decompress() {
            return Some(p);
        }

        d += Scalar::ONE;
    }
    None
}

fn decode(p: RistrettoPoint) -> Vec<u8> {
    let scalar = Scalar::from_bytes_mod_order(p.compress().to_bytes());
    let scalar_bytes = &scalar.as_bytes()[1..];
    scalar_bytes[1..(scalar_bytes[0] as usize + 1)].to_vec()
}

pub fn encrypt(msg: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
    let pk: PublicKey<Ristretto> = PublicKey::from_bytes(pk).unwrap();
    let key = Aes128Gcm::generate_key(&mut OsRng);

    let encoded_key: <Ristretto as ElementOps>::Element =
        try_encode(&key).ok_or("encoding failed")?;
    let encrypted_key = serde_json::to_vec(&pk.encrypt_element(encoded_key, &mut OsRng))?;

    let cipher = Aes128Gcm::new(&key);
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg,
                aad: &encrypted_key,
            },
        )
        .unwrap();

    Ok(serde_json::to_vec(&(&encrypted_key, &nonce.to_vec(), &ct))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::{KeygenProtocolTest, ThresholdProtocolTest};
    use rand::seq::IteratorRandom;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Elgamal;
        const ROUNDS: usize = 4;
    }

    impl ThresholdProtocolTest for DecryptContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Elgamal;
        const ROUNDS: usize = 2;
    }

    #[test]
    fn test_encode() {
        let message = b"hello";
        let point = try_encode(message).unwrap();
        let decoded = decode(point);
        assert_eq!(message, decoded.as_slice());
    }

    #[test]
    fn keygen() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (pks, _) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);

                for i in 1..parties {
                    assert_eq!(pks[0], pks[i])
                }
            }
        }
    }

    #[test]
    fn decrypt() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (pks, ctxs) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);
                let msg = b"hello";
                let ct = encrypt(msg, &pks[0]).unwrap();

                let mut indices = (0..parties as u16).choose_multiple(&mut OsRng, threshold);
                indices.sort();
                let results =
                    <DecryptContext as ThresholdProtocolTest>::run(ctxs, indices, ct.to_vec());

                for result in results {
                    assert_eq!(&msg.to_vec(), &result);
                }
            }
        }
    }
}
