pub mod elgamal;
pub mod frost;
pub mod gg18;

use crate::proto::{ProtocolMessage, ProtocolType};
use prost::Message;
use serde::{Deserialize, Serialize};

fn deserialize_vec<'de, T: Deserialize<'de>>(vec: &'de [Vec<u8>]) -> serde_json::Result<Vec<T>> {
    vec.iter()
        .map(|item| serde_json::from_slice::<T>(item))
        .collect()
}

fn inflate<T: Clone>(value: T, n: usize) -> Vec<T> {
    std::iter::repeat(value).take(n).collect()
}

/// Serialize value and repeat the result n times,
/// as the current server always expects one message for each party
fn serialize_bcast<T: Serialize>(value: &T, n: usize) -> serde_json::Result<Vec<Vec<u8>>> {
    let ser = serde_json::to_vec(value)?;
    Ok(inflate(ser, n))
}

/// Serialize vector of unicast messages
fn serialize_uni<T: Serialize>(vec: Vec<T>) -> serde_json::Result<Vec<Vec<u8>>> {
    vec.iter().map(|item| serde_json::to_vec(item)).collect()
}

/// Decode a protobuf message from the server
fn unpack(data: &[u8]) -> std::result::Result<Vec<Vec<u8>>, prost::DecodeError> {
    let msgs = ProtocolMessage::decode(data)?.message;
    Ok(msgs)
}

/// Encode msgs as a protobuf message for the server
fn pack(msgs: Vec<Vec<u8>>, protocol_type: ProtocolType) -> Vec<u8> {
    ProtocolMessage {
        protocol_type: protocol_type.into(),
        message: msgs,
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use prost::bytes::Bytes;

    use crate::{proto::ProtocolGroupInit, protocol::KeygenProtocol, protocol::Protocol};

    use super::*;

    pub trait ProtocolTest {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const KEYGEN_ROUNDS: usize;

        type KeygenProtocol: KeygenProtocol;

        fn keygen(threshold: u32, parties: u32) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            assert!(threshold <= parties);

            // initialize
            let mut ctxs: Vec<Self::KeygenProtocol> =
                (0..parties).map(|_| Self::KeygenProtocol::new()).collect();
            let mut messages: Vec<_> = ctxs
                .iter_mut()
                .enumerate()
                .map(|(idx, ctx)| {
                    ProtocolMessage::decode::<Bytes>(
                        ctx.advance(
                            &(ProtocolGroupInit {
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                index: idx as u32 + 1,
                                parties,
                                threshold,
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .into(),
                    )
                    .unwrap()
                    .message
                })
                .collect();

            // protocol rounds
            for _ in 0..(Self::KEYGEN_ROUNDS - 1) {
                messages = ctxs
                    .iter_mut()
                    .enumerate()
                    .map(|(idx, ctx)| {
                        let relay = messages
                            .iter()
                            .enumerate()
                            .map(|(sender, msg)| {
                                if sender < idx {
                                    Some(msg[idx - 1].clone())
                                } else if sender > idx {
                                    Some(msg[idx].clone())
                                } else {
                                    None
                                }
                            })
                            .filter(Option::is_some)
                            .map(Option::unwrap)
                            .collect();

                        ProtocolMessage::decode::<Bytes>(
                            ctx.advance(
                                &(ProtocolMessage {
                                    protocol_type: ProtocolType::Frost as i32,
                                    message: relay,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .into(),
                        )
                        .unwrap()
                        .message
                    })
                    .collect();
            }

            let pks: Vec<_> = messages.iter().map(|x| x[0].clone()).collect();

            let results = ctxs
                .into_iter()
                .map(|ctx| Box::new(ctx).finish().unwrap())
                .collect();

            (pks, results)
        }
    }
}
