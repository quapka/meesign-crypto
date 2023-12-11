use criterion::{black_box, criterion_group, criterion_main, Criterion};
use meesign_crypto::proto::{ProtocolMessage, ProtocolType};
use meesign_crypto::protocol::deserialize_vec;
use meesign_crypto::protocol::ptsrsap1::{GroupParams, KeygenContext, SignContext};
use num_bigint::BigInt;
use pretzel::{combine_shares, generate_with_dealer, verify_proof, PublicPackage, SecretPackage};
use rand::distributions::Uniform;
use rand::rngs::OsRng;
use rand::seq::IteratorRandom;
use rand::Rng;
use rayon::prelude::*;

// use rsa::{hazmat::pkcs1v15_generate_prefix, Pkcs1v15Sign};
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use meesign_crypto::{
    proto::{ProtocolGroupInit, ProtocolInit},
    protocol::{KeygenProtocol, ThresholdProtocol},
};
use prost::{bytes::Bytes, Message};

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

// fn fibonacci(n: u64) -> u64 {
//     match n {
//         0 => 1,
//         1 => 1,
//         n => fibonacci(n - 1) + fibonacci(n - 2),
//     }
// }
#[inline]
fn random_message() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    // Assumes no hashing and 2048 bit keys
    let message_size = rng.gen_range(0..1024);
    let range = Uniform::from(0..=255);
    rng.sample_iter(&range).take(message_size).collect()
}

pub trait KeygenProtocolTest: KeygenProtocol + Sized {
    // Cannot be added in Protocol (yet) due to typetag Trait limitations
    const PROTOCOL_TYPE: ProtocolType;
    const ROUNDS: usize;
    const INDEX_OFFSET: u32 = 0;

    fn run(threshold: u32, parties: u32) -> (Vec<Vec<u8>>, Vec<Vec<u8>>)
    where
        Self: Send,
    {
        assert!(threshold <= parties);

        // initialize
        let mut ctxs: Vec<Self> = (0..parties).map(|_| Self::new()).collect();
        let mut messages: Vec<_> = ctxs
            .par_iter_mut()
            .enumerate()
            .map(|(idx, ctx)| {
                ProtocolMessage::decode::<Bytes>(
                    ctx.advance(
                        &(ProtocolGroupInit {
                            protocol_type: Self::PROTOCOL_TYPE as i32,
                            index: idx as u32 + Self::INDEX_OFFSET,
                            parties,
                            threshold,
                        })
                        .encode_to_vec(),
                    )
                    .unwrap()
                    .0
                    .into(),
                )
                .unwrap()
                .message
            })
            .collect();

        // protocol rounds
        for _ in 0..(Self::ROUNDS - 1) {
            messages = ctxs
                .par_iter_mut()
                .enumerate()
                .map(|(idx, ctx)| {
                    let relay = messages
                        .par_iter()
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
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                message: relay,
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .0
                        .into(),
                    )
                    .unwrap()
                    .message
                })
                .collect();
        }

        let pks: Vec<_> = messages.par_iter().map(|x| x[0].clone()).collect();

        let results = ctxs
            .into_iter()
            .map(|ctx| Box::new(ctx).finish().unwrap())
            .collect();

        (pks, results)
    }
}

pub trait ThresholdProtocolTest: ThresholdProtocol + Sized {
    // Cannot be added in Protocol (yet) due to typetag Trait limitations
    const PROTOCOL_TYPE: ProtocolType;
    const ROUNDS: usize;
    const INDEX_OFFSET: u32 = 0;

    fn run(ctxs: Vec<Vec<u8>>, indices: Vec<u16>, data: Vec<u8>) -> Vec<Vec<u8>>
    where
        Self: Send,
    {
        // initialize
        let mut ctxs: Vec<Self> = ctxs
            .par_iter()
            .enumerate()
            .filter(|(idx, _)| indices.contains(&(*idx as u16)))
            .map(|(_, ctx)| Self::new(&ctx))
            .collect();
        let mut messages: Vec<_> = indices
            .par_iter()
            .zip(ctxs.par_iter_mut())
            .map(|(idx, ctx)| {
                ProtocolMessage::decode::<Bytes>(
                    ctx.advance(
                        &(ProtocolInit {
                            protocol_type: Self::PROTOCOL_TYPE as i32,
                            indices: indices
                                .par_iter()
                                .map(|x| *x as u32 + Self::INDEX_OFFSET)
                                .collect(),
                            index: *idx as u32 + Self::INDEX_OFFSET,
                            data: data.clone(),
                        })
                        .encode_to_vec(),
                    )
                    .unwrap()
                    .0
                    .into(),
                )
                .unwrap()
                .message
            })
            .collect();

        // protocol rounds
        for _ in 0..(Self::ROUNDS - 1) {
            messages = ctxs
                .par_iter_mut()
                .enumerate()
                .map(|(idx, ctx)| {
                    let relay = messages
                        .par_iter()
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
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                message: relay,
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .0
                        .into(),
                    )
                    .unwrap()
                    .message
                })
                .collect();
        }

        ctxs.into_iter()
            .map(|ctx| Box::new(ctx).finish().unwrap())
            .collect()
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let min_signers = 3;
    let max_signers = 5;

    eprintln!("starting keygen");
    let (_, last_rounds_ctxs) =
        <KeygenContext as KeygenProtocolTest>::run(min_signers as u32, min_signers as u32);

    let results: Vec<(GroupParams, SecretPackage, PublicPackage)> =
        deserialize_vec(&last_rounds_ctxs).unwrap();

    let mut indices = (0..min_signers as u16).choose_multiple(&mut OsRng, min_signers);
    indices.sort();

    // let msg = random_message();
    eprintln!("starting benchmark");
    let msg = b"hello";
    c.bench_function(
        // format!("PTSRSAP1 {}-out-of-{} Signing", min_signers, min_signers).into()
        &format!("{min_signers}-out-of-{max_signers}").to_owned(),
        |b| {
            b.iter(|| {
                // fibonacci(black_box(20))
                // let min_signers = 2;
                // TODO FIXME the scheme is not working for 1-out-of-1 type of setting. That is kinda OK,
                // but it could mean that there is something slightly off.
                let results = <SignContext as ThresholdProtocolTest>::run(
                    last_rounds_ctxs.clone(),
                    indices.clone(),
                    msg.clone().into(),
                );
                // let signature: BigInt = serde_json::from_slice(&results[0]).unwrap();
                // let packages: Vec<(GroupParams, SecretPackage, PublicPackage)> =
                //     deserialize_vec(&last_rounds_ctxs).unwrap();

                // let hashed = Sha256::digest(msg);
            })
        },
    );

    // FIXME: The verification sometimes fails
    // assert_eq!(
    //     packages[0].2.public_key.verify(
    //         Pkcs1v15Sign {
    //             hash_len: Some(<Sha256>::output_size()),
    //             prefix: pkcs1v15_generate_prefix::<Sha256>().into(),
    //         },
    //         &hashed,
    //         &signature.to_bytes_be().1,
    //     ),
    //     Ok(()),
    // );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
