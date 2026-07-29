//
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use libsignal_protocol::dsa;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// A fixed message so that signing and verification are measured over a
/// constant input across artefacts and invocations.
const MESSAGE: &[u8] = b"pqs-v7 fixed benchmark message";

fn bench_mldsa(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    eprintln!("\nML-DSA-87 sizes (bytes):");
    eprintln!("  public key : {}", dsa::PUBLIC_KEY_LENGTH);
    eprintln!("  secret key : {}", dsa::SECRET_KEY_LENGTH);
    eprintln!("  signature  : {}", dsa::SIGNATURE_LENGTH);
    eprintln!();

    c.bench_function("MLDSA87_generate", |b| {
        b.iter(|| {
            black_box(dsa::KeyPair::generate(&mut rng));
        });
    });

    // Fixtures built outside every timed region.
    let key_pairs: Vec<_> = std::iter::from_fn(|| Some(dsa::KeyPair::generate(&mut rng)))
        .take(10)
        .collect();

    c.bench_function("MLDSA87_sign", |b| {
        let mut keys = key_pairs.iter().cycle();
        b.iter(|| {
            let kp = keys.next().unwrap();
            black_box(
                kp.secret_key
                    .calculate_signature(MESSAGE, &mut rng)
                    .expect("signing works"),
            );
        });
    });

    let signatures: Vec<_> = key_pairs
        .iter()
        .map(|kp| {
            let sig = kp
                .secret_key
                .calculate_signature(MESSAGE, &mut rng)
                .expect("signing works");
            (kp.public_key, sig)
        })
        .collect();

    c.bench_function("MLDSA87_verify", |b| {
        let mut pairs = signatures.iter().cycle();
        b.iter(|| {
            let (pk, sig) = pairs.next().unwrap();
            black_box(pk.verify_signature(MESSAGE, sig.as_ref()));
        });
    });
}

criterion_group!(benches, bench_mldsa);
criterion_main!(benches);
