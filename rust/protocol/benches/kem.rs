//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use libsignal_protocol::kem::{KeyPair, KeyType};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// The KEMs compared head-to-head. All three target NIST security level 5, so
/// this is an apples-to-apples comparison of the code-based HQC-256 against the
/// lattice-based ML-KEM-1024 (FIPS 203) and its pre-standard sibling Kyber1024.
const COMPARED_KEMS: [KeyType; 3] = [KeyType::HQC256, KeyType::MLKEM1024, KeyType::Kyber1024];

/// Print the wire sizes (excluding the 1-byte type tag) for each KEM so the
/// space cost of HQC-256 can be weighed against ML-KEM-1024 alongside the
/// timings below. Emitted on stderr so it shows up in `cargo bench` output.
fn report_sizes() {
    let mut rng = OsRng.unwrap_err();
    eprintln!("\nKEM wire sizes (bytes, excluding the 1-byte type tag):");
    eprintln!(
        "  {:<11} {:>8} {:>8} {:>11} {:>7}",
        "kem", "pubkey", "seckey", "ciphertext", "secret"
    );
    for key_type in COMPARED_KEMS {
        let kp = KeyPair::generate(key_type, &mut rng);
        let (ss, ct) = kp
            .public_key
            .encapsulate(&mut rng)
            .expect("encapsulation works");
        eprintln!(
            "  {:<11} {:>8} {:>8} {:>11} {:>7}",
            format!("{key_type:?}"),
            kp.public_key.serialize().len() - 1,
            kp.secret_key.serialize().len() - 1,
            ct.len() - 1,
            ss.len(),
        );
    }
    eprintln!();
}

fn bench_kem(c: &mut Criterion) {
    report_sizes();
    for key_type in COMPARED_KEMS {
        let mut rng = OsRng.unwrap_err();

        c.bench_function(format!("{key_type:?}_generate").as_str(), |b| {
            b.iter(|| {
                black_box(KeyPair::generate(key_type, &mut rng));
            });
        });
        let key_pairs: Vec<_> = std::iter::from_fn(|| Some(KeyPair::generate(key_type, &mut rng)))
            .take(10)
            .collect();
        c.bench_function(format!("{key_type:?}_encapsulate").as_str(), |b| {
            let mut public_keys = key_pairs.iter().map(|kp| &kp.public_key).cycle();
            b.iter(|| {
                black_box(public_keys.next().unwrap().encapsulate(&mut rng))
                    .expect("encapsulation works");
            });
        });
        c.bench_function(format!("{key_type:?}_decapsulate").as_str(), |b| {
            let mut ct_sk_pairs = key_pairs
                .iter()
                .map(move |kp| {
                    let sk = &kp.secret_key;
                    let (_ss, ct) = kp
                        .public_key
                        .encapsulate(&mut rng)
                        .expect("encapsulation works");
                    (ct, sk)
                })
                .cycle();
            b.iter(|| {
                let (ct, sk) = ct_sk_pairs.next().unwrap();
                black_box(sk.decapsulate(&ct)).expect("decapsulation works");
            });
        });
    }
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
