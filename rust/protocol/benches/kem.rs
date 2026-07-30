//
// Copyright 2023 Signal Messenger, LLC.
// Copyright 2026 Mark Saviour Farrugia.
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

/// Print the wire sizes for each KEM so the space cost of HQC-256 can be weighed
/// against ML-KEM-1024 alongside the timings below.
///
/// Keys and ciphertexts are reported twice: `*_raw` is the bare primitive length,
/// and `*_tagged` is this artefact's serialized encoding, which prefixes a
/// 1-byte algorithm identifier. Shared secrets carry no tag, so they are
/// reported once. Emitted on stderr so it shows up in `cargo bench` output.
fn report_sizes() {
    let mut rng = OsRng.unwrap_err();
    eprintln!("\nKEM wire sizes (bytes; _raw excludes, _tagged includes the 1-byte type tag):");
    eprintln!(
        "  {:<12}{:>7}{:>11}{:>8}{:>11}{:>8}{:>11}{:>8}",
        "kem", "pk_raw", "pk_tagged", "sk_raw", "sk_tagged", "ct_raw", "ct_tagged", "secret"
    );
    for key_type in COMPARED_KEMS {
        let kp = KeyPair::generate(key_type, &mut rng);
        let (ss, ct) = kp
            .public_key
            .encapsulate(&mut rng)
            .expect("encapsulation works");
        let pk = kp.public_key.serialize();
        let sk = kp.secret_key.serialize();
        eprintln!(
            "  {:<12}{:>7}{:>11}{:>8}{:>11}{:>8}{:>11}{:>8}",
            format!("{key_type:?}"),
            pk.len() - 1,
            pk.len(),
            sk.len() - 1,
            sk.len(),
            ct.len() - 1,
            ct.len(),
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
            // Materialise every ciphertext/secret-key pair before the timed region.
            // `Iterator::map` is lazy and `cycle` restarts the underlying iterator, so
            // cycling the unmaterialised chain would re-run the encapsulation on every
            // `next()` and charge it to decapsulation.
            let materialised: Vec<_> = key_pairs
                .iter()
                .map(|kp| {
                    let (_ss, ct) = kp
                        .public_key
                        .encapsulate(&mut rng)
                        .expect("encapsulation works");
                    (ct, &kp.secret_key)
                })
                .collect();
            let mut ct_sk_pairs = materialised.iter().cycle();
            b.iter(|| {
                let (ct, sk) = ct_sk_pairs.next().unwrap();
                black_box(sk.decapsulate(ct)).expect("decapsulation works");
            });
        });
    }
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
