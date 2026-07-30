//
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The baseline's classical primitives, measured as individual operations.
//!
//! These belong to one artefact only. The version trees replace X25519 agreement and XEdDSA
//! authentication with a KEM and ML-DSA, so there is no counterpart there to measure against, and
//! unlike the post-quantum primitive cells these cannot be taken once from the common `v2` tree.
//!
//! Structured after `benches/mldsa.rs` on the version trees, and signing the same fixed message,
//! so the classical and post-quantum signature figures are read over identical input.
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use libsignal_protocol::KeyPair;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// A fixed message so that signing and verification are measured over a
/// constant input across artefacts and invocations. This is the message
/// `benches/mldsa.rs` signs on the version trees.
const MESSAGE: &[u8] = b"pqs-v7 fixed benchmark message";

fn bench_classical(c: &mut Criterion) {
    let mut rng = OsRng.unwrap_err();

    // Fixtures built outside every timed region.
    let key_pair = KeyPair::generate(&mut rng);
    let peer_key_pair = KeyPair::generate(&mut rng);
    let signature = key_pair
        .calculate_signature(MESSAGE, &mut rng)
        .expect("signing works");
    assert!(
        key_pair.public_key.verify_signature(MESSAGE, &signature),
        "the prepared signature must verify"
    );

    eprintln!("\nX25519 and XEdDSA sizes (bytes):");
    eprintln!(
        "  public key  : {}",
        key_pair.public_key.public_key_bytes().len()
    );
    eprintln!(
        "  private key : {}",
        key_pair.private_key.serialize().len()
    );
    eprintln!("  signature   : {}", signature.len());
    eprintln!();

    c.bench_function("X25519_generate", |b| {
        b.iter(|| {
            black_box(KeyPair::generate(&mut rng));
        });
    });

    c.bench_function("X25519_agree", |b| {
        b.iter(|| {
            black_box(
                key_pair
                    .calculate_agreement(&peer_key_pair.public_key)
                    .expect("agreement works"),
            );
        });
    });

    c.bench_function("XEdDSA_sign", |b| {
        b.iter(|| {
            black_box(
                key_pair
                    .calculate_signature(MESSAGE, &mut rng)
                    .expect("signing works"),
            );
        });
    });

    c.bench_function("XEdDSA_verify", |b| {
        b.iter(|| {
            black_box(key_pair.public_key.verify_signature(MESSAGE, &signature));
        });
    });
}

criterion_group!(benches, bench_classical);
criterion_main!(benches);
