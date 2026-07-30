//
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Baseline measurement spans for the deployed handshake at this commit: X3DH over X25519 with
//! XEdDSA identities and an optional Kyber-1024 prekey.
//!
//! These are the baseline counterparts to the bounded handshake spans on the version trees. Every
//! case name is prefixed `baseline`, and the mode that varies is named for the one-time *curve*
//! prekey, because what the baseline can omit is the optional one-time X25519 prekey, not the
//! optional one-time KEM prekey the version trees omit. The two are not the same axis and the
//! cases are named so as not to imply otherwise.
//!
//! Nothing here touches `src/`. The whole file is an instrument added on top of the unmodified
//! upstream commit, which is what Chapter 4 requires of a harness commit.

use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

#[path = "../tests/support/mod.rs"]
mod support;

/// Initiator span: begins by processing the responder's bundle and ends once the initial
/// `PreKeySignalMessage` has been serialised. `PreKeySignalMessage::new` serialises eagerly into
/// its `serialized` field, so serialisation is already accounted for when `support::encrypt`
/// returns.
///
/// One-time curve prekey present, which is what `support::create_pre_key_bundle` publishes.
pub fn baseline_initiate_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng.unwrap_err();
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    // Fixtures: built once, outside every timed region.
    let mut bob_store = support::TestStoreBuilder::new().store;
    let bob_bundle = support::create_pre_key_bundle(&mut bob_store, &mut csprng)
        .now_or_never()
        .expect("sync")?;
    assert!(
        bob_bundle.pre_key_id()?.is_some(),
        "expected a one-time curve prekey in the bundle"
    );
    assert!(
        bob_bundle.has_kyber_pre_key(),
        "expected the hybrid bundle to carry a Kyber prekey"
    );

    let alice_store = support::test_in_memory_protocol_store()?;

    c.bench_function("baseline initiate session and encrypt first message", |b| {
        b.iter_batched(
            || alice_store.clone(),
            |mut alice_store| {
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bob_bundle,
                    SystemTime::now(),
                    &mut OsRng.unwrap_err(),
                )
                .now_or_never()
                .expect("sync")
                .expect("valid bundle");

                let initial = support::encrypt(&mut alice_store, &bob_address, "a short message")
                    .now_or_never()
                    .expect("sync")
                    .expect("success");

                criterion::black_box(initial.serialize().len())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    Ok(())
}

/// The same initiator span with the optional one-time curve prekey absent, so the X3DH secret
/// loses its `DH(EK_A, OPK_B)` term. A builder that is never given a one-time prekey yields a
/// bundle without one.
pub fn baseline_initiate_no_one_time_curve_key_result(
    c: &mut Criterion,
) -> Result<(), SignalProtocolError> {
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    // Fixtures: built once, outside every timed region.
    let bob_builder = support::TestStoreBuilder::new()
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    let bob_bundle = bob_builder.make_bundle_with_latest_keys(1.into());
    assert!(
        bob_bundle.pre_key_id()?.is_none(),
        "expected no one-time curve prekey in the bundle"
    );
    assert!(
        bob_bundle.has_kyber_pre_key(),
        "expected the hybrid bundle to carry a Kyber prekey"
    );

    let alice_store = support::test_in_memory_protocol_store()?;

    c.bench_function(
        "baseline initiate session and encrypt first message, no one-time curve key",
        |b| {
            b.iter_batched(
                || alice_store.clone(),
                |mut alice_store| {
                    process_prekey_bundle(
                        &bob_address,
                        &mut alice_store.session_store,
                        &mut alice_store.identity_store,
                        &bob_bundle,
                        SystemTime::now(),
                        &mut OsRng.unwrap_err(),
                    )
                    .now_or_never()
                    .expect("sync")
                    .expect("valid bundle");

                    let initial =
                        support::encrypt(&mut alice_store, &bob_address, "a short message")
                            .now_or_never()
                            .expect("sync")
                            .expect("success");

                    criterion::black_box(initial.serialize().len())
                },
                criterion::BatchSize::SmallInput,
            )
        },
    );

    Ok(())
}

/// Responder span: from the serialised initial message and a fresh store through to a successful
/// decryption and the derived session being inserted. This is the side that performs the KEM
/// decapsulation, consumes the one-time prekeys, and derives the session.
///
/// One-time curve prekey present.
pub fn baseline_decrypt_first_message_result(
    c: &mut Criterion,
) -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng.unwrap_err();
    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    // Fixtures: built once, outside every timed region.
    let mut bob_store = support::TestStoreBuilder::new().store;
    let bob_bundle = support::create_pre_key_bundle(&mut bob_store, &mut csprng)
        .now_or_never()
        .expect("sync")?;
    assert!(
        bob_bundle.pre_key_id()?.is_some(),
        "expected a one-time curve prekey in the bundle"
    );

    let mut alice_store = support::test_in_memory_protocol_store()?;
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        SystemTime::now(),
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")?;
    let initial = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;
    assert_eq!(initial.message_type(), CiphertextMessageType::PreKey);
    let initial_bytes = initial.serialize().to_vec();

    c.bench_function("baseline decrypt first message", |b| {
        b.iter_batched(
            || bob_store.clone(),
            |mut bob_store| {
                let received = CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(initial_bytes.as_slice())
                        .expect("valid wire form"),
                );
                let plaintext = support::decrypt(&mut bob_store, &alice_address, &received)
                    .now_or_never()
                    .expect("sync")
                    .expect("success");

                criterion::black_box(plaintext.len())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    Ok(())
}

/// Integrated span: a session confirmed in both directions, from the initiator receiving the
/// responder's bundle to the initiator decrypting the responder's first reply. The two spans above
/// bound the initiator and responder halves separately; this one measures them as a client
/// experiences them, so the cost of reaching a usable session is available as a single figure.
///
/// One mode only: the responder's bundle carries the one-time curve prekey. Both messages cross
/// the timed region in serialised form, as they would on the wire.
pub fn baseline_establish_and_first_exchange_result(
    c: &mut Criterion,
) -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng.unwrap_err();
    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    // Fixtures: built once, outside every timed region.
    let mut bob_store = support::TestStoreBuilder::new().store;
    let bob_bundle = support::create_pre_key_bundle(&mut bob_store, &mut csprng)
        .now_or_never()
        .expect("sync")?;
    assert!(
        bob_bundle.pre_key_id()?.is_some(),
        "expected a one-time curve prekey in the bundle"
    );

    let alice_store = support::test_in_memory_protocol_store()?;

    c.bench_function("baseline session establishment and first exchange", |b| {
        b.iter_batched(
            || (alice_store.clone(), bob_store.clone()),
            |(mut alice_store, mut bob_store)| {
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bob_bundle,
                    SystemTime::now(),
                    &mut OsRng.unwrap_err(),
                )
                .now_or_never()
                .expect("sync")
                .expect("valid bundle");

                let initial = support::encrypt(&mut alice_store, &bob_address, "a short message")
                    .now_or_never()
                    .expect("sync")
                    .expect("success");
                let received = CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(initial.serialize()).expect("valid wire form"),
                );
                support::decrypt(&mut bob_store, &alice_address, &received)
                    .now_or_never()
                    .expect("sync")
                    .expect("success");

                let reply = support::encrypt(&mut bob_store, &alice_address, "a short message")
                    .now_or_never()
                    .expect("sync")
                    .expect("success");
                let received = CiphertextMessage::SignalMessage(
                    SignalMessage::try_from(reply.serialize()).expect("valid wire form"),
                );
                let plaintext = support::decrypt(&mut alice_store, &bob_address, &received)
                    .now_or_never()
                    .expect("sync")
                    .expect("success");

                criterion::black_box(plaintext.len())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    Ok(())
}

pub fn baseline_initiate(c: &mut Criterion) {
    baseline_initiate_result(c).expect("no errors");
}

pub fn baseline_initiate_no_one_time_curve_key(c: &mut Criterion) {
    baseline_initiate_no_one_time_curve_key_result(c).expect("no errors");
}

pub fn baseline_decrypt_first_message(c: &mut Criterion) {
    baseline_decrypt_first_message_result(c).expect("no errors");
}

pub fn baseline_establish_and_first_exchange(c: &mut Criterion) {
    baseline_establish_and_first_exchange_result(c).expect("no errors");
}

criterion_group!(
    benches,
    baseline_initiate,
    baseline_initiate_no_one_time_curve_key,
    baseline_decrypt_first_message,
    baseline_establish_and_first_exchange
);

criterion_main!(benches);
