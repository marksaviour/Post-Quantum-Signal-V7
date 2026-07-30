//
// Copyright 2020-2021 Signal Messenger, LLC.
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn session_encrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session_record, bob_session_record) = support::initialize_sessions_v3()?;

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    alice_store
        .store_session(&bob_address, &alice_session_record)
        .now_or_never()
        .expect("sync")?;
    bob_store
        .store_session(&alice_address, &bob_session_record)
        .now_or_never()
        .expect("sync")?;

    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session decrypt first message", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    let _ = support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
        .now_or_never()
        .expect("sync")?;
    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session encrypt", |b| {
        b.iter(|| {
            support::encrypt(&mut alice_store, &bob_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });
    c.bench_function("session decrypt", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    // Archive on Alice's side...
    let mut state = alice_store
        .load_session(&bob_address)
        .now_or_never()
        .expect("sync")?
        .expect("already decrypted successfully");
    state.archive_current_state()?;
    alice_store
        .store_session(&bob_address, &state)
        .now_or_never()
        .expect("sync")?;

    // ...then initialize a new session...
    let bob_signed_pre_key_pair = KeyPair::generate(&mut OsRng.unwrap_err());

    let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
    let bob_signed_pre_key_signature = bob_store
        .get_identity_key_pair()
        .now_or_never()
        .expect("sync")?
        .private_key()
        .calculate_signature(&bob_signed_pre_key_public, &mut OsRng.unwrap_err())?;

    // The fully PQ handshake also needs a signed ML-KEM-1024 prekey.
    let bob_kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut OsRng.unwrap_err());
    let bob_kyber_pre_key_public = bob_kyber_pre_key_pair.public_key.serialize();
    let bob_kyber_pre_key_signature = bob_store
        .get_identity_key_pair()
        .now_or_never()
        .expect("sync")?
        .private_key()
        .calculate_signature(&bob_kyber_pre_key_public, &mut OsRng.unwrap_err())?;

    let signed_pre_key_id = 22;
    let kyber_pre_key_id = 23;

    let bob_pre_key_bundle = PreKeyBundle::new(
        bob_store
            .get_local_registration_id()
            .now_or_never()
            .expect("sync")?,
        1.into(),                 // device id
        signed_pre_key_id.into(), // signed pre key id
        bob_signed_pre_key_pair.public_key,
        bob_signed_pre_key_signature.to_vec(),
        kyber_pre_key_id.into(),
        bob_kyber_pre_key_pair.public_key.clone(),
        bob_kyber_pre_key_signature.to_vec(),
        *bob_store
            .get_identity_key_pair()
            .now_or_never()
            .expect("sync")?
            .identity_key(),
    )?;

    bob_store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                Timestamp::from_epoch_millis(42),
                &bob_signed_pre_key_pair,
                &bob_signed_pre_key_signature,
            ),
        )
        .now_or_never()
        .expect("sync")?;

    bob_store
        .save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(
                kyber_pre_key_id.into(),
                Timestamp::from_epoch_millis(42),
                &bob_kyber_pre_key_pair,
                &bob_kyber_pre_key_signature,
            ),
        )
        .now_or_never()
        .expect("sync")?;

    // initialize_sessions_v3 makes up its own identity keys,
    // so we need to reset here to avoid it looking like the identity changed.
    alice_store.identity_store.reset();
    bob_store.identity_store.reset();

    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_pre_key_bundle,
        SystemTime::now(),
        &mut OsRng.unwrap_err(),
    )
    .now_or_never()
    .expect("sync")?;

    let original_message_to_decrypt = message_to_decrypt;

    // ...send another message to archive on Bob's side...
    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;
    let _ = support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
        .now_or_never()
        .expect("sync")?;
    // ...and prepare another message to benchmark decrypting.
    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session decrypt with archived state", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    // Reset once more to go back to the original message.
    bob_store.identity_store.reset();

    c.bench_function("session decrypt using previous state", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &original_message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    Ok(())
}

pub fn session_encrypt_decrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session_record, bob_session_record) = support::initialize_sessions_v3()?;

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    alice_store
        .store_session(&bob_address, &alice_session_record)
        .now_or_never()
        .expect("sync")?;
    bob_store
        .store_session(&alice_address, &bob_session_record)
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session encrypt+decrypt 1 way", |b| {
        b.iter(|| {
            let ctext = support::encrypt(&mut alice_store, &bob_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
            let _ptext = support::decrypt(&mut bob_store, &alice_address, &ctext)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    c.bench_function("session encrypt+decrypt ping pong", |b| {
        b.iter(|| {
            let ctext = support::encrypt(&mut alice_store, &bob_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
            let _ptext = support::decrypt(&mut bob_store, &alice_address, &ctext)
                .now_or_never()
                .expect("sync")
                .expect("success");

            let ctext = support::encrypt(&mut bob_store, &alice_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
            let _ptext = support::decrypt(&mut alice_store, &bob_address, &ctext)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    Ok(())
}

/// Initiator span: begins by processing the responder's bundle and ends once the initial
/// `PreKeySignalMessage` has been serialised. `PreKeySignalMessage::new` serialises eagerly into
/// its `serialized` field, so serialisation is already accounted for when `support::encrypt`
/// returns.
///
/// Measured in both KEM modes: with a one-time KEM prekey alongside the signed last-resort one,
/// and with the last-resort prekey alone.
pub fn session_initiate_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng.unwrap_err();
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    // Fixtures: built once, outside every timed region.
    let mut bob_store = support::TestStoreBuilder::new().store;
    let bob_bundle_full = support::create_pre_key_bundle(&mut bob_store, &mut csprng)
        .now_or_never()
        .expect("sync")?;

    // A builder with exactly one kyber prekey yields a bundle without a one-time KEM prekey.
    let bob_last_resort_builder = support::TestStoreBuilder::new()
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    let bob_bundle_last_resort = bob_last_resort_builder.make_bundle_with_latest_keys(1.into());
    assert!(
        bob_bundle_last_resort.one_time_kyber_pre_key_id()?.is_none(),
        "expected no one-time KEM prekey in the last-resort-only bundle"
    );

    let alice_store = support::test_in_memory_protocol_store()?;

    c.bench_function("initiate session and encrypt first message", |b| {
        b.iter_batched(
            || alice_store.clone(),
            |mut alice_store| {
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bob_bundle_full,
                    SystemTime::now(),
                    &mut OsRng.unwrap_err(),
                )
                .now_or_never()
                .expect("sync")
                .expect("valid bundle");
                support::encrypt(&mut alice_store, &bob_address, "a short message")
                    .now_or_never()
                    .expect("sync")
                    .expect("success");
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function(
        "initiate session and encrypt first message, last-resort only",
        |b| {
            b.iter_batched(
                || alice_store.clone(),
                |mut alice_store| {
                    process_prekey_bundle(
                        &bob_address,
                        &mut alice_store.session_store,
                        &mut alice_store.identity_store,
                        &bob_bundle_last_resort,
                        SystemTime::now(),
                        &mut OsRng.unwrap_err(),
                    )
                    .now_or_never()
                    .expect("sync")
                    .expect("valid bundle");
                    support::encrypt(&mut alice_store, &bob_address, "a short message")
                        .now_or_never()
                        .expect("sync")
                        .expect("success");
                },
                criterion::BatchSize::SmallInput,
            )
        },
    );

    Ok(())
}

/// Responder span: decrypting a genuine initial `PreKeySignalMessage`, which is the side that
/// performs the KEM decapsulation and derives the session.
///
/// Both spans build their session through `process_prekey_bundle`, which is what causes
/// `message_encrypt` to emit a `PreKeySignalMessage` rather than a `Whisper`. The pre-existing
/// `session decrypt first message` span does not do this, so it is not a full-mode counterpart to
/// these; see the note in the harness report.
pub fn session_decrypt_first_message_modes_result(
    c: &mut Criterion,
) -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng.unwrap_err();
    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    // Full mode: signed last-resort plus one-time KEM prekey.
    let mut bob_store_full = support::TestStoreBuilder::new().store;
    let bob_bundle_full = support::create_pre_key_bundle(&mut bob_store_full, &mut csprng)
        .now_or_never()
        .expect("sync")?;

    let mut alice_store = support::test_in_memory_protocol_store()?;
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle_full,
        SystemTime::now(),
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")?;
    let full_mode_message = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;
    assert_eq!(
        full_mode_message.message_type(),
        CiphertextMessageType::PreKey
    );
    let full_mode_bytes = full_mode_message.serialize().to_vec();

    c.bench_function("session decrypt first message, full mode", |b| {
        b.iter_batched(
            || bob_store_full.clone(),
            |mut bob_store| {
                let received = CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(full_mode_bytes.as_slice())
                        .expect("valid wire form"),
                );
                support::decrypt(&mut bob_store, &alice_address, &received)
                    .now_or_never()
                    .expect("sync")
                    .expect("success");
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Last-resort-only mode, via the builder pattern.
    let bob_last_resort_builder = support::TestStoreBuilder::new()
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    let bob_bundle_last_resort = bob_last_resort_builder.make_bundle_with_latest_keys(1.into());
    assert!(
        bob_bundle_last_resort.one_time_kyber_pre_key_id()?.is_none(),
        "expected no one-time KEM prekey in the last-resort-only bundle"
    );
    let bob_store_last_resort = bob_last_resort_builder.store;

    let mut alice_store = support::test_in_memory_protocol_store()?;
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle_last_resort,
        SystemTime::now(),
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")?;
    let last_resort_message = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;
    assert_eq!(
        last_resort_message.message_type(),
        CiphertextMessageType::PreKey
    );
    let last_resort_bytes = last_resort_message.serialize().to_vec();

    c.bench_function("session decrypt first message, last-resort only", |b| {
        b.iter_batched(
            || bob_store_last_resort.clone(),
            |mut bob_store| {
                let received = CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(last_resort_bytes.as_slice())
                        .expect("valid wire form"),
                );
                support::decrypt(&mut bob_store, &alice_address, &received)
                    .now_or_never()
                    .expect("sync")
                    .expect("success");
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
/// One mode only: the responder's bundle carries the signed KEM prekey and the one-time KEM
/// prekey. Both messages cross the timed region in serialised form, as they would on the wire.
pub fn session_establish_and_first_exchange_result(
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
        bob_bundle.one_time_kyber_pre_key_id()?.is_some(),
        "expected a one-time KEM prekey in the full-mode bundle"
    );

    let alice_store = support::test_in_memory_protocol_store()?;

    c.bench_function("session establishment and first exchange", |b| {
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

pub fn session_encrypt(c: &mut Criterion) {
    session_encrypt_result(c).expect("success");
}

pub fn session_encrypt_decrypt(c: &mut Criterion) {
    session_encrypt_decrypt_result(c).expect("success");
}

pub fn session_initiate(c: &mut Criterion) {
    session_initiate_result(c).expect("no errors");
}

pub fn session_decrypt_first_message_modes(c: &mut Criterion) {
    session_decrypt_first_message_modes_result(c).expect("no errors");
}

pub fn session_establish_and_first_exchange(c: &mut Criterion) {
    session_establish_and_first_exchange_result(c).expect("no errors");
}

criterion_group!(
    benches,
    session_encrypt,
    session_encrypt_decrypt,
    session_initiate,
    session_decrypt_first_message_modes,
    session_establish_and_first_exchange
);

criterion_main!(benches);
