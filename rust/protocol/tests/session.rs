//
// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Integration tests for the fully post-quantum PQXDH session establishment and the (unchanged)
//! Double Ratchet that runs on top of it.
//!
//! The handshake here uses an ML-DSA-87 identity (authentication only), ML-KEM-1024 signed and
//! one-time prekeys for confidentiality, and an ML-DSA-87 transcript authenticator. No X25519
//! Diffie-Hellman contributes to the root key; X25519 survives only as the Double Ratchet's
//! `ratchet_key`.

mod support;

use std::time::{Duration, SystemTime};

use assert_matches::assert_matches;
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use support::*;

type TestResult = Result<(), SignalProtocolError>;

// Use this function to debug tests
#[allow(dead_code)]
fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

// ---------------------------------------------------------------------------
// Handshake-from-bundle tests
// ---------------------------------------------------------------------------

/// Full end-to-end PQXDH handshake: Alice builds a session from Bob's signed bundle, sends a
/// PreKeySignalMessage, Bob establishes the matching session and replies, then both ratchet
/// through many ordered and out-of-order messages.
#[test]
fn test_full_pq_prekey_handshake() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        // Bob publishes a signed bundle (signed X25519 ratchet key + signed & one-time
        // ML-KEM-1024 prekeys, all authenticated by his ML-DSA identity).
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        assert!(alice_store.load_session(&bob_address).await?.is_some());
        assert_eq!(
            alice_store.session_version(&bob_address)?,
            KYBER_AWARE_MESSAGE_VERSION
        );

        let original_message = "L'homme est condamné à être libre";
        let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message).await?;
        assert_eq!(
            outgoing_message.message_type(),
            CiphertextMessageType::PreKey
        );

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message.serialize())?,
        );

        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message).await?;
        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        // Bob now has a matching session and can reply.
        let bobs_session = bob_store
            .load_session(&alice_address)
            .await?
            .expect("session found");
        assert_eq!(bobs_session.session_version()?, KYBER_AWARE_MESSAGE_VERSION);

        let bobs_response = "Who watches the watchers?";
        let bob_outgoing = encrypt(&mut bob_store, &alice_address, bobs_response).await?;
        assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);

        let alice_decrypts = decrypt(&mut alice_store, &bob_address, &bob_outgoing).await?;
        assert_eq!(
            String::from_utf8(alice_decrypts).expect("valid utf8"),
            bobs_response
        );

        // Exercise the Double Ratchet thoroughly.
        run_interaction(
            &mut alice_store,
            &alice_address,
            &mut bob_store,
            &bob_address,
        )
        .await?;

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// The one-time KEM prekey is optional: if Bob's bundle has only the signed (last-resort) KEM
/// prekey, the handshake must still succeed (the secret is `0xFF*32 || ss1`).
#[test]
fn test_prekey_handshake_without_one_time_kem() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        // A builder with exactly one kyber prekey yields a bundle without a one-time KEM prekey.
        let mut bob_store_builder = TestStoreBuilder::new()
            .with_signed_pre_key(22.into())
            .with_kyber_pre_key(8000.into());
        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());
        assert!(
            bob_pre_key_bundle
                .one_time_kyber_pre_key_id()?
                .is_none(),
            "expected no one-time KEM prekey in this bundle"
        );

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let message = "no one-time prekey needed";
        let outgoing = encrypt(&mut alice_store, &bob_address, message).await?;
        let incoming = CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
            outgoing.serialize(),
        )?);
        let ptext = decrypt(&mut bob_store_builder.store, &alice_address, &incoming).await?;
        assert_eq!(String::from_utf8(ptext).expect("valid utf8"), message);

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// A bad ML-DSA signature over Bob's signed X25519 ratchet key must be rejected.
#[test]
fn test_bad_signed_pre_key_signature() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let bob_store_builder = TestStoreBuilder::new()
            .with_signed_pre_key(22.into())
            .with_kyber_pre_key(8000.into());

        let good_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

        // Flipping any of a sampling of bits in the signature must be detected. (ML-DSA signatures
        // are thousands of bytes, so we sample rather than exhaustively flip every bit.)
        let sig_len = good_bundle
            .signed_pre_key_signature()
            .expect("has signature")
            .len();
        for bit in (0..8 * sig_len).step_by(811) {
            let mut bad_signature = good_bundle
                .signed_pre_key_signature()
                .expect("has signature")
                .to_vec();
            bad_signature[bit / 8] ^= 0x01u8 << (bit % 8);

            let bad_bundle = good_bundle
                .clone()
                .modify(|content| content.ec_pre_key_signature = Some(bad_signature))
                .expect("can recreate the bundle");

            assert!(matches!(
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bad_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await,
                Err(SignalProtocolError::SignatureValidationFailed)
            ));
        }

        // The untouched signature is accepted.
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &good_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// A bad ML-DSA signature over Bob's signed ML-KEM-1024 prekey must be rejected.
#[test]
fn test_bad_kyber_pre_key_signature() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let bob_store_builder = TestStoreBuilder::new()
            .with_signed_pre_key(22.into())
            .with_kyber_pre_key(8000.into());

        let good_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

        let mut bad_signature = good_bundle.kyber_pre_key_signature().expect("sig").to_vec();
        bad_signature[0] ^= 0xFF;

        let bad_bundle = good_bundle
            .clone()
            .modify(|content| content.kyber_pre_key_signature = Some(bad_signature))
            .expect("can recreate the bundle");

        assert!(matches!(
            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bad_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await,
            Err(SignalProtocolError::SignatureValidationFailed)
        ));

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// Several PreKeySignalMessages from the same unacknowledged session must all decrypt, and
/// re-processing the bundle/message is idempotent.
#[test]
fn test_repeat_bundle_message() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let original_message = "It's over, Anakin. I have the high ground.";
        let outgoing_one = encrypt(&mut alice_store, &bob_address, original_message).await?;
        let outgoing_two = encrypt(&mut alice_store, &bob_address, original_message).await?;
        assert_eq!(outgoing_one.message_type(), CiphertextMessageType::PreKey);
        assert_eq!(outgoing_two.message_type(), CiphertextMessageType::PreKey);

        // Bob decrypts the first message, establishing the session.
        let incoming_one = CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
            outgoing_one.serialize(),
        )?);
        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_one).await?;
        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        // The second PreKeySignalMessage decrypts against the already-established session.
        let incoming_two = CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
            outgoing_two.serialize(),
        )?);
        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_two).await?;
        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        // And Bob can reply on the Whisper session.
        let response = encrypt(&mut bob_store, &alice_address, "general kenobi").await?;
        let decrypted = decrypt(&mut alice_store, &bob_address, &response).await?;
        assert_eq!(
            String::from_utf8(decrypted).expect("valid utf8"),
            "general kenobi"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// When Alice and Bob initiate at the same time, they each create a distinct session, converge
/// after the first Whisper response, and end up sharing a single session.
#[test]
fn test_basic_simultaneous_initiate() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut csprng).await?;
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;
        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
        let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

        assert_eq!(message_for_bob.message_type(), CiphertextMessageType::PreKey);
        assert_eq!(
            message_for_alice.message_type(),
            CiphertextMessageType::PreKey
        );

        assert!(
            !is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?
        );

        let alice_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_alice.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(alice_plaintext).expect("valid utf8"),
            "hi alice"
        );

        let bob_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_bob.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "hi bob"
        );

        assert!(
            !is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?
        );

        let alice_response = encrypt(&mut alice_store, &bob_address, "nice to see you").await?;
        assert_eq!(
            alice_response.message_type(),
            CiphertextMessageType::Whisper
        );

        let response_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                alice_response.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "nice to see you"
        );

        assert!(is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?);

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// A PreKeySignalMessage whose inner ciphertext has been tampered with must fail to decrypt
/// without mutating Bob's stores.
#[test]
fn prekey_message_failed_decryption_does_not_update_stores() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let message = encrypt(&mut alice_store, &bob_address, "this will be corrupted").await?;
        let message = assert_matches!(message, CiphertextMessage::PreKeySignalMessage(m) => m);

        // Perturb the inner Double Ratchet ciphertext, leaving the handshake transcript intact.
        let mut signal_message = message.message().serialized().to_owned();
        let last_byte = signal_message.last_mut().unwrap();
        *last_byte = last_byte.wrapping_add(1);

        let corrupted = PreKeySignalMessage::new(
            message.message_version(),
            message.registration_id(),
            message.pre_key_id(),
            message.signed_pre_key_id(),
            message
                .kyber_pre_key_id()
                .zip(message.kyber_ciphertext())
                .map(|(id, ct)| KyberPayload::new(id, ct.clone())),
            message
                .pq_one_time_pre_key_id()
                .zip(message.pq_one_time_ciphertext())
                .map(|(id, ct)| KyberPayload::new(id, ct.clone())),
            message.identity_signature().into(),
            *message.base_key(),
            *message.identity_key(),
            (&*signal_message).try_into().unwrap(),
        )?;

        let before = bob_store.load_session(&alice_address).await?;
        assert!(before.is_none(), "no session should exist yet");

        let result = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(corrupted),
        )
        .await;
        assert!(result.is_err(), "tampered message must not decrypt");

        // The failed decryption must not have created/persisted a session.
        assert!(bob_store.load_session(&alice_address).await?.is_none());

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

/// An unacknowledged outbound session is unusable once it ages out.
#[test]
fn test_unacknowledged_sessions_eventually_expire() -> TestResult {
    async {
        const WELL_PAST_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 90);

        let mut csprng = OsRng.unwrap_err();
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .await?;

        let initial_session = alice_store
            .session_store
            .load_session(&bob_address)
            .await?
            .expect("session exists");
        assert!(initial_session
            .has_usable_sender_chain(SystemTime::UNIX_EPOCH)
            .expect("can check for a sender chain"));
        assert!(!initial_session
            .has_usable_sender_chain(SystemTime::UNIX_EPOCH + WELL_PAST_EXPIRATION)
            .expect("can check for a sender chain"));

        // Encrypting well past expiration fails because the unacknowledged session is too old.
        let result = message_encrypt(
            b"too late",
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::UNIX_EPOCH + WELL_PAST_EXPIRATION,
        )
        .await;
        assert!(matches!(result, Err(SignalProtocolError::SessionNotFound(_))));

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

// ---------------------------------------------------------------------------
// Double Ratchet tests driven by directly-initialized sessions
// ---------------------------------------------------------------------------

#[test]
fn test_basic_session() -> TestResult {
    let (alice_session, bob_session) = initialize_sessions_v3()?;
    run_session_interaction(alice_session, bob_session)?;

    let (alice_session, bob_session) = initialize_sessions_v4()?;
    run_session_interaction(alice_session, bob_session)?;
    Ok(())
}

#[test]
fn test_message_key_limits() -> TestResult {
    run(initialize_sessions_v3()?)?;
    run(initialize_sessions_v4()?)?;

    fn run(sessions: (SessionRecord, SessionRecord)) -> TestResult {
        async {
            let (alice_session_record, bob_session_record) = sessions;

            let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

            let mut alice_store = TestStoreBuilder::new().store;
            let mut bob_store = TestStoreBuilder::new().store;

            alice_store
                .store_session(&bob_address, &alice_session_record)
                .await?;
            bob_store
                .store_session(&alice_address, &bob_session_record)
                .await?;

            const MAX_MESSAGE_KEYS: usize = 2000; // same value as in library
            const TOO_MANY_MESSAGES: usize = MAX_MESSAGE_KEYS + 300;

            let mut inflight = Vec::with_capacity(TOO_MANY_MESSAGES);

            for i in 0..TOO_MANY_MESSAGES {
                inflight
                    .push(encrypt(&mut alice_store, &bob_address, &format!("It's over {i}")).await?);
            }

            assert_eq!(
                String::from_utf8(decrypt(&mut bob_store, &alice_address, &inflight[1000]).await?)
                    .expect("valid utf8"),
                "It's over 1000"
            );
            assert_eq!(
                String::from_utf8(
                    decrypt(
                        &mut bob_store,
                        &alice_address,
                        &inflight[TOO_MANY_MESSAGES - 1],
                    )
                    .await?
                )
                .expect("valid utf8"),
                format!("It's over {}", TOO_MANY_MESSAGES - 1)
            );

            let err = decrypt(&mut bob_store, &alice_address, &inflight[5])
                .await
                .unwrap_err();
            assert!(matches!(err, SignalProtocolError::DuplicatedMessage(2300, 5)));
            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn run_session_interaction(alice_session: SessionRecord, bob_session: SessionRecord) -> TestResult {
    async {
        use rand::seq::SliceRandom;

        let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        alice_store
            .store_session(&bob_address, &alice_session)
            .await?;
        bob_store.store_session(&alice_address, &bob_session).await?;

        let alice_plaintext = "This is Alice's message";
        let alice_ciphertext = encrypt(&mut alice_store, &bob_address, alice_plaintext).await?;
        let bob_decrypted = decrypt(&mut bob_store, &alice_address, &alice_ciphertext).await?;
        assert_eq!(
            String::from_utf8(bob_decrypted).expect("valid utf8"),
            alice_plaintext
        );

        let bob_plaintext = "This is Bob's reply";
        let bob_ciphertext = encrypt(&mut bob_store, &alice_address, bob_plaintext).await?;
        let alice_decrypted = decrypt(&mut alice_store, &bob_address, &bob_ciphertext).await?;
        assert_eq!(
            String::from_utf8(alice_decrypted).expect("valid utf8"),
            bob_plaintext
        );

        const ALICE_MESSAGE_COUNT: usize = 50;
        const BOB_MESSAGE_COUNT: usize = 50;

        let mut alice_messages = Vec::with_capacity(ALICE_MESSAGE_COUNT);
        for i in 0..ALICE_MESSAGE_COUNT {
            let ptext = format!("смерть за смерть {i}");
            let ctext = encrypt(&mut alice_store, &bob_address, &ptext).await?;
            alice_messages.push((ptext, ctext));
        }

        let mut rng = rand::rngs::OsRng.unwrap_err();
        alice_messages.shuffle(&mut rng);

        for message in alice_messages.iter().take(ALICE_MESSAGE_COUNT / 2) {
            let ptext = decrypt(&mut bob_store, &alice_address, &message.1).await?;
            assert_eq!(String::from_utf8(ptext).expect("valid utf8"), message.0);
        }

        let mut bob_messages = Vec::with_capacity(BOB_MESSAGE_COUNT);
        for i in 0..BOB_MESSAGE_COUNT {
            let ptext = format!("Relax in the safety of your own delusions. {i}");
            let ctext = encrypt(&mut bob_store, &alice_address, &ptext).await?;
            bob_messages.push((ptext, ctext));
        }

        bob_messages.shuffle(&mut rng);

        for message in bob_messages.iter().take(BOB_MESSAGE_COUNT / 2) {
            let ptext = decrypt(&mut alice_store, &bob_address, &message.1).await?;
            assert_eq!(String::from_utf8(ptext).expect("valid utf8"), message.0);
        }

        for message in alice_messages.iter().skip(ALICE_MESSAGE_COUNT / 2) {
            let ptext = decrypt(&mut bob_store, &alice_address, &message.1).await?;
            assert_eq!(String::from_utf8(ptext).expect("valid utf8"), message.0);
        }

        for message in bob_messages.iter().skip(BOB_MESSAGE_COUNT / 2) {
            let ptext = decrypt(&mut alice_store, &bob_address, &message.1).await?;
            assert_eq!(String::from_utf8(ptext).expect("valid utf8"), message.0);
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

async fn run_interaction(
    alice_store: &mut InMemSignalProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &mut InMemSignalProtocolStore,
    bob_address: &ProtocolAddress,
) -> TestResult {
    let alice_ptext = "It's rabbit season";
    let alice_message = encrypt(alice_store, bob_address, alice_ptext).await?;
    assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
            .expect("valid utf8"),
        alice_ptext
    );

    let bob_ptext = "It's duck season";
    let bob_message = encrypt(bob_store, alice_address, bob_ptext).await?;
    assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
            .expect("valid utf8"),
        bob_ptext
    );

    for i in 0..10 {
        let alice_ptext = format!("A->B message {i}");
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message {i}");
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    let mut alice_ooo_messages = vec![];
    for i in 0..10 {
        let alice_ptext = format!("A->B OOO message {i}");
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        alice_ooo_messages.push((alice_ptext, alice_message));
    }

    for i in 0..10 {
        let alice_ptext = format!("A->B post-OOO message {i}");
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for (ptext, ctext) in alice_ooo_messages {
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &ctext).await?).expect("valid utf8"),
            ptext
        );
    }

    Ok(())
}

async fn is_session_id_equal(
    alice_store: &dyn ProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &dyn ProtocolStore,
    bob_address: &ProtocolAddress,
) -> Result<bool, SignalProtocolError> {
    Ok(alice_store
        .load_session(bob_address)
        .await?
        .expect("session found")
        .alice_base_key()?
        == bob_store
            .load_session(alice_address)
            .await?
            .expect("session found")
            .alice_base_key()?)
}
