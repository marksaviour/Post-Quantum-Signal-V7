//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Handshake-level tests for the fully post-quantum PQXDH key agreement.
//!
//! The classic X3DH known-answer vectors (`test_ratcheting_session_as_alice/bob`) used fixed
//! Curve25519 identity keys and Diffie-Hellman agreement. Those no longer apply: the identity key
//! is now ML-DSA-87 (authentication only) and the shared secret comes entirely from ML-KEM-1024
//! encapsulations. These tests exercise the new construction directly.

use libsignal_protocol::*;
use rand::TryRngCore as _;

mod support;
use support::*;

/// Drive the Alice/Bob halves of the handshake directly and confirm they derive the same chain
/// keys, both with and without a one-time KEM prekey.
fn alice_and_bob_agree(with_one_time_kem: bool) -> Result<(), SignalProtocolError> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();

    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);

    let alice_base_key = KeyPair::generate(&mut csprng);
    // Bob's signed X25519 ratchet key (used only by the Double Ratchet) and ML-KEM-1024 prekeys.
    let bob_ratchet_key = KeyPair::generate(&mut csprng);
    let bob_signed_kem = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut csprng);
    let bob_one_time_kem = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut csprng);

    let mut alice_params = AliceSignalProtocolParameters::new(
        alice_identity,
        alice_base_key,
        *bob_identity.identity_key(),
        bob_ratchet_key.public_key,
        bob_signed_kem.public_key.clone(),
    );
    if with_one_time_kem {
        alice_params.set_their_one_time_kem_pre_key(&bob_one_time_kem.public_key);
    }

    let alice_record = initialize_alice_session_record(&alice_params, &mut csprng)?;

    assert_eq!(
        KYBER_AWARE_MESSAGE_VERSION,
        alice_record.session_version().expect("must have a version")
    );

    let kem_ciphertext = alice_record
        .get_kyber_ciphertext()?
        .expect("must have KEM ciphertext")
        .clone()
        .into_boxed_slice();
    let one_time_ciphertext = alice_record
        .get_pq_one_time_ciphertext()?
        .map(|ct| ct.clone().into_boxed_slice());
    assert_eq!(one_time_ciphertext.is_some(), with_one_time_kem);
    let signature = alice_record
        .get_identity_signature()?
        .expect("must have transcript signature")
        .clone();

    let bob_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_ratchet_key,
        bob_signed_kem,
        with_one_time_kem.then_some(bob_one_time_kem),
        *alice_identity.identity_key(),
        alice_base_key.public_key,
        &kem_ciphertext,
        one_time_ciphertext.as_ref(),
        &signature,
    );
    let bob_record = initialize_bob_session_record(&bob_params)?;

    assert_eq!(
        KYBER_AWARE_MESSAGE_VERSION,
        bob_record.session_version().expect("must have a version")
    );

    assert_eq!(
        bob_record
            .get_sender_chain_key_bytes()
            .expect("bob should have chain key"),
        alice_record
            .get_receiver_chain_key_bytes(&bob_ratchet_key.public_key)
            .expect("should have chain key")
            .expect("chain key present")
            .to_vec()
    );

    Ok(())
}

#[test]
fn test_alice_and_bob_agree_with_one_time_kem_prekey() -> Result<(), SignalProtocolError> {
    alice_and_bob_agree(true)
}

#[test]
fn test_alice_and_bob_agree_without_one_time_kem_prekey() -> Result<(), SignalProtocolError> {
    alice_and_bob_agree(false)
}

/// Bob must reject the handshake if Alice's ML-DSA transcript signature is invalid.
#[test]
fn test_bob_rejects_bad_transcript_signature() -> Result<(), SignalProtocolError> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();

    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);

    let alice_base_key = KeyPair::generate(&mut csprng);
    let bob_ratchet_key = KeyPair::generate(&mut csprng);
    let bob_signed_kem = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut csprng);

    let alice_params = AliceSignalProtocolParameters::new(
        alice_identity,
        alice_base_key,
        *bob_identity.identity_key(),
        bob_ratchet_key.public_key,
        bob_signed_kem.public_key.clone(),
    );
    let alice_record = initialize_alice_session_record(&alice_params, &mut csprng)?;

    let kem_ciphertext = alice_record
        .get_kyber_ciphertext()?
        .expect("must have KEM ciphertext")
        .clone()
        .into_boxed_slice();
    let mut signature = alice_record
        .get_identity_signature()?
        .expect("must have transcript signature")
        .clone();

    // Corrupt the signature.
    signature[0] ^= 0xFF;

    let bob_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_ratchet_key,
        bob_signed_kem,
        None,
        *alice_identity.identity_key(),
        alice_base_key.public_key,
        &kem_ciphertext,
        None,
        &signature,
    );

    let result = initialize_bob_session_record(&bob_params);
    assert!(
        matches!(result, Err(SignalProtocolError::SignatureValidationFailed)),
        "Bob must reject a tampered transcript signature"
    );

    Ok(())
}
