//
// Copyright 2020 Signal Messenger, LLC.
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

use rand::{CryptoRng, Rng};

pub(crate) use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::state::SessionState;
use crate::{IdentityKey, KeyPair, PublicKey, Result, SessionRecord, SignalProtocolError};

/// HKDF label for the fully post-quantum PQXDH key derivation.
///
/// The secret input is `0xFF*32 || ss1 || ss2`, where `ss1`/`ss2` are the
/// ML-KEM-1024 shared secrets from the signed and (optional) one-time KEM
/// prekeys. No X25519 agreement contributes to this secret.
const PQXDH_LABEL: &[u8] = b"PQXDH_MLKEM1024_MLDSA87_SHA-256";

/// Domain-separation label prefixed to the signed handshake transcript.
const PQXDH_TRANSCRIPT_LABEL: &[u8] = b"PQXDH_MLKEM1024_MLDSA87_transcript";

fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey) {
    derive_keys_with_label(PQXDH_LABEL, secret_input)
}

fn message_version() -> u8 {
    CIPHERTEXT_MESSAGE_CURRENT_VERSION
}

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey) {
    let mut secrets = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes) = secrets.split_at(32);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);

    (root_key, chain_key)
}

/// Build the byte string that the initiator (Alice) signs with her ML-DSA identity key and that the
/// responder (Bob) verifies.
///
/// Each component is length-prefixed to remove any concatenation ambiguity. The transcript binds
/// both identities, both KEM ciphertexts, Bob's signed ratchet key, and Alice's base key:
/// `label || her_IK || ct1 || ct2 || their_IK || their_ratchet_key || base_key`.
fn handshake_transcript(
    alice_identity: &IdentityKey,
    ct1: &[u8],
    ct2: &[u8],
    bob_identity: &IdentityKey,
    bob_ratchet_key: &PublicKey,
    alice_base_key: &PublicKey,
) -> Vec<u8> {
    let alice_ik = alice_identity.serialize();
    let bob_ik = bob_identity.serialize();
    let ratchet = bob_ratchet_key.serialize();
    let base = alice_base_key.serialize();

    let parts: [&[u8]; 7] = [
        PQXDH_TRANSCRIPT_LABEL,
        &alice_ik,
        ct1,
        ct2,
        &bob_ik,
        &ratchet,
        &base,
    ];

    let mut transcript = Vec::new();
    for part in parts {
        transcript.extend_from_slice(&(part.len() as u32).to_be_bytes());
        transcript.extend_from_slice(part);
    }
    transcript
}

pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    // Confidentiality + forward secrecy come entirely from ML-KEM-1024:
    //   ss1 <- encapsulate to Bob's signed (last-resort) KEM prekey   [mandatory]
    //   ss2 <- encapsulate to Bob's one-time KEM prekey               [optional]
    let (ss1, ct1) = parameters.their_signed_kem_pre_key().encapsulate(&mut csprng)?;
    let (ss2, ct2) = match parameters.their_one_time_kem_pre_key() {
        Some(one_time) => {
            let (ss, ct) = one_time.encapsulate(&mut csprng)?;
            (Some(ss), Some(ct))
        }
        None => (None, None),
    };

    let mut secrets = Vec::with_capacity(32 * 3);
    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"
    secrets.extend_from_slice(ss1.as_ref());
    if let Some(ss2) = &ss2 {
        secrets.extend_from_slice(ss2.as_ref());
    }

    let (root_key, chain_key) = derive_keys(&secrets);

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    // Alice -> Bob authenticator: an ML-DSA signature over the handshake transcript.
    let ct2_bytes: &[u8] = ct2.as_deref().unwrap_or(&[]);
    let transcript = handshake_transcript(
        local_identity,
        &ct1,
        ct2_bytes,
        parameters.their_identity_key(),
        parameters.their_ratchet_key(),
        &parameters.our_base_key_pair().public_key,
    );
    let signature = parameters
        .our_identity_key_pair()
        .sign(&transcript, &mut csprng)?;

    let mut session = SessionState::new(
        message_version(),
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_kyber_ciphertext(ct1);
    if let Some(ct2) = ct2 {
        session.set_pq_one_time_ciphertext(ct2);
    }
    session.set_identity_signature(&signature);

    Ok(session)
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    // Decapsulate ss1 (mandatory) and ss2 (optional).
    let ss1 = parameters
        .our_signed_kem_pre_key_pair()
        .secret_key
        .decapsulate(parameters.their_kem_ciphertext())?;

    let ss2 = match (
        parameters.our_one_time_kem_pre_key_pair(),
        parameters.their_one_time_kem_ciphertext(),
    ) {
        (Some(key_pair), Some(ciphertext)) => {
            Some(key_pair.secret_key.decapsulate(ciphertext)?)
        }
        (None, None) => None,
        _ => {
            return Err(SignalProtocolError::InvalidArgument(
                "one-time KEM prekey and ciphertext must both be present or both absent".to_string(),
            ));
        }
    };

    let mut secrets = Vec::with_capacity(32 * 3);
    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"
    secrets.extend_from_slice(ss1.as_ref());
    if let Some(ss2) = &ss2 {
        secrets.extend_from_slice(ss2.as_ref());
    }

    let (root_key, chain_key) = derive_keys(&secrets);

    // Verify Alice's ML-DSA authenticator over the handshake transcript; reject on failure.
    let ct2_bytes: &[u8] = parameters
        .their_one_time_kem_ciphertext()
        .map(|ct| ct.as_ref())
        .unwrap_or(&[]);
    let transcript = handshake_transcript(
        parameters.their_identity_key(),
        parameters.their_kem_ciphertext(),
        ct2_bytes,
        local_identity,
        &parameters.our_ratchet_key_pair().public_key,
        parameters.their_base_key(),
    );
    if !parameters
        .their_identity_key()
        .verify_signature(&transcript, parameters.their_signature())
    {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let session = SessionState::new(
        message_version(),
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
