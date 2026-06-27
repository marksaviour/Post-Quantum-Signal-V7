//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Runnable demonstration of the fully post-quantum PQXDH handshake.
//!
//! Run it with:
//!
//! ```sh
//! cargo run -p libsignal-protocol --example pqxdh
//! ```
//!
//! It walks through the whole construction:
//!   * ML-DSA-87 identity keys (authentication only — no Diffie-Hellman),
//!   * Bob's ML-KEM-1024 prekeys authenticated by his ML-DSA identity,
//!   * the KEM-only shared secret `0xFF*32 || ss1 || ss2`,
//!   * Alice's ML-DSA transcript authenticator,
//!   * agreement on identical chain keys with NO X25519 in the secret, and
//!   * rejection of a tampered transcript signature and a tampered prekey signature.

use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

fn main() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();

    println!("=== Fully post-quantum PQXDH  (ML-KEM-1024 + ML-DSA-87) ===\n");

    // --- Long-term identities: ML-DSA-87 signing keypairs (no agreement) ---------------------
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_identity = IdentityKeyPair::generate(&mut rng);

    // --- Bob's prekeys ----------------------------------------------------------------------
    // A small signed X25519 key used ONLY by the Double Ratchet (never in the handshake secret),
    let bob_ratchet_key = KeyPair::generate(&mut rng);
    // a signed (last-resort) ML-KEM-1024 prekey, and an optional one-time ML-KEM-1024 prekey.
    let bob_signed_kem = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut rng);
    let bob_one_time_kem = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut rng);

    println!("Primitive sizes (bytes, excluding 1-byte type tags):");
    println!("  ML-DSA-87 identity public key : {}", dsa::PUBLIC_KEY_LENGTH);
    println!("  ML-DSA-87 identity secret key : {}", dsa::SECRET_KEY_LENGTH);
    println!("  ML-DSA-87 signature           : {}", dsa::SIGNATURE_LENGTH);
    println!(
        "  ML-KEM-1024 public key        : {}",
        bob_signed_kem.public_key.serialize().len() - 1
    );

    // --- Bob authenticates his prekeys with his ML-DSA identity -----------------------------
    let signed_kem_public = bob_signed_kem.public_key.serialize();
    let bob_prekey_signature = bob_identity.sign(&signed_kem_public, &mut rng)?;
    let verified = bob_identity
        .identity_key()
        .verify_signature(&signed_kem_public, &bob_prekey_signature);
    println!(
        "\n[1] Bob signs his ML-KEM prekey with ML-DSA; Alice verifies it: {}",
        if verified { "OK" } else { "FAILED" }
    );
    assert!(verified);

    // --- Alice's half of the handshake ------------------------------------------------------
    let alice_base_key = KeyPair::generate(&mut rng);
    let alice_params = AliceSignalProtocolParameters::new(
        alice_identity,
        alice_base_key,
        *bob_identity.identity_key(),
        bob_ratchet_key.public_key,
        bob_signed_kem.public_key.clone(),
    )
    .with_their_one_time_kem_pre_key(&bob_one_time_kem.public_key);

    let alice_session = initialize_alice_session_record(&alice_params, &mut rng)?;

    let ct1 = alice_session
        .get_kyber_ciphertext()?
        .expect("signed KEM ciphertext")
        .clone()
        .into_boxed_slice();
    let ct2 = alice_session
        .get_pq_one_time_ciphertext()?
        .expect("one-time KEM ciphertext")
        .clone()
        .into_boxed_slice();
    let transcript_signature = alice_session
        .get_identity_signature()?
        .expect("transcript signature")
        .clone();

    println!(
        "[2] Alice encapsulates to Bob's signed + one-time ML-KEM prekeys -> ct1 ({} B), ct2 ({} B)",
        ct1.len(),
        ct2.len()
    );
    println!(
        "[3] Alice signs the handshake transcript with ML-DSA -> authenticator ({} B)",
        transcript_signature.len()
    );

    // --- Bob's half of the handshake --------------------------------------------------------
    let bob_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_ratchet_key,
        bob_signed_kem.clone(),
        Some(bob_one_time_kem.clone()),
        *alice_identity.identity_key(),
        alice_base_key.public_key,
        &ct1,
        Some(&ct2),
        &transcript_signature,
    );
    let bob_session = initialize_bob_session_record(&bob_params)?;
    println!("[4] Bob decapsulates and verifies Alice's transcript signature: OK");

    // --- Confirm both sides derived the same key material -----------------------------------
    let alice_chain = alice_session
        .get_receiver_chain_key_bytes(&bob_ratchet_key.public_key)?
        .expect("alice receiver chain");
    let bob_chain = bob_session.get_sender_chain_key_bytes()?;
    assert_eq!(&alice_chain[..], &bob_chain[..]);
    println!("\n>>> Agreement succeeded with NO X25519 in the secret (secret = 0xFF*32 || ss1 || ss2).");
    println!("    shared chain key = {}", hex::encode(&bob_chain));

    // --- Negative test 1: tampered transcript signature -------------------------------------
    let mut bad_signature = transcript_signature.clone();
    bad_signature[0] ^= 0xFF;
    let tampered_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_ratchet_key,
        bob_signed_kem.clone(),
        Some(bob_one_time_kem.clone()),
        *alice_identity.identity_key(),
        alice_base_key.public_key,
        &ct1,
        Some(&ct2),
        &bad_signature,
    );
    match initialize_bob_session_record(&tampered_params) {
        Err(SignalProtocolError::SignatureValidationFailed) => {
            println!("\n[neg] Tampered transcript signature correctly REJECTED.")
        }
        Err(other) => panic!("expected SignatureValidationFailed, got {other}"),
        Ok(_) => panic!("expected rejection, but the tampered handshake was accepted!"),
    }

    // --- Negative test 2: tampered prekey signature -----------------------------------------
    let mut bad_prekey_sig = bob_prekey_signature.to_vec();
    bad_prekey_sig[0] ^= 0xFF;
    let prekey_ok = bob_identity
        .identity_key()
        .verify_signature(&signed_kem_public, &bad_prekey_sig);
    println!(
        "[neg] Tampered ML-KEM prekey signature correctly REJECTED: {}",
        if prekey_ok { "NO (bug!)" } else { "yes" }
    );
    assert!(!prekey_ok);

    println!("\nAll checks passed.");
    Ok(())
}
