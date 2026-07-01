//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Runnable demonstration of the *complete* fully post-quantum Signal protocol.
//!
//! Run it with:
//!
//! ```sh
//! cargo run -p libsignal-protocol --example full_session
//! ```
//!
//! Whereas `examples/pqxdh.rs` demonstrates only the raw PQXDH handshake math (working directly
//! with `AliceSignalProtocolParameters` / `initialize_*_session_record`), this example drives the
//! real public API end to end through in-memory protocol stores — exactly the path a Signal
//! client takes:
//!
//!   1. Alice and Bob each get an ML-DSA-87 identity and an empty store.
//!   2. Bob publishes a prekey bundle (signed X25519 ratchet key + signed HQC-256 prekey + a
//!      one-time HQC-256 prekey, all authenticated by his ML-DSA identity).
//!   3. Alice verifies the bundle's signatures and builds a session (PQXDH handshake).
//!   4. Alice sends the initial `PreKeySignalMessage`; Bob decrypts it and derives the matching
//!      session.
//!   5. Bob replies with a `Whisper` message; Alice decrypts it.
//!   6. Both sides exchange many ordered messages, exercising the Double Ratchet.
//!   7. Messages are also delivered out of order to show skipped-message-key handling.
//!
//! Every ciphertext is round-tripped through its serialized "wire" form to mirror real transport.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};

fn main() -> Result<(), SignalProtocolError> {
    // HQC-256 and ML-DSA-87 values are large, and driving the whole protocol as a single async
    // state machine needs more than the default ~1 MiB main-thread stack on some platforms
    // (notably Windows). Run it on a thread with a roomier stack; the test harness gives its
    // threads more stack implicitly, which is why the equivalent integration test does not need
    // this. Every in-memory store operation resolves immediately, so the async protocol API can
    // be driven to completion synchronously with `now_or_never`.
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            async { run().await }
                .now_or_never()
                .expect("in-memory stores never yield")
        })
        .expect("failed to spawn worker thread")
        .join()
        .expect("worker thread panicked")
}

async fn run() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();

    println!("=== Full post-quantum Signal protocol (HQC-256 KEM + ML-DSA-87 identity) ===\n");

    // --- 1. Identities and stores ----------------------------------------------------------
    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

    let mut alice_store = make_store(&mut rng)?;
    let mut bob_store = make_store(&mut rng)?;
    println!("[1] Generated ML-DSA-87 identities and empty in-memory stores for Alice and Bob.");

    // --- 2. Bob publishes a signed prekey bundle -------------------------------------------
    let bob_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;
    println!(
        "[2] Bob published a prekey bundle (every item signed with ML-DSA-87):\n      \
         - signed X25519 ratchet key  (Double Ratchet only -- never enters the PQXDH secret)\n      \
         - signed HQC-256 prekey + one-time HQC-256 prekey  (the sole source of the shared secret)\n    \
         Signed HQC-256 public key: {} B.",
        bob_bundle.kyber_pre_key_public()?.serialize().len() - 1
    );

    // --- 3. Alice verifies the bundle and establishes a session ----------------------------
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        SystemTime::now(),
        &mut rng,
    )
    .await?;

    let version = alice_store
        .load_session(&bob_address)
        .await?
        .expect("session was created")
        .session_version()?;
    println!(
        "[3] Alice verified Bob's ML-DSA signatures and ran PQXDH -> session established \
         (version {version} = post-quantum)."
    );

    // --- 4. Alice's initial message (a PreKeySignalMessage) --------------------------------
    let m1 = "Meet me where the quantum computers can't read us.";
    let outgoing = encrypt(&mut alice_store, &bob_address, m1).await?;
    assert_eq!(outgoing.message_type(), CiphertextMessageType::PreKey);
    println!(
        "\n[4] Alice -> Bob  [PreKey, {} B on the wire]: {m1:?}",
        outgoing.serialize().len()
    );

    let received = over_the_wire(&outgoing)?;
    let plaintext = decrypt(&mut bob_store, &alice_address, &received).await?;
    assert_eq!(plaintext, m1.as_bytes());
    println!(
        "    Bob decrypted it and derived the matching session: {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    // --- 5. Bob replies (a Whisper / SignalMessage) ----------------------------------------
    let m2 = "Acknowledged. The ratchet is already turning.";
    let reply = encrypt(&mut bob_store, &alice_address, m2).await?;
    assert_eq!(reply.message_type(), CiphertextMessageType::Whisper);
    let received = over_the_wire(&reply)?;
    let plaintext = decrypt(&mut alice_store, &bob_address, &received).await?;
    assert_eq!(plaintext, m2.as_bytes());
    println!(
        "[5] Bob -> Alice  [Whisper, {} B on the wire]: {:?}",
        reply.serialize().len(),
        String::from_utf8_lossy(&plaintext)
    );

    // --- 6. Many ordered ratchet steps -----------------------------------------------------
    println!("\n[6] Exchanging 6 ordered messages to exercise the Double Ratchet...");
    for i in 0..3 {
        let a = format!("Alice ratchet message #{i}");
        let ct = encrypt(&mut alice_store, &bob_address, &a).await?;
        let pt = decrypt(&mut bob_store, &alice_address, &over_the_wire(&ct)?).await?;
        assert_eq!(pt, a.as_bytes());

        let b = format!("Bob ratchet message #{i}");
        let ct = encrypt(&mut bob_store, &alice_address, &b).await?;
        let pt = decrypt(&mut alice_store, &bob_address, &over_the_wire(&ct)?).await?;
        assert_eq!(pt, b.as_bytes());
    }
    println!("    All 6 delivered and verified in order.");

    // --- 7. Out-of-order delivery ----------------------------------------------------------
    println!(
        "\n[7] Out-of-order delivery: Alice sends 4 messages, Bob decrypts them in reverse..."
    );
    let mut pending = Vec::new();
    for i in 0..4 {
        let p = format!("out-of-order #{i}");
        let ct = encrypt(&mut alice_store, &bob_address, &p).await?;
        pending.push((p, over_the_wire(&ct)?));
    }
    for (p, ct) in pending.into_iter().rev() {
        let pt = decrypt(&mut bob_store, &alice_address, &ct).await?;
        assert_eq!(pt, p.as_bytes());
        println!("    Bob recovered {p:?} using a skipped message key.");
    }

    println!("\nAll checks passed. The full post-quantum protocol ran end to end.");
    Ok(())
}

/// Create an in-memory store backed by a freshly generated ML-DSA-87 identity.
fn make_store<R: Rng + CryptoRng>(
    csprng: &mut R,
) -> Result<InMemSignalProtocolStore, SignalProtocolError> {
    let identity = IdentityKeyPair::generate(&mut *csprng);
    // Valid registration IDs fit in 14 bits.
    let registration_id: u8 = csprng.random();
    InMemSignalProtocolStore::new(identity, registration_id as u32)
}

/// Encrypt a UTF-8 string to `remote_address` using the sender's session and identity stores.
async fn encrypt(
    store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &str,
) -> Result<CiphertextMessage, SignalProtocolError> {
    message_encrypt(
        msg.as_bytes(),
        remote_address,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
    )
    .await
}

/// Decrypt a ciphertext from `remote_address`, consuming any one-time prekeys as needed.
async fn decrypt(
    store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<Vec<u8>, SignalProtocolError> {
    let mut csprng = OsRng.unwrap_err();
    message_decrypt(
        msg,
        remote_address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut csprng,
    )
    .await
}

/// Serialize a ciphertext and parse it back, mirroring what happens when a message is sent over
/// the network and reconstructed by the receiver.
fn over_the_wire(msg: &CiphertextMessage) -> Result<CiphertextMessage, SignalProtocolError> {
    let bytes = msg.serialize();
    Ok(match msg.message_type() {
        CiphertextMessageType::PreKey => {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(bytes)?)
        }
        CiphertextMessageType::Whisper => {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(bytes)?)
        }
        other => panic!("this example only sends PreKey and Whisper messages, got {other:?}"),
    })
}

/// Build a fully post-quantum prekey bundle for `store`'s owner and persist the matching private
/// keys, so the owner can later answer a session built from the bundle.
async fn create_pre_key_bundle<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    csprng: &mut R,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let identity = store.get_identity_key_pair().await?;

    // The signed X25519 ratchet key seeds the Double Ratchet only; it never enters the PQXDH
    // shared secret. ML-DSA authenticates it.
    let signed_pre_key_pair = KeyPair::generate(&mut *csprng);
    let signed_pre_key_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut *csprng)?;

    // Bob's signed (last-resort) HQC-256 prekey.
    let signed_kyber_pair = kem::KeyPair::generate(kem::KeyType::HQC256, &mut *csprng);
    let signed_kyber_signature = identity
        .private_key()
        .calculate_signature(&signed_kyber_pair.public_key.serialize(), &mut *csprng)?;

    // Bob's one-time HQC-256 prekey.
    let one_time_kyber_pair = kem::KeyPair::generate(kem::KeyType::HQC256, &mut *csprng);
    let one_time_kyber_signature = identity
        .private_key()
        .calculate_signature(&one_time_kyber_pair.public_key.serialize(), &mut *csprng)?;

    let device_id = 1u32;
    let signed_pre_key_id = 1u32;
    let signed_kyber_id = 1u32;
    let one_time_kyber_id = 2u32;

    let bundle = PreKeyBundle::new(
        store.get_local_registration_id().await?,
        device_id.into(),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        signed_kyber_id.into(),
        signed_kyber_pair.public_key.clone(),
        signed_kyber_signature.to_vec(),
        *identity.identity_key(),
    )?
    .with_one_time_kyber_pre_key(
        one_time_kyber_id.into(),
        one_time_kyber_pair.public_key.clone(),
        one_time_kyber_signature.to_vec(),
    );

    // Persist the private halves so the bundle owner can complete the handshake later.
    store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                Timestamp::from_epoch_millis(0),
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .await?;
    store
        .save_kyber_pre_key(
            signed_kyber_id.into(),
            &KyberPreKeyRecord::new(
                signed_kyber_id.into(),
                Timestamp::from_epoch_millis(0),
                &signed_kyber_pair,
                &signed_kyber_signature,
            ),
        )
        .await?;
    store
        .save_kyber_pre_key(
            one_time_kyber_id.into(),
            &KyberPreKeyRecord::new(
                one_time_kyber_id.into(),
                Timestamp::from_epoch_millis(0),
                &one_time_kyber_pair,
                &one_time_kyber_signature,
            ),
        )
        .await?;

    Ok(bundle)
}
