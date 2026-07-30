//
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Deterministic size capture for the fully post-quantum PQXDH handshake.
//!
//! Run it with:
//!
//! ```sh
//! cargo run --release -p libsignal-protocol --example sizes
//! ```
//!
//! Serialised lengths are deterministic, so this is an example rather than a Criterion benchmark:
//! it needs one run per artefact, not five, and putting it in a benchmark would imply the figures
//! vary. Timing lives in `benches/`; nothing here is timed.
//!
//! A serialised length is byte-exact only when the mode, plaintext, registration and device
//! identifiers, prekey identifiers, counters, and field presence are all fixed. Every one of those
//! is pinned by the constants below, so two runs on any machine produce identical output. Note that
//! the identifiers are protobuf varints, so their *values* — not merely their being fixed — affect
//! the encoded lengths reported here.
//!
//! Both KEM modes are reported: the mandatory signed last-resort prekey alone, and the last-resort
//! prekey plus a one-time prekey.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore as _};

/// Fixed plaintext for both the initial message and the first reply.
const PLAINTEXT: &str = "pqs-v7 fixed size-capture plaintext";
const DEVICE_ID: u32 = 1;
const SIGNED_PRE_KEY_ID: u32 = 22;
const KYBER_PRE_KEY_ID: u32 = 8000;
const ONE_TIME_KYBER_PRE_KEY_ID: u32 = 8001;

/// Registration ids are fixed here rather than generated, because they are varint-encoded into the
/// `PreKeySignalMessage` and so affect its serialised length. Valid registration ids fit in 14
/// bits.
const ALICE_REGISTRATION_ID: u32 = 1234;
const BOB_REGISTRATION_ID: u32 = 5678;

/// The KEM under measurement is whichever one the tree defaults to. The v1.x copy pins the
/// constant instead of using this cfg gate, because that line does not declare the `hqc256`
/// feature and the gate would trip `unexpected_cfgs` there; the two copies are otherwise
/// identical.
#[cfg(feature = "hqc256")]
const KEM_KEY_TYPE: kem::KeyType = kem::KeyType::HQC256;
#[cfg(not(feature = "hqc256"))]
const KEM_KEY_TYPE: kem::KeyType = kem::KeyType::MLKEM1024;

/// Which KEM prekeys the responder publishes.
#[derive(Copy, Clone)]
enum Mode {
    LastResortOnly,
    LastResortPlusOneTime,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::LastResortOnly => "last-resort only",
            Mode::LastResortPlusOneTime => "last-resort plus one-time",
        }
    }

    fn has_one_time(self) -> bool {
        matches!(self, Mode::LastResortPlusOneTime)
    }
}

fn main() -> Result<(), SignalProtocolError> {
    // Post-quantum keys and ciphertexts are large, and driving the whole protocol as a single
    // async state machine needs more than the default ~1 MiB main-thread stack on some platforms
    // (notably Windows), exactly as in `examples/full_session.rs`.
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
    println!("=== Serialised sizes: {KEM_KEY_TYPE:?} KEM + ML-DSA-87 identity ===");
    println!();
    println!("Fixed inputs");
    println!("  plaintext                  : {PLAINTEXT:?} ({} B)", PLAINTEXT.len());
    println!("  device id                  : {DEVICE_ID}");
    println!("  signed prekey id           : {SIGNED_PRE_KEY_ID}");
    println!("  signed KEM prekey id       : {KYBER_PRE_KEY_ID}");
    println!("  one-time KEM prekey id     : {ONE_TIME_KYBER_PRE_KEY_ID}");
    println!("  initiator registration id  : {ALICE_REGISTRATION_ID}");
    println!("  responder registration id  : {BOB_REGISTRATION_ID}");

    report_primitives()?;

    for mode in [Mode::LastResortOnly, Mode::LastResortPlusOneTime] {
        report_mode(mode).await?;
    }

    println!();
    println!("All lengths in bytes. `raw` excludes and `tagged` includes the 1-byte algorithm");
    println!("identifier this artefact prefixes to serialised keys and KEM ciphertexts. Shared");
    println!("secrets and ML-DSA signatures carry no such tag, so they are reported once.");
    Ok(())
}

/// Primitive lengths. These are properties of the algorithms, so they are identical in both modes
/// and are reported once rather than repeated under each mode heading.
fn report_primitives() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();

    let kem_pair = kem::KeyPair::generate(KEM_KEY_TYPE, &mut rng);
    let (shared_secret, ciphertext) = kem_pair.public_key.encapsulate(&mut rng)?;
    let kem_public = kem_pair.public_key.serialize();
    let kem_secret = kem_pair.secret_key.serialize();

    println!();
    println!("Primitive lengths (identical in both modes)");
    println!("  {:<32}{:>8}{:>9}", "quantity", "raw", "tagged");
    print_tagged_row(&format!("{KEM_KEY_TYPE:?} public key"), kem_public.len());
    print_tagged_row(&format!("{KEM_KEY_TYPE:?} secret key"), kem_secret.len());
    print_tagged_row(&format!("{KEM_KEY_TYPE:?} ciphertext"), ciphertext.len());
    print_untagged_row("KEM shared secret", shared_secret.len());
    print_tagged_row("ML-DSA-87 public key", dsa::PUBLIC_KEY_LENGTH + 1);
    print_tagged_row("ML-DSA-87 secret key", dsa::SECRET_KEY_LENGTH + 1);
    print_untagged_row("ML-DSA-87 signature", dsa::SIGNATURE_LENGTH);
    print_tagged_row("X25519 ratchet public key", 33);

    Ok(())
}

/// Print a quantity that carries a 1-byte algorithm tag, given its tagged length.
fn print_tagged_row(label: &str, tagged_len: usize) {
    println!("  {:<32}{:>8}{:>9}", label, tagged_len - 1, tagged_len);
}

/// Print a quantity that carries no algorithm tag, so has a single length.
fn print_untagged_row(label: &str, len: usize) {
    println!("  {:<32}{:>8}{:>9}", label, len, "-");
}

async fn report_mode(mode: Mode) -> Result<(), SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();

    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), DEVICE_ID.into());
    let bob_address = ProtocolAddress::new("+14151111112".to_owned(), DEVICE_ID.into());

    let mut alice_store = make_store(ALICE_REGISTRATION_ID, &mut rng)?;
    let mut bob_store = make_store(BOB_REGISTRATION_ID, &mut rng)?;

    let bundle = publish_bundle(&mut bob_store, mode, &mut rng).await?;
    assert_eq!(bundle.has_one_time_kyber_pre_key(), mode.has_one_time());

    println!();
    println!("--- Mode: {} ---", mode.label());

    // Bundle components. `PreKeyBundle` has no complete wire serialiser in this crate, so this is
    // the sum of its cryptographic components and deliberately not called a serialised bundle.
    let mut components: Vec<(String, usize)> = vec![
        (
            "identity key (ML-DSA-87, tagged)".to_owned(),
            bundle.identity_key()?.serialize().len(),
        ),
        (
            "signed X25519 ratchet key (tagged)".to_owned(),
            bundle.signed_pre_key_public()?.serialize().len(),
        ),
        (
            "ratchet key signature (raw)".to_owned(),
            bundle.signed_pre_key_signature()?.len(),
        ),
        (
            format!("signed {KEM_KEY_TYPE:?} prekey (tagged)"),
            bundle.kyber_pre_key_public()?.serialize().len(),
        ),
        (
            "signed KEM prekey signature (raw)".to_owned(),
            bundle.kyber_pre_key_signature()?.len(),
        ),
    ];
    if let Some(public) = bundle.one_time_kyber_pre_key_public()? {
        components.push((
            format!("one-time {KEM_KEY_TYPE:?} prekey (tagged)"),
            public.serialize().len(),
        ));
    }
    if let Some(signature) = bundle.one_time_kyber_pre_key_signature()? {
        components.push((
            "one-time KEM prekey signature (raw)".to_owned(),
            signature.len(),
        ));
    }

    println!("  Published bundle components");
    for (label, len) in &components {
        println!("    {:<50}{:>8}", label, len);
    }
    let total: usize = components.iter().map(|(_, len)| len).sum();
    println!(
        "    {:<50}{:>8}",
        "serialised cryptographic bundle-component total", total
    );

    // Protocol objects, at the fixed plaintext.
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bundle,
        SystemTime::now(),
        &mut rng,
    )
    .await?;

    let outgoing = encrypt(&mut alice_store, &bob_address, PLAINTEXT).await?;
    assert_eq!(outgoing.message_type(), CiphertextMessageType::PreKey);
    let initial_len = outgoing.serialize().len();

    let received = CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
        outgoing.serialize(),
    )?);
    let plaintext = decrypt(&mut bob_store, &alice_address, &received).await?;
    assert_eq!(plaintext, PLAINTEXT.as_bytes());

    let reply = encrypt(&mut bob_store, &alice_address, PLAINTEXT).await?;
    assert_eq!(reply.message_type(), CiphertextMessageType::Whisper);
    let reply_len = reply.serialize().len();

    println!("  Protocol objects");
    println!(
        "    {:<50}{:>8}",
        "initial PreKeySignalMessage (serialised)", initial_len
    );
    println!(
        "    {:<50}{:>8}",
        "first reply, Whisper (serialised)", reply_len
    );

    Ok(())
}

/// Create an in-memory store with a fixed registration id and a fresh ML-DSA-87 identity.
fn make_store<R: Rng + CryptoRng>(
    registration_id: u32,
    csprng: &mut R,
) -> Result<InMemSignalProtocolStore, SignalProtocolError> {
    let identity = IdentityKeyPair::generate(&mut *csprng);
    InMemSignalProtocolStore::new(identity, registration_id)
}

/// Publish the responder's bundle at the fixed identifiers, with or without a one-time KEM prekey,
/// persisting the private halves so the handshake can complete.
async fn publish_bundle<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    mode: Mode,
    csprng: &mut R,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let identity = store.get_identity_key_pair().await?;

    let signed_pre_key_pair = KeyPair::generate(&mut *csprng);
    let signed_pre_key_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut *csprng)?;

    let signed_kem_pair = kem::KeyPair::generate(KEM_KEY_TYPE, &mut *csprng);
    let signed_kem_signature = identity
        .private_key()
        .calculate_signature(&signed_kem_pair.public_key.serialize(), &mut *csprng)?;

    let mut bundle = PreKeyBundle::new(
        store.get_local_registration_id().await?,
        DEVICE_ID.into(),
        SIGNED_PRE_KEY_ID.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        KYBER_PRE_KEY_ID.into(),
        signed_kem_pair.public_key.clone(),
        signed_kem_signature.to_vec(),
        *identity.identity_key(),
    )?;

    store
        .save_signed_pre_key(
            SIGNED_PRE_KEY_ID.into(),
            &SignedPreKeyRecord::new(
                SIGNED_PRE_KEY_ID.into(),
                Timestamp::from_epoch_millis(0),
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .await?;
    store
        .save_kyber_pre_key(
            KYBER_PRE_KEY_ID.into(),
            &KyberPreKeyRecord::new(
                KYBER_PRE_KEY_ID.into(),
                Timestamp::from_epoch_millis(0),
                &signed_kem_pair,
                &signed_kem_signature,
            ),
        )
        .await?;

    if mode.has_one_time() {
        let one_time_pair = kem::KeyPair::generate(KEM_KEY_TYPE, &mut *csprng);
        let one_time_signature = identity
            .private_key()
            .calculate_signature(&one_time_pair.public_key.serialize(), &mut *csprng)?;
        bundle = bundle.with_one_time_kyber_pre_key(
            ONE_TIME_KYBER_PRE_KEY_ID.into(),
            one_time_pair.public_key.clone(),
            one_time_signature.to_vec(),
        );
        store
            .save_kyber_pre_key(
                ONE_TIME_KYBER_PRE_KEY_ID.into(),
                &KyberPreKeyRecord::new(
                    ONE_TIME_KYBER_PRE_KEY_ID.into(),
                    Timestamp::from_epoch_millis(0),
                    &one_time_pair,
                    &one_time_signature,
                ),
            )
            .await?;
    }

    Ok(bundle)
}

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
