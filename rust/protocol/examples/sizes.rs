//
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Deterministic size capture for the deployed hybrid handshake: X3DH over X25519 with XEdDSA
//! identities and a signed Kyber-1024 prekey.
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
//! This is the baseline counterpart of the version copies, and it keeps their structure and output
//! format so the three artefacts can be read side by side. What varies between the two modes is
//! the optional one-time *curve* prekey; the baseline publishes a single KEM prekey and has no
//! one-time KEM prekey to withhold, so its modes are not the versions' modes under other names.

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
/// The baseline's optional one-time prekey is a curve key rather than a KEM key. It is given the
/// identifier the version copies give their one-time KEM prekey, so the two encode to varints of
/// the same width.
const ONE_TIME_PRE_KEY_ID: u32 = 8001;

/// Registration ids are fixed here rather than generated, because they are varint-encoded into the
/// `PreKeySignalMessage` and so affect its serialised length. Valid registration ids fit in 14
/// bits.
const ALICE_REGISTRATION_ID: u32 = 1234;
const BOB_REGISTRATION_ID: u32 = 5678;

/// The KEM under measurement. This line builds Kyber-1024 and nothing else, so the constant is
/// pinned, as it is on the v1.x copy.
const KEM_KEY_TYPE: kem::KeyType = kem::KeyType::Kyber1024;

/// Whether the responder publishes the optional one-time curve prekey.
#[derive(Copy, Clone)]
enum Mode {
    NoOneTimeCurveKey,
    OneTimeCurveKey,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::NoOneTimeCurveKey => "no one-time curve key",
            Mode::OneTimeCurveKey => "one-time curve key present",
        }
    }

    fn has_one_time(self) -> bool {
        matches!(self, Mode::OneTimeCurveKey)
    }
}

fn main() -> Result<(), SignalProtocolError> {
    // Driving the whole protocol as a single async state machine can need more than the default
    // ~1 MiB main-thread stack on some platforms (notably Windows). The version copies run on a
    // roomier thread for that reason, and this one does the same so the three captures are
    // produced by the same harness shape.
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
    println!("=== Serialised sizes: {KEM_KEY_TYPE:?} KEM + X25519 identity (XEdDSA) ===");
    println!();
    println!("Fixed inputs");
    println!("  plaintext                  : {PLAINTEXT:?} ({} B)", PLAINTEXT.len());
    println!("  device id                  : {DEVICE_ID}");
    println!("  signed prekey id           : {SIGNED_PRE_KEY_ID}");
    println!("  signed KEM prekey id       : {KYBER_PRE_KEY_ID}");
    println!("  one-time curve prekey id   : {ONE_TIME_PRE_KEY_ID}");
    println!("  initiator registration id  : {ALICE_REGISTRATION_ID}");
    println!("  responder registration id  : {BOB_REGISTRATION_ID}");

    report_primitives()?;

    for mode in [Mode::NoOneTimeCurveKey, Mode::OneTimeCurveKey] {
        report_mode(mode).await?;
    }

    println!();
    println!("All lengths in bytes. `raw` excludes and `tagged` includes the 1-byte algorithm");
    println!("identifier this artefact prefixes to serialised keys and KEM ciphertexts. Shared");
    println!("secrets, private curve keys, and XEdDSA signatures carry no such tag, so they are");
    println!("reported once.");
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

    let identity = IdentityKeyPair::generate(&mut rng);
    let signature = identity
        .private_key()
        .calculate_signature(&kem_public, &mut rng)?;
    let ratchet_pair = KeyPair::generate(&mut rng);

    println!();
    println!("Primitive lengths (identical in both modes)");
    println!("  {:<32}{:>8}{:>9}", "quantity", "raw", "tagged");
    print_tagged_row(&format!("{KEM_KEY_TYPE:?} public key"), kem_public.len());
    print_tagged_row(&format!("{KEM_KEY_TYPE:?} secret key"), kem_secret.len());
    print_tagged_row(&format!("{KEM_KEY_TYPE:?} ciphertext"), ciphertext.len());
    print_untagged_row("KEM shared secret", shared_secret.len());
    print_tagged_row(
        "X25519 identity public key",
        identity.identity_key().serialize().len(),
    );
    print_untagged_row(
        "X25519 identity secret key",
        identity.private_key().serialize().len(),
    );
    print_untagged_row("XEdDSA signature", signature.len());
    print_tagged_row(
        "X25519 ratchet public key",
        ratchet_pair.public_key.serialize().len(),
    );

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
    assert_eq!(bundle.pre_key_id()?.is_some(), mode.has_one_time());

    println!();
    println!("--- Mode: {} ---", mode.label());

    // Bundle components. `PreKeyBundle` has no complete wire serialiser in this crate, so this is
    // the sum of its cryptographic components and deliberately not called a serialised bundle.
    let mut components: Vec<(String, usize)> = vec![
        (
            "identity key (X25519, tagged)".to_owned(),
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
            bundle
                .kyber_pre_key_public()?
                .expect("hybrid bundle carries a KEM prekey")
                .serialize()
                .len(),
        ),
        (
            "signed KEM prekey signature (raw)".to_owned(),
            bundle
                .kyber_pre_key_signature()?
                .expect("hybrid bundle carries a KEM prekey signature")
                .len(),
        ),
    ];
    // The baseline's one-time curve prekey is unsigned, so it contributes a key and no signature.
    if let Some(public) = bundle.pre_key_public()? {
        components.push((
            "one-time X25519 prekey (tagged)".to_owned(),
            public.serialize().len(),
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

/// Create an in-memory store with a fixed registration id and a fresh X25519 identity.
fn make_store<R: Rng + CryptoRng>(
    registration_id: u32,
    csprng: &mut R,
) -> Result<InMemSignalProtocolStore, SignalProtocolError> {
    let identity = IdentityKeyPair::generate(&mut *csprng);
    InMemSignalProtocolStore::new(identity, registration_id)
}

/// Publish the responder's bundle at the fixed identifiers, with or without a one-time curve
/// prekey, persisting the private halves so the handshake can complete.
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

    let one_time_pre_key_pair = mode.has_one_time().then(|| KeyPair::generate(&mut *csprng));
    let one_time_pre_key = one_time_pre_key_pair
        .as_ref()
        .map(|pair| (ONE_TIME_PRE_KEY_ID.into(), pair.public_key));

    let bundle = PreKeyBundle::new(
        store.get_local_registration_id().await?,
        DEVICE_ID.into(),
        one_time_pre_key,
        SIGNED_PRE_KEY_ID.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        *identity.identity_key(),
    )?
    .with_kyber_pre_key(
        KYBER_PRE_KEY_ID.into(),
        signed_kem_pair.public_key.clone(),
        signed_kem_signature.to_vec(),
    );

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

    if let Some(pair) = one_time_pre_key_pair.as_ref() {
        store
            .save_pre_key(
                ONE_TIME_PRE_KEY_ID.into(),
                &PreKeyRecord::new(ONE_TIME_PRE_KEY_ID.into(), pair),
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
