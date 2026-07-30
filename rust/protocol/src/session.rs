//
// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use rand::{CryptoRng, Rng};

use crate::ratchet::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::state::GenericSignedPreKey;
use crate::{
    ratchet, Direction, IdentityKey, IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyStore,
    PreKeyBundle, PreKeyId, PreKeySignalMessage, PreKeyStore, ProtocolAddress, Result,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyStore,
};

#[derive(Default)]
pub struct PreKeysUsed {
    pub pre_key_id: Option<PreKeyId>,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
}

/// Expected [`IdentityKeyStore`] change when [`process_prekey`] succeeds.
///
/// This represents a deferred action. Assuming later operations succeed, the
/// caller of `process_prekey` should apply this to the `IdentityKeyStore` that
/// was provided.
#[must_use]
pub struct IdentityToSave<'a> {
    pub remote_address: &'a ProtocolAddress,
    pub their_identity_key: &'a IdentityKey,
}

/*
These functions are on SessionBuilder in Java

However using SessionBuilder + SessionCipher at the same time causes
&mut sharing issues. And as SessionBuilder has no actual state beyond
its reference to the various data stores, instead the functions are
free standing.
 */

pub async fn process_prekey<'a>(
    message: &'a PreKeySignalMessage,
    remote_address: &'a ProtocolAddress,
    session_record: &mut SessionRecord,
    identity_store: &dyn IdentityKeyStore,
    pre_key_store: &dyn PreKeyStore,
    signed_prekey_store: &dyn SignedPreKeyStore,
    kyber_prekey_store: &dyn KyberPreKeyStore,
) -> Result<(PreKeysUsed, IdentityToSave<'a>)> {
    let their_identity_key = message.identity_key();

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Receiving)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    let pre_keys_used = process_prekey_impl(
        message,
        remote_address,
        session_record,
        signed_prekey_store,
        kyber_prekey_store,
        pre_key_store,
        identity_store,
    )
    .await?;

    let identity_to_save = IdentityToSave {
        remote_address,
        their_identity_key,
    };

    Ok((pre_keys_used, identity_to_save))
}

async fn process_prekey_impl(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    signed_prekey_store: &dyn SignedPreKeyStore,
    kyber_prekey_store: &dyn KyberPreKeyStore,
    _pre_key_store: &dyn PreKeyStore,
    identity_store: &dyn IdentityKeyStore,
) -> Result<PreKeysUsed> {
    if session_record.promote_matching_session(
        message.message_version() as u32,
        &message.base_key().serialize(),
    )? {
        // We've already set up a session for this message, we can exit early.
        return Ok(Default::default());
    }

    // Bob's signed X25519 ratchet key (formerly the EC signed prekey).
    let our_ratchet_key_pair = signed_prekey_store
        .get_signed_pre_key(message.signed_pre_key_id())
        .await?
        .key_pair()?;

    // Bob's signed (last-resort) ML-KEM-1024 prekey, used to decapsulate ct1.
    let kyber_pre_key_id = message.kyber_pre_key_id().ok_or_else(|| {
        SignalProtocolError::InvalidMessage(
            crate::CiphertextMessageType::PreKey,
            "fully PQ PreKey message is missing its signed KEM prekey",
        )
    })?;
    let our_signed_kem_pre_key_pair = kyber_prekey_store
        .get_kyber_pre_key(kyber_pre_key_id)
        .await?
        .key_pair()?;

    // Bob's optional one-time ML-KEM-1024 prekey, used to decapsulate ct2.
    let our_one_time_kem_pre_key_pair = if let Some(one_time_id) = message.pq_one_time_pre_key_id() {
        log::info!("processing PreKey message from {remote_address} with a one-time KEM prekey");
        Some(
            kyber_prekey_store
                .get_kyber_pre_key(one_time_id)
                .await?
                .key_pair()?,
        )
    } else {
        log::warn!(
            "processing PreKey message from {remote_address} which had no one-time KEM prekey"
        );
        None
    };

    let their_kem_ciphertext = message.kyber_ciphertext().ok_or_else(|| {
        SignalProtocolError::InvalidMessage(
            crate::CiphertextMessageType::PreKey,
            "fully PQ PreKey message is missing its KEM ciphertext",
        )
    })?;

    let parameters = BobSignalProtocolParameters::new(
        identity_store.get_identity_key_pair().await?,
        our_ratchet_key_pair,
        our_signed_kem_pre_key_pair,
        our_one_time_kem_pre_key_pair,
        *message.identity_key(),
        *message.base_key(),
        their_kem_ciphertext,
        message.pq_one_time_ciphertext(),
        message.identity_signature(),
    );

    let mut new_session = ratchet::initialize_bob_session(&parameters)?;

    new_session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    new_session.set_remote_registration_id(message.registration_id());

    session_record.promote_state(new_session);

    let pre_keys_used = PreKeysUsed {
        pre_key_id: None,
        // Only the one-time KEM prekey (if any) is consumed; the signed/last-resort
        // KEM prekey is reused across sessions.
        kyber_pre_key_id: message.pq_one_time_pre_key_id(),
    };
    Ok(pre_keys_used)
}

pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    bundle: &PreKeyBundle,
    now: SystemTime,
    mut csprng: &mut R,
) -> Result<()> {
    let their_identity_key = bundle.identity_key()?;

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Sending)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // Bob's signed X25519 ratchet key is authenticated by his ML-DSA identity.
    if !their_identity_key.verify_signature(
        &bundle.signed_pre_key_public()?.serialize(),
        bundle.signed_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    // Bob's signed (last-resort) ML-KEM-1024 prekey is authenticated by his ML-DSA identity.
    if !their_identity_key.verify_signature(
        bundle.kyber_pre_key_public()?.serialize().as_ref(),
        bundle.kyber_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    // Bob's optional one-time ML-KEM-1024 prekey is likewise authenticated.
    if let Some(one_time_public) = bundle.one_time_kyber_pre_key_public()? {
        if !their_identity_key.verify_signature(
            one_time_public.serialize().as_ref(),
            bundle
                .one_time_kyber_pre_key_signature()?
                .expect("signature must be present"),
        ) {
            return Err(SignalProtocolError::SignatureValidationFailed);
        }
    }

    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let our_base_key_pair = KeyPair::generate(&mut csprng);
    let their_ratchet_key = bundle.signed_pre_key_public()?;

    let our_identity_key_pair = identity_store.get_identity_key_pair().await?;

    let mut parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        *their_identity_key,
        their_ratchet_key,
        bundle.kyber_pre_key_public()?.clone(),
    );
    if let Some(one_time_public) = bundle.one_time_kyber_pre_key_public()? {
        parameters.set_their_one_time_kem_pre_key(one_time_public);
    }

    let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;

    log::info!(
        "set_unacknowledged_pre_key_message for: {} with signed kyber preKeyId: {}",
        remote_address,
        bundle.kyber_pre_key_id()?
    );

    // No EC one-time prekey is used in the fully PQ handshake.
    session.set_unacknowledged_pre_key_message(
        None,
        bundle.signed_pre_key_id()?,
        &our_base_key_pair.public_key,
        now,
    );

    session.set_unacknowledged_kyber_pre_key_id(bundle.kyber_pre_key_id()?);
    if let Some(one_time_id) = bundle.one_time_kyber_pre_key_id()? {
        session.set_pq_one_time_pre_key_id(one_time_id);
    }

    session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    session.set_remote_registration_id(bundle.registration_id()?);

    identity_store
        .save_identity(remote_address, their_identity_key)
        .await?;

    session_record.promote_state(session);

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(())
}
