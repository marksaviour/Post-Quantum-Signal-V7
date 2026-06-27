//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::clone::Clone;

use crate::state::SignedPreKeyId;
use crate::{kem, DeviceId, IdentityKey, KyberPreKeyId, PublicKey, Result, SignalProtocolError};

/// Bob's signed X25519 ratchet key (formerly the EC signed prekey).
///
/// In the fully post-quantum PQXDH handshake this key no longer contributes to the shared secret;
/// it is used solely as the Double Ratchet's first `ratchet_key`. It is signed by Bob's ML-DSA
/// identity key.
#[derive(Clone)]
struct SignedPreKey {
    id: SignedPreKeyId,
    public_key: PublicKey,
    signature: Vec<u8>,
}

impl SignedPreKey {
    fn new(id: SignedPreKeyId, public_key: PublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

/// An ML-KEM-1024 prekey (signed/last-resort or one-time), signed by Bob's ML-DSA identity key.
#[derive(Clone)]
struct KyberPreKey {
    id: KyberPreKeyId,
    public_key: kem::PublicKey,
    signature: Vec<u8>,
}

impl KyberPreKey {
    fn new(id: KyberPreKeyId, public_key: kem::PublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

// Represents the raw contents of the pre-key bundle without any notion of required/optional
// fields. Can be used as a "builder" for PreKeyBundle, in which case all the validation will
// happen in PreKeyBundle::new.
pub struct PreKeyBundleContent {
    pub registration_id: Option<u32>,
    pub device_id: Option<DeviceId>,
    pub identity_key: Option<IdentityKey>,
    // Signed X25519 ratchet key (formerly EC signed prekey).
    pub ec_pre_key_id: Option<SignedPreKeyId>,
    pub ec_pre_key_public: Option<PublicKey>,
    pub ec_pre_key_signature: Option<Vec<u8>>,
    // Signed (last-resort) ML-KEM-1024 prekey.
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
    pub kyber_pre_key_public: Option<kem::PublicKey>,
    pub kyber_pre_key_signature: Option<Vec<u8>>,
    // Optional one-time ML-KEM-1024 prekey.
    pub one_time_kyber_pre_key_id: Option<KyberPreKeyId>,
    pub one_time_kyber_pre_key_public: Option<kem::PublicKey>,
    pub one_time_kyber_pre_key_signature: Option<Vec<u8>>,
}

impl From<PreKeyBundle> for PreKeyBundleContent {
    fn from(bundle: PreKeyBundle) -> Self {
        Self {
            registration_id: Some(bundle.registration_id),
            device_id: Some(bundle.device_id),
            identity_key: Some(bundle.identity_key),
            ec_pre_key_id: Some(bundle.ec_signed_pre_key.id),
            ec_pre_key_public: Some(bundle.ec_signed_pre_key.public_key),
            ec_pre_key_signature: Some(bundle.ec_signed_pre_key.signature),
            kyber_pre_key_id: Some(bundle.kyber_pre_key.id),
            kyber_pre_key_public: Some(bundle.kyber_pre_key.public_key),
            kyber_pre_key_signature: Some(bundle.kyber_pre_key.signature),
            one_time_kyber_pre_key_id: bundle.one_time_kyber_pre_key.as_ref().map(|k| k.id),
            one_time_kyber_pre_key_public: bundle
                .one_time_kyber_pre_key
                .as_ref()
                .map(|k| k.public_key.clone()),
            one_time_kyber_pre_key_signature: bundle
                .one_time_kyber_pre_key
                .as_ref()
                .map(|k| k.signature.clone()),
        }
    }
}

impl TryFrom<PreKeyBundleContent> for PreKeyBundle {
    type Error = SignalProtocolError;

    fn try_from(content: PreKeyBundleContent) -> Result<Self> {
        let mut bundle = PreKeyBundle::new(
            content.registration_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("registration_id is required".to_string())
            })?,
            content.device_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("device_id is required".to_string())
            })?,
            content.ec_pre_key_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("signed_pre_key_id is required".to_string())
            })?,
            content.ec_pre_key_public.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "signed_pre_key_public is required".to_string(),
                )
            })?,
            content.ec_pre_key_signature.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "signed_pre_key_signature is required".to_string(),
                )
            })?,
            content.kyber_pre_key_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("kyber_pre_key_id is required".to_string())
            })?,
            content.kyber_pre_key_public.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("kyber_pre_key_public is required".to_string())
            })?,
            content.kyber_pre_key_signature.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "kyber_pre_key_signature is required".to_string(),
                )
            })?,
            content.identity_key.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("identity_key is required".to_string())
            })?,
        )?;

        fn zip3<T, U, V>(x: Option<T>, y: Option<U>, z: Option<V>) -> Option<(T, U, V)> {
            x.zip(y).zip(z).map(|((x, y), z)| (x, y, z))
        }

        if let Some((id, public, sig)) = zip3(
            content.one_time_kyber_pre_key_id,
            content.one_time_kyber_pre_key_public,
            content.one_time_kyber_pre_key_signature,
        ) {
            bundle = bundle.with_one_time_kyber_pre_key(id, public, sig);
        }
        Ok(bundle)
    }
}

#[derive(Clone)]
pub struct PreKeyBundle {
    registration_id: u32,
    device_id: DeviceId,
    identity_key: IdentityKey,
    // Signed X25519 ratchet key (formerly EC signed prekey).
    ec_signed_pre_key: SignedPreKey,
    // Signed (last-resort) ML-KEM-1024 prekey. Mandatory in the fully PQ handshake.
    kyber_pre_key: KyberPreKey,
    // Optional one-time ML-KEM-1024 prekey.
    one_time_kyber_pre_key: Option<KyberPreKey>,
}

impl PreKeyBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: u32,
        device_id: DeviceId,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        kyber_pre_key_id: KyberPreKeyId,
        kyber_pre_key_public: kem::PublicKey,
        kyber_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> Result<Self> {
        let ec_signed_pre_key = SignedPreKey::new(
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
        );

        let kyber_pre_key = KyberPreKey::new(
            kyber_pre_key_id,
            kyber_pre_key_public,
            kyber_pre_key_signature,
        );

        Ok(Self {
            registration_id,
            device_id,
            identity_key,
            ec_signed_pre_key,
            kyber_pre_key,
            one_time_kyber_pre_key: None,
        })
    }

    pub fn with_one_time_kyber_pre_key(
        mut self,
        pre_key_id: KyberPreKeyId,
        public_key: kem::PublicKey,
        signature: Vec<u8>,
    ) -> Self {
        self.one_time_kyber_pre_key = Some(KyberPreKey::new(pre_key_id, public_key, signature));
        self
    }

    pub fn registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        Ok(self.device_id)
    }

    /// Bob's signed X25519 ratchet key identifier (formerly the EC signed prekey id).
    pub fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(self.ec_signed_pre_key.id)
    }

    /// Bob's signed X25519 ratchet key (formerly the EC signed prekey).
    pub fn signed_pre_key_public(&self) -> Result<PublicKey> {
        Ok(self.ec_signed_pre_key.public_key)
    }

    pub fn signed_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(self.ec_signed_pre_key.signature.as_ref())
    }

    pub fn identity_key(&self) -> Result<&IdentityKey> {
        Ok(&self.identity_key)
    }

    /// Bob's signed (last-resort) ML-KEM-1024 prekey identifier.
    pub fn kyber_pre_key_id(&self) -> Result<KyberPreKeyId> {
        Ok(self.kyber_pre_key.id)
    }

    /// Bob's signed (last-resort) ML-KEM-1024 prekey.
    pub fn kyber_pre_key_public(&self) -> Result<&kem::PublicKey> {
        Ok(&self.kyber_pre_key.public_key)
    }

    pub fn kyber_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(self.kyber_pre_key.signature.as_ref())
    }

    pub fn has_one_time_kyber_pre_key(&self) -> bool {
        self.one_time_kyber_pre_key.is_some()
    }

    /// Bob's optional one-time ML-KEM-1024 prekey identifier.
    pub fn one_time_kyber_pre_key_id(&self) -> Result<Option<KyberPreKeyId>> {
        Ok(self.one_time_kyber_pre_key.as_ref().map(|k| k.id))
    }

    /// Bob's optional one-time ML-KEM-1024 prekey.
    pub fn one_time_kyber_pre_key_public(&self) -> Result<Option<&kem::PublicKey>> {
        Ok(self.one_time_kyber_pre_key.as_ref().map(|k| &k.public_key))
    }

    pub fn one_time_kyber_pre_key_signature(&self) -> Result<Option<&[u8]>> {
        Ok(self
            .one_time_kyber_pre_key
            .as_ref()
            .map(|k| k.signature.as_ref()))
    }

    pub fn modify<F>(self, modify: F) -> Result<Self>
    where
        F: FnOnce(&mut PreKeyBundleContent),
    {
        let mut content = self.into();
        modify(&mut content);
        content.try_into()
    }
}
