//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Parameters for the fully post-quantum PQXDH handshake.
//!
//! The X3DH Diffie-Hellman terms of classic PQXDH are gone: confidentiality
//! comes entirely from ML-KEM-1024 encapsulations (a signed "last-resort" KEM
//! prekey plus an optional one-time KEM prekey), and authentication comes
//! entirely from ML-DSA-87 signatures (Bob's signed prekeys and Alice's signed
//! transcript). The only remaining X25519 key is the Double Ratchet `ratchet_key`
//! (Bob's signed ratchet key, formerly the EC signed prekey), which the ongoing
//! ratchet still uses for its DH step.

use crate::{kem, IdentityKey, IdentityKeyPair, KeyPair, PublicKey};

pub struct AliceSignalProtocolParameters<'a> {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    /// Bob's signed X25519 ratchet key (formerly the EC signed prekey). Used only by the
    /// Double Ratchet's DH step, never in the handshake secret.
    their_ratchet_key: PublicKey,
    /// Bob's signed (last-resort) ML-KEM-1024 prekey.
    their_signed_kem_pre_key: kem::PublicKey,
    /// Bob's optional one-time ML-KEM-1024 prekey.
    their_one_time_kem_pre_key: Option<&'a kem::PublicKey>,
}

impl<'a> AliceSignalProtocolParameters<'a> {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_ratchet_key: PublicKey,
        their_signed_kem_pre_key: kem::PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_ratchet_key,
            their_signed_kem_pre_key,
            their_one_time_kem_pre_key: None,
        }
    }

    pub fn set_their_one_time_kem_pre_key(&mut self, kem_public: &'a kem::PublicKey) {
        self.their_one_time_kem_pre_key = Some(kem_public);
    }

    pub fn with_their_one_time_kem_pre_key(mut self, kem_public: &'a kem::PublicKey) -> Self {
        self.set_their_one_time_kem_pre_key(kem_public);
        self
    }

    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_base_key_pair(&self) -> &KeyPair {
        &self.our_base_key_pair
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_ratchet_key(&self) -> &PublicKey {
        &self.their_ratchet_key
    }

    #[inline]
    pub fn their_signed_kem_pre_key(&self) -> &kem::PublicKey {
        &self.their_signed_kem_pre_key
    }

    #[inline]
    pub fn their_one_time_kem_pre_key(&self) -> Option<&kem::PublicKey> {
        self.their_one_time_kem_pre_key
    }
}

pub struct BobSignalProtocolParameters<'a> {
    our_identity_key_pair: IdentityKeyPair,
    /// Bob's signed X25519 ratchet key pair (formerly the EC signed prekey pair).
    our_ratchet_key_pair: KeyPair,
    /// Bob's signed (last-resort) ML-KEM-1024 prekey pair.
    our_signed_kem_pre_key_pair: kem::KeyPair,
    /// Bob's optional one-time ML-KEM-1024 prekey pair.
    our_one_time_kem_pre_key_pair: Option<kem::KeyPair>,

    their_identity_key: IdentityKey,
    their_base_key: PublicKey,
    /// Ciphertext ct1 encapsulated by Alice to Bob's signed KEM prekey.
    their_kem_ciphertext: &'a kem::SerializedCiphertext,
    /// Optional ciphertext ct2 encapsulated to Bob's one-time KEM prekey.
    their_one_time_kem_ciphertext: Option<&'a kem::SerializedCiphertext>,
    /// Alice's ML-DSA-87 signature over the handshake transcript.
    their_signature: &'a [u8],
}

impl<'a> BobSignalProtocolParameters<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_ratchet_key_pair: KeyPair,
        our_signed_kem_pre_key_pair: kem::KeyPair,
        our_one_time_kem_pre_key_pair: Option<kem::KeyPair>,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kem_ciphertext: &'a kem::SerializedCiphertext,
        their_one_time_kem_ciphertext: Option<&'a kem::SerializedCiphertext>,
        their_signature: &'a [u8],
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_ratchet_key_pair,
            our_signed_kem_pre_key_pair,
            our_one_time_kem_pre_key_pair,
            their_identity_key,
            their_base_key,
            their_kem_ciphertext,
            their_one_time_kem_ciphertext,
            their_signature,
        }
    }

    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_ratchet_key_pair(&self) -> &KeyPair {
        &self.our_ratchet_key_pair
    }

    #[inline]
    pub fn our_signed_kem_pre_key_pair(&self) -> &kem::KeyPair {
        &self.our_signed_kem_pre_key_pair
    }

    #[inline]
    pub fn our_one_time_kem_pre_key_pair(&self) -> Option<&kem::KeyPair> {
        self.our_one_time_kem_pre_key_pair.as_ref()
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_base_key(&self) -> &PublicKey {
        &self.their_base_key
    }

    #[inline]
    pub fn their_kem_ciphertext(&self) -> &kem::SerializedCiphertext {
        self.their_kem_ciphertext
    }

    #[inline]
    pub fn their_one_time_kem_ciphertext(&self) -> Option<&kem::SerializedCiphertext> {
        self.their_one_time_kem_ciphertext
    }

    #[inline]
    pub fn their_signature(&self) -> &[u8] {
        self.their_signature
    }
}
