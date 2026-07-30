//
// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 Mark Saviour Farrugia.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Wrappers over the post-quantum [`crate::dsa`] (ML-DSA-87) signature scheme to
//! represent the long-term identity of a user.
//!
//! In the fully post-quantum PQXDH variant the identity key is an **ML-DSA-87
//! signing keypair**. It is used purely for *authentication* — it signs prekey
//! bundles and the initiator's handshake transcript — and, unlike the legacy
//! Curve25519 identity key, performs no Diffie-Hellman agreement.

#![warn(missing_docs)]

use prost::Message;
use rand::{CryptoRng, Rng};

use crate::{dsa, proto, Result, SignalProtocolError};

// Used for domain separation between alternate-identity signatures and other key-to-key signatures.
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1: &[u8] = &[0xFF; 32];
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2: &[u8] = b"Signal_PNI_Signature";

/// A public key that represents the identity of a user.
///
/// Wrapper for an ML-DSA-87 [`dsa::PublicKey`] (verification key).
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct IdentityKey {
    public_key: dsa::PublicKey,
}

impl IdentityKey {
    /// Initialize a public-facing identity from a verification key.
    pub fn new(public_key: dsa::PublicKey) -> Self {
        Self { public_key }
    }

    /// Return the ML-DSA verification key representing this identity.
    #[inline]
    pub fn public_key(&self) -> &dsa::PublicKey {
        &self.public_key
    }

    /// Return an owned byte slice which can be deserialized with [`Self::decode`].
    #[inline]
    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }

    /// Deserialize a public identity from a byte slice.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = dsa::PublicKey::deserialize(value)?;
        Ok(Self { public_key: pk })
    }

    /// Verify an ML-DSA `signature` produced by the corresponding [`IdentityKeyPair`] over
    /// `message`.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.public_key.verify_signature(message, signature)
    }

    /// Given a trusted identity `self`, verify that `other` represents an alternate identity for
    /// this user.
    ///
    /// `signature` must be calculated from [`IdentityKeyPair::sign_alternate_identity`].
    pub fn verify_alternate_identity(&self, other: &IdentityKey, signature: &[u8]) -> Result<bool> {
        Ok(self.public_key.verify_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            signature,
        ))
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

impl From<dsa::PublicKey> for IdentityKey {
    fn from(value: dsa::PublicKey) -> Self {
        Self { public_key: value }
    }
}

/// The private identity of a user.
///
/// Can be converted to and from a [`dsa::KeyPair`].
#[derive(Copy, Clone, Debug)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: dsa::SecretKey,
}

impl IdentityKeyPair {
    /// Create a key pair from a public `identity_key` and a private `private_key`.
    pub fn new(identity_key: IdentityKey, private_key: dsa::SecretKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    /// Generate a random new identity from randomness in `csprng`.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = dsa::KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.secret_key,
        }
    }

    /// Return the public identity of this user.
    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Return the public verification key that defines this identity.
    #[inline]
    pub fn public_key(&self) -> &dsa::PublicKey {
        self.identity_key.public_key()
    }

    /// Return the private signing key that defines this identity.
    #[inline]
    pub fn private_key(&self) -> &dsa::SecretKey {
        &self.private_key
    }

    /// Return a byte slice which can later be deserialized with [`Self::try_from`].
    pub fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
        };

        let result = structure.encode_to_vec();
        result.into_boxed_slice()
    }

    /// Sign `message` with this identity's ML-DSA signing key.
    pub fn sign<R: Rng + CryptoRng>(&self, message: &[u8], rng: &mut R) -> Result<Box<[u8]>> {
        self.private_key.calculate_signature(message, rng)
    }

    /// Generate a signature claiming that `other` represents the same user as `self`.
    pub fn sign_alternate_identity<R: Rng + CryptoRng>(
        &self,
        other: &IdentityKey,
        rng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.private_key.calculate_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            rng,
        )
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: dsa::SecretKey::deserialize(&structure.private_key)?,
        })
    }
}

impl From<dsa::KeyPair> for IdentityKeyPair {
    fn from(value: dsa::KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.secret_key,
        }
    }
}

impl From<IdentityKeyPair> for dsa::KeyPair {
    fn from(value: IdentityKeyPair) -> Self {
        dsa::KeyPair {
            public_key: *value.identity_key.public_key(),
            secret_key: value.private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;

    #[test]
    fn test_identity_key_from() {
        let key_pair = dsa::KeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }

    #[test]
    fn test_serialize_identity_key_pair() -> Result<()> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let serialized = identity_key_pair.serialize();
        let deserialized_identity_key_pair = IdentityKeyPair::try_from(&serialized[..])?;
        assert_eq!(
            identity_key_pair.identity_key(),
            deserialized_identity_key_pair.identity_key()
        );
        assert_eq!(
            identity_key_pair.private_key().serialize(),
            deserialized_identity_key_pair.private_key().serialize()
        );

        Ok(())
    }

    #[test]
    fn test_alternate_identity_signing() -> Result<()> {
        let mut rng = OsRng.unwrap_err();
        let primary = IdentityKeyPair::generate(&mut rng);
        let secondary = IdentityKeyPair::generate(&mut rng);

        let signature = secondary.sign_alternate_identity(primary.identity_key(), &mut rng)?;
        assert!(secondary
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &signature)?);
        // Not symmetric.
        assert!(!primary
            .identity_key()
            .verify_alternate_identity(secondary.identity_key(), &signature)?);

        let another_signature =
            secondary.sign_alternate_identity(primary.identity_key(), &mut rng)?;
        assert!(secondary
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &another_signature)?);

        let unrelated = IdentityKeyPair::generate(&mut rng);
        assert!(!secondary
            .identity_key()
            .verify_alternate_identity(unrelated.identity_key(), &signature)?);
        assert!(!unrelated
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &signature)?);

        Ok(())
    }
}
