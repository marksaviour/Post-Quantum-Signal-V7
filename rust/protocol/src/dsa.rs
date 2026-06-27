//! ML-DSA (FIPS 204) digital signatures for fully post-quantum identity keys.
//!
//! In the post-quantum PQXDH variant implemented by this crate, the long-term
//! identity key is a ML-DSA-87 signing keypair.
//! Unlike the legacy Curve25519 identity key, it performs no key agreement, just authentication
//! by signing prekey bundles (Bob) and the initiator's handshake transcript (Alice).
//!
//! ML-DSA-87 is chosen to match the NIST level 5 security of the ML-KEM-1024
//! KEM prekeys are used elsewhere in the handshake.
//!
//! Serialised keys are prefixed with a single type byte, mirroring the
//! conventions used by [`crate::kem`] and [`libsignal_core::curve`], so that the
//! scheme can be identified (and, in the future, evolved) on the wire.

use libcrux_ml_dsa::ml_dsa_87::{
    self, MLDSA87Signature, MLDSA87SigningKey, MLDSA87VerificationKey,
};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

use crate::{Result, SignalProtocolError};

/// Length in bytes of a raw ML-DSA-87 verification (public) key.
pub const PUBLIC_KEY_LENGTH: usize = MLDSA87VerificationKey::len();
/// Length in bytes of a raw ML-DSA-87 signing (secret) key.
pub const SECRET_KEY_LENGTH: usize = MLDSA87SigningKey::len();
/// Length in bytes of an ML-DSA-87 signature.
pub const SIGNATURE_LENGTH: usize = MLDSA87Signature::len();

/// Type-prefix byte identifying an ML-DSA-87 key in serialized form.
const ML_DSA_87_TYPE: u8 = 0x09;

/// Domain-separation context passed to every ML-DSA operation in this crate.
const CONTEXT: &[u8] = b"Signal_PQXDH_MLDSA87";

/// Concatenate the parts of a multipart message into a single buffer for signing/verification.
fn flatten(message: &[&[u8]]) -> Vec<u8> {
    let total = message.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(total);
    for part in message {
        out.extend_from_slice(part);
    }
    out
}

/// An ML-DSA-87 verification (public) key.
#[derive(Clone, Copy)]
pub struct PublicKey {
    data: [u8; PUBLIC_KEY_LENGTH],
}

impl PublicKey {
    /// Deserialize a verification key from its type-prefixed byte representation.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        let (type_byte, key_bytes) = value
            .split_first()
            .ok_or(SignalProtocolError::NoKeyTypeIdentifier)?;
        if *type_byte != ML_DSA_87_TYPE {
            return Err(SignalProtocolError::BadKeyType(*type_byte));
        }
        let data: [u8; PUBLIC_KEY_LENGTH] = key_bytes.try_into().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "bad ML-DSA-87 public key length {}",
                key_bytes.len()
            ))
        })?;
        Ok(Self { data })
    }

    /// Serialize the verification key with its type-prefix byte.
    pub fn serialize(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(1 + PUBLIC_KEY_LENGTH);
        out.push(ML_DSA_87_TYPE);
        out.extend_from_slice(&self.data);
        out.into_boxed_slice()
    }

    /// Verify an ML-DSA-87 `signature` over a single-part `message`.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_signature_for_multipart_message(&[message], signature)
    }

    /// Verify an ML-DSA-87 `signature` over the concatenation of `message` parts.
    pub fn verify_signature_for_multipart_message(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> bool {
        let Ok(signature) = <[u8; SIGNATURE_LENGTH]>::try_from(signature) else {
            return false;
        };
        let verification_key = MLDSA87VerificationKey::new(self.data);
        let signature = MLDSA87Signature::new(signature);
        ml_dsa_87::verify(&verification_key, &flatten(message), CONTEXT, &signature).is_ok()
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.data[..].ct_eq(&other.data[..])
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ML-DSA-87 PublicKey {{ {} }}",
            hex::encode(&self.data[..8])
        )
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

/// An ML-DSA-87 signing (secret) key.
#[derive(Clone, Copy)]
pub struct SecretKey {
    data: [u8; SECRET_KEY_LENGTH],
}

impl SecretKey {
    /// Deserialize a signing key from its type-prefixed byte representation.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        let (type_byte, key_bytes) = value
            .split_first()
            .ok_or(SignalProtocolError::NoKeyTypeIdentifier)?;
        if *type_byte != ML_DSA_87_TYPE {
            return Err(SignalProtocolError::BadKeyType(*type_byte));
        }
        let data: [u8; SECRET_KEY_LENGTH] = key_bytes.try_into().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "bad ML-DSA-87 secret key length {}",
                key_bytes.len()
            ))
        })?;
        Ok(Self { data })
    }

    /// Serialize the signing key with its type-prefix byte.
    pub fn serialize(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(1 + SECRET_KEY_LENGTH);
        out.push(ML_DSA_87_TYPE);
        out.extend_from_slice(&self.data);
        out.into_boxed_slice()
    }

    /// Produce an ML-DSA-87 signature over a single-part `message`.
    pub fn calculate_signature<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.calculate_signature_for_multipart_message(&[message], csprng)
    }

    /// Produce an ML-DSA-87 signature over the concatenation of `message` parts.
    pub fn calculate_signature_for_multipart_message<R: Rng + CryptoRng>(
        &self,
        message: &[&[u8]],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        let signing_key = MLDSA87SigningKey::new(self.data);
        let randomness: [u8; 32] = csprng.random();
        let signature = ml_dsa_87::sign(&signing_key, &flatten(message), CONTEXT, randomness)
            .map_err(|_| {
                SignalProtocolError::InvalidArgument("ML-DSA-87 signing failed".to_string())
            })?;
        Ok(signature.as_slice().into())
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ML-DSA-87 SecretKey {{ <redacted> }}")
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

/// An ML-DSA-87 signing keypair.
#[derive(Clone, Copy, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Generate a fresh ML-DSA-87 keypair from `csprng`.
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let randomness: [u8; 32] = csprng.random();
        let key_pair = ml_dsa_87::generate_key_pair(randomness);
        Self {
            public_key: PublicKey {
                data: *key_pair.verification_key.as_ref(),
            },
            secret_key: SecretKey {
                data: *key_pair.signing_key.as_ref(),
            },
        }
    }

    /// Reconstruct a keypair from serialized public and secret keys.
    pub fn from_public_and_private(public_key: &[u8], secret_key: &[u8]) -> Result<Self> {
        Ok(Self {
            public_key: PublicKey::deserialize(public_key)?,
            secret_key: SecretKey::deserialize(secret_key)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let mut rng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut rng);
        let message = b"fully post-quantum PQXDH";
        let signature = key_pair
            .secret_key
            .calculate_signature(message, &mut rng)
            .expect("signing succeeds");
        assert!(key_pair.public_key.verify_signature(message, &signature));

        // A tampered message must not verify.
        assert!(!key_pair
            .public_key
            .verify_signature(b"different message", &signature));

        // A signature from an unrelated key must not verify.
        let other = KeyPair::generate(&mut rng);
        assert!(!other.public_key.verify_signature(message, &signature));
    }

    #[test]
    fn serialize_round_trip() {
        let mut rng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut rng);

        let serialized_public = key_pair.public_key.serialize();
        assert_eq!(serialized_public.len(), PUBLIC_KEY_LENGTH + 1);
        let public = PublicKey::deserialize(&serialized_public).expect("valid public key");
        assert_eq!(public, key_pair.public_key);

        let serialized_secret = key_pair.secret_key.serialize();
        assert_eq!(serialized_secret.len(), SECRET_KEY_LENGTH + 1);

        let reconstructed =
            KeyPair::from_public_and_private(&serialized_public, &serialized_secret)
                .expect("valid keypair");
        let message = b"round trip";
        let signature = reconstructed
            .secret_key
            .calculate_signature(message, &mut rng)
            .expect("signing succeeds");
        assert!(key_pair.public_key.verify_signature(message, &signature));
    }
}
