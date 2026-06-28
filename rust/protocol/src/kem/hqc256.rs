//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! HQC-256 KEM, backed by the pure-Rust [`hqc_kem`] crate.
//!
//! HQC is a *code-based* KEM (NIST FIPS 207, security level 5). It is wired in
//! here as a drop-in replacement for ML-KEM-1024 in the fully post-quantum
//! PQXDH handshake so that a lattice-based KEM (ML-KEM) and a code-based KEM
//! (HQC) can be compared head to head.
//!
//! # RNG bridging
//! `hqc-kem` is built against `rand` 0.10 while the rest of libsignal uses
//! `rand` 0.9, so the two `CryptoRng` traits are *not* interchangeable and the
//! caller's RNG cannot be handed directly to HQC's randomized functions.
//! Instead we draw the raw entropy (key-generation seed, encapsulation message
//! and salt) from the caller's CSPRNG and feed it to HQC's *deterministic*
//! entry points. This keeps every byte of randomness sourced from the caller
//! while side-stepping the version mismatch, and is equivalent to the
//! randomized API (which internally samples the same values uniformly).

use hqc_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Hqc256Params, HqcKem};
use rand::RngCore as _;

use super::{BadKEMKeyLength, DecapsulateError, KeyMaterial, KeyType, Public, Secret};

/// The HQC parameter set used by the handshake (NIST level 5).
type Hqc = HqcKem<Hqc256Params>;

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const KEY_TYPE: KeyType = KeyType::HQC256;
    const PUBLIC_KEY_LENGTH: usize = hqc_kem::hqc256::PUBLIC_KEY_SIZE;
    const SECRET_KEY_LENGTH: usize = hqc_kem::hqc256::SECRET_KEY_SIZE;
    const CIPHERTEXT_LENGTH: usize = hqc_kem::hqc256::CIPHERTEXT_SIZE;
    const SHARED_SECRET_LENGTH: usize = hqc_kem::hqc256::SHARED_SECRET_SIZE;

    fn generate<R: rand::CryptoRng + ?Sized>(
        csprng: &mut R,
    ) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let mut seed = [0u8; 32];
        csprng.fill_bytes(&mut seed);
        let (ek, dk) = Hqc::generate_key_deterministic(&seed);
        (
            KeyMaterial::new(ek.as_ref().into()),
            KeyMaterial::new(dk.as_ref().into()),
        )
    }

    fn encapsulate<R: rand::CryptoRng + ?Sized>(
        pub_key: &KeyMaterial<Public>,
        csprng: &mut R,
    ) -> Result<(Box<[u8]>, Box<[u8]>), BadKEMKeyLength> {
        let ek = EncapsulationKey::<Hqc256Params>::try_from(pub_key.as_ref())
            .map_err(|_| BadKEMKeyLength)?;
        let mut message = [0u8; hqc_kem::hqc256::MESSAGE_SIZE];
        let mut salt = [0u8; hqc_kem::hqc256::SALT_SIZE];
        csprng.fill_bytes(&mut message);
        csprng.fill_bytes(&mut salt);
        // The public key length was already validated above and the message/salt
        // sizes are fixed, so encapsulation cannot fail in practice; treat any
        // error as a bad key for the trait's single error channel.
        let (ct, ss) = ek
            .encapsulate_deterministic(&message, &salt)
            .map_err(|_| BadKEMKeyLength)?;
        Ok((ss.as_ref().into(), ct.as_ref().into()))
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<Box<[u8]>, DecapsulateError> {
        let dk = DecapsulationKey::<Hqc256Params>::try_from(secret_key.as_ref())
            .map_err(|_| DecapsulateError::BadKeyLength)?;
        let ct = Ciphertext::<Hqc256Params>::try_from(ciphertext)
            .map_err(|_| DecapsulateError::BadCiphertext)?;
        // HQC uses the Fujisaki-Okamoto transform with implicit rejection, so
        // decapsulation is infallible once the inputs are well-formed.
        let ss = dk.decapsulate(&ct);
        Ok(ss.as_ref().into())
    }
}
