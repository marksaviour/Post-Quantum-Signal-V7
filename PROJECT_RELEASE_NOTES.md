# Project Release Notes

This file records every release version of the Post-Quantum Signal research artefact. Project
versions use Git tags and are independent of Signal's inherited package version metadata.

## Version and tag conventions

- Upstream libsignal snapshot: `0.73.3`.
- Rust `libsignal-protocol` crate metadata: `0.1.0`.
- Existing research tags: `v1.0.0`, `v1.0.1`, and `v2.0.0`.
- Current release candidate: `v2.0.1`.
- Signal's inherited `RELEASE_NOTES.md` remains at `0.73.3`; these project notes are the source for
  research GitHub releases.

The `v1.x` line evaluates ML-KEM-1024 with ML-DSA-87. The `v2.x` line replaces ML-KEM-1024 with
HQC-256 while retaining ML-DSA-87 and the same KEM-agnostic PQXDH construction.

## Imported libsignal versions

These snapshots are development baselines, not Post-Quantum Signal release tags:

- `0.87.5` — initially imported on 2 March 2026 in commit
  `f75f33e115f86ce9f0e804447da249752d33093d`.
- `0.73.3` — adopted on 17 June 2026 in commit
  `26ff061ede6512736a7c51d7bd617673ed031791` as the base for the post-quantum implementation.

## v2.0.1 — Documentation and portability update

- **Status:** Planned release
- **Base tag:** `v2.0.0`
- **Release tag:** `v2.0.1` after validation

Planned changes:

- Merge `HQC_SWAP_CHANGES.md` into `POST_QUANTUM_PQXDH.md` as the canonical Version 2 document.
- Correct stale branch, validation, terminology, and HQC standardisation statements.
- Add project-specific README content while preserving the original Signal README beneath it.
- Complete the project-authored comment audit.
- Carry forward the executable-mode and shared-fixture symlink repair from `v1.0.1`.
- Re-run the HQC protocol tests, examples, known-answer tests, Clippy, and KEM benchmark before
  release.

This section will be updated with final commit and validation details before the `v2.0.1` tag is
created.

## v2.0.0 — HQC-256 evaluation

- **Released:** 1 July 2026
- **Tag:** `v2.0.0`
- **Commit:** `95f53fac6f0aa82ad1aeaf12215db2eee8e3efa9`
- **Base:** `v1.0.0`

### Changes

- Replaces ML-KEM-1024 prekeys with the code-based HQC-256 KEM.
- Adds `KeyType::HQC256`, wire type tag `0x0B`, and HQC-specific domain-separation labels.
- Vendors the RustCrypto `hqc-kem` implementation and fixes its inverted byte-length check.
- Makes `hqc256` the default protocol feature while retaining `mlkem1024` for comparison.
- Adds HQC unit tests, PQXDH integration coverage, demonstrations, and a Criterion comparison
  benchmark.
- Adds `rust/protocol/examples/full_session.rs` for a complete public-API session flow.

### Recorded findings

- HQC-256 public keys are approximately 4.6 times larger than ML-KEM-1024 public keys.
- HQC-256 ciphertexts are approximately 9.2 times larger.
- The recorded Rust implementation was approximately 46–142 times slower across key generation,
  encapsulation, and decapsulation.
- HQC provides code-based algorithmic diversity, but ML-KEM remains the more practical default for
  a bandwidth- and latency-sensitive messenger.

### Scope

- The initial PQXDH handshake uses HQC-256 and ML-DSA-87 without X25519 in its shared secret.
- The subsequent Double Ratchet continues to use X25519.
- Java, Swift, Node, Sealed Sender, and compatibility with stock Signal clients remain out of
  scope.
- This tag contains the inherited Windows metadata loss repaired by the planned `v2.0.1` release.

## v1.0.1 — Full public-API session demonstration

- **Released:** 28 July 2026
- **Tag:** `v1.0.1`
- **Commit:** `b475a92c4c1c23593c9e1e15b21668777cd06597`
- **Base tag:** `v1.0.0`

### Changes

- Adds `rust/protocol/examples/full_session.rs`, a runnable end-to-end demonstration using the
  public protocol API and in-memory stores.
- Exercises the ML-KEM-1024 + ML-DSA-87 initial handshake, serialized wire transport, Bob's
  matching session, a reply, ordered Double Ratchet messages, and out-of-order delivery.
- Describes the scope accurately: the initial handshake is fully post-quantum, while the ongoing
  Double Ratchet still uses X25519.
- Restores 21 Unix executable modes and 12 shared test-fixture symlinks unintentionally lost from
  the Windows-authored `v1.0.0` snapshot.

### Validation

Release-candidate validation performed on 23 July 2026:

- `cargo check -p libsignal-protocol --example full_session` — passed.
- `cargo run -p libsignal-protocol --example full_session` — passed every assertion.
- `cargo test -p libsignal-protocol` — 68 passed, 2 ignored, 0 failed.
- `rustfmt --edition 2021 --check rust/protocol/examples/full_session.rs` — passed.
- Example-specific Clippy passed after allowing two existing `v1.0.0` library findings:
  `large_enum_variant` in `protocol.rs` and `cast_possible_truncation` in `ratchet.rs`.

## v1.0.0 — Fully post-quantum PQXDH baseline

- **Released:** 27 June 2026
- **Tag:** `v1.0.0`
- **Commit:** `f55ae91d9bb9d9412763adf7aa5b67e345cba7e1`
- **Upstream base:** libsignal `0.73.3`

### Changes

- Converts the initial PQXDH handshake from a hybrid X25519/KEM design to a KEM-only shared
  secret using ML-KEM-1024.
- Replaces Curve25519 identity authentication with ML-DSA-87 signatures.
- Adds explicit ML-DSA authentication for Alice through a signed handshake transcript.
- Uses signed and optional one-time ML-KEM-1024 prekeys.
- Adds new wire and storage fields for the second KEM ciphertext and transcript signature.
- Adds unit, handshake, session, negative-path, and serialization tests.
- Adds the `pqxdh` runnable handshake demonstration and the initial
  `POST_QUANTUM_PQXDH.md` design document.

### Scope

- The initial shared secret contains no X25519 contribution.
- X25519 remains as the Double Ratchet key after the handshake.
- Sealed Sender and non-Rust language bindings are not supported by this research variant.
- The protocol is intentionally incompatible with stock Signal clients.

## Shared release notice

All `v1.x` and `v2.x` releases are unofficial research artefacts. They are not affiliated with,
endorsed by, or supported by Signal, and they have not received a production cryptographic
security audit.
