# Project Release Notes

This file is the single project-authored document for the `v1.x` (ML-KEM-1024 + ML-DSA-87) line
of the Post-Quantum Signal research artefact. Each release line carries its own copy of these
notes, scoped to that line's releases; this copy records the `v1.x` releases and consolidates the
design material that earlier releases kept in the separate `POST_QUANTUM_PQXDH.md` document.
Project versions use Git tags and are independent of Signal's inherited package version metadata.

## Version and tag conventions

- Upstream libsignal snapshot: `0.73.3`.
- Rust `libsignal-protocol` crate metadata: `0.1.0`.
- Existing research tags: `v1.0.0`, `v1.0.1`, and `v2.0.0`.
- Signal's inherited `RELEASE_NOTES.md` remains at `0.73.3`; these project notes are the source for
  research GitHub releases.
- Each line's copy of these notes documents that line's releases.

The `v1.x` line evaluates ML-KEM-1024 with ML-DSA-87. The `v2.x` line replaces ML-KEM-1024 with
HQC-256 while retaining ML-DSA-87 and the same KEM-agnostic PQXDH construction; its releases and
HQC material are documented in its own copy of these notes on the `v2.x` branches.

## Branch layout

Each release line has its own pair of branches; there is no single aggregated history:

- `main-v1` — current state of the `v1.x` line; release tags mark its published versions.
- `main-v2` — current state of the `v2.x` line and the repository default branch; release tags
  mark its published versions.
- `working-v1.x` and `working-v2.x` — development branches for the two lines. Release candidates
  are validated and tagged there, then merged into the corresponding `main-vN` branch.

The former aggregated `main` branch interleaved the two release lines in one history, so during
`v2.0.1` it was retired in favour of the per-line branches above. Each line's history contains
only the shared post-quantum baseline plus its own work; improvements are ported between lines as
ordinary commits rather than history merges.

## Documentation policy

Each release line keeps exactly one project-authored Markdown file: this one. Every other
Markdown file in the repository (`README.md`, `RELEASE_NOTES.md`, `RELEASE.md`, `TESTING.md`,
`SECURITY.md`, `CODING_GUIDELINES.md`, and the `doc/` book) is inherited from upstream libsignal.
This line's `POST_QUANTUM_PQXDH.md` design document was consolidated into the technical summary
below; its full text remains available in Git history up to tag `v1.0.1`.

## Imported libsignal versions

These snapshots are development baselines, not Post-Quantum Signal release tags:

- `0.87.5` — initially imported on 2 March 2026 in commit
  `f75f33e115f86ce9f0e804447da249752d33093d`.
- `0.73.3` — adopted on 17 June 2026 in commit
  `26ff061ede6512736a7c51d7bd617673ed031791` as the base for the post-quantum implementation.

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
- Adds the `pqxdh` runnable handshake demonstration and the initial `POST_QUANTUM_PQXDH.md`
  design document (since consolidated into this file).

### Scope

- The initial shared secret contains no X25519 contribution.
- X25519 remains as the Double Ratchet key after the handshake.
- Sealed Sender and non-Rust language bindings are not supported by this research variant.
- The protocol is intentionally incompatible with stock Signal clients.

## Technical summary

This section consolidates the retired `POST_QUANTUM_PQXDH.md` design document for the `v1.x`
line. The handshake construction is KEM-agnostic: the `v2.x` line swaps ML-KEM-1024 for HQC-256,
and its copy of these notes records the HQC integration and the measured ML-KEM-1024 versus
HQC-256 comparison.

### Fully post-quantum PQXDH design

The initial PQXDH key agreement is converted from Signal's hybrid construction (X25519
Diffie–Hellman plus a post-quantum KEM) into a fully post-quantum handshake:

- The long-term identity is an ML-DSA-87 signing keypair used only to produce and verify
  signatures; it can no longer perform Diffie–Hellman, so a harvest-now-decrypt-later adversary
  has no DH value to break.
- Bob publishes a bundle containing a signed X25519 ratchet key (Double Ratchet bootstrap only —
  it contributes nothing to the secret), a mandatory signed KEM prekey, and an optional one-time
  KEM prekey, each signed by his ML-DSA-87 identity.
- Alice verifies every bundle signature, then encapsulates to the signed prekey (`ss1`/`ct1`) and,
  if present, to the one-time prekey (`ss2`/`ct2`). The one-time prekey provides post-quantum
  forward secrecy for the initial message.
- The secret input is `0xFF*32 ‖ ss1 ‖ [ss2]`, derived through HKDF-SHA-256. There is no X25519
  contribution to the shared secret.
- Alice authenticates explicitly by signing the handshake transcript with her ML-DSA-87 identity.
  The transcript length-prefixes the label, both identities, both ciphertexts, Bob's ratchet key,
  and Alice's base key, preventing mix-and-match manipulation; Bob rejects tampering with
  `SignatureValidationFailed`.
- All ML-DSA operations use the context string `Signal_PQXDH_MLDSA87`.

The KEM is selected at prekey-generation time. This line's domain-separation labels are
`PQXDH_MLKEM1024_MLDSA87_SHA-256` (HKDF) and `PQXDH_MLKEM1024_MLDSA87_transcript` (transcript);
the `v2.x` line substitutes HQC-256 labels.

### Primitives

| Primitive | Role | Library | Type tag | Sizes (bytes) |
| --- | --- | --- | --- | --- |
| ML-DSA-87 (FIPS 204) | Identity / signatures | `libcrux-ml-dsa` 0.0.8 | `0x09` | pk 2592, sk 4896, sig 4627 |
| ML-KEM-1024 (FIPS 203) | KEM prekeys | `libcrux-ml-kem` 0.0.2 | `0x0A` | pk 1568, sk 3168, ct 1568, ss 32 |
| X25519 | Double Ratchet ratchet key only | `curve25519-dalek` | `0x05` | pk 32 |
| HKDF-SHA-256 | Root/chain key derivation | `hkdf` / `sha2` | — | 64-byte output |

ML-DSA-87 and ML-KEM-1024 both sit at NIST security level 5.

### Wire and storage additions

`PreKeySignalMessage` (`wire.proto`) gains `pq_one_time_pre_key_id (9)`,
`pq_one_time_ciphertext (10)`, and `identity_signature (11)`. `PendingKyberPreKey`
(`storage.proto`) gains `pq_one_time_pre_key_id (3)`, `pq_one_time_ciphertext (4)`, and
`identity_signature (5)` so the same authenticator and ciphertexts are re-sent on every
`PreKeySignalMessage` until Bob acknowledges the session.

### Scope and caveats

- The Double Ratchet that runs after the handshake still uses X25519, so these releases deliver a
  fully post-quantum handshake, not a fully post-quantum session.
- Sealed Sender performs Diffie–Hellman against the identity key, which a signing-only ML-DSA
  identity cannot do; it is gated behind the off-by-default `sealed_sender` feature.
- Only the Rust `libsignal-protocol` crate is updated. The Java, Swift, and Node bridges still
  assume Curve25519 identities, so always scope builds with `-p libsignal-protocol`.
- The wire format is intentionally incompatible with stock Signal clients.

### Build, test, and demonstration commands

```bash
cargo build -p libsignal-protocol
cargo test  -p libsignal-protocol
cargo run   -p libsignal-protocol --example pqxdh          # handshake demonstration
cargo run   -p libsignal-protocol --example full_session   # full public-API session flow
cargo bench -p libsignal-protocol --bench kem
```

Building requires a C/C++ linker toolchain and `protoc`, which `rust/protocol/build.rs` uses to
compile the wire and storage protobuf definitions.

## Shared release notice

All `v1.x` and `v2.x` releases are unofficial research artefacts. They are not affiliated with,
endorsed by, or supported by Signal, and they have not received a production cryptographic
security audit.
