# Project Release Notes

This file is the single project-authored document for the `v2.x` (HQC-256 + ML-DSA-87) line of
the Post-Quantum Signal research artefact. Each release line carries its own copy of these notes,
scoped to that line's releases; this copy records the `v2.x` releases and consolidates the design
and evaluation material that earlier releases kept in separate documents (`POST_QUANTUM_PQXDH.md`
and `HQC_SWAP_CHANGES.md`, both retired in `v2.0.1`). Project versions use Git tags and are
independent of Signal's inherited package version metadata.

## Version and tag conventions

- Upstream libsignal snapshot: `0.73.3`.
- Rust `libsignal-protocol` crate metadata: `0.1.0`.
- Existing research tags: `v1.0.0`, `v1.0.1`, and `v2.0.0`.
- Current release candidate: `v2.0.1`.
- Signal's inherited `RELEASE_NOTES.md` remains at `0.73.3`; these project notes are the source for
  research GitHub releases.
- Each line's copy of these notes documents that line's releases.

The `v1.x` line evaluates ML-KEM-1024 with ML-DSA-87. The `v2.x` line replaces ML-KEM-1024 with
HQC-256 while retaining ML-DSA-87 and the same KEM-agnostic PQXDH construction. The `v1.x`
releases are documented in the `v1.x` line's copy of these notes.

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

From `v2.0.1` onward each release line keeps exactly one project-authored Markdown file: its own
copy of these notes. Every other Markdown file in the repository (`README.md`, `RELEASE_NOTES.md`,
`RELEASE.md`, `TESTING.md`, `SECURITY.md`, `CODING_GUIDELINES.md`, and the `doc/` book) is
inherited from upstream libsignal, and `third-party/hqc-kem/` keeps its own upstream README as
part of the vendored crate. The `v1.x` line's `POST_QUANTUM_PQXDH.md` was retired the same way,
and the full text of all retired documents remains available in Git history up to tags `v1.0.1`
and `v2.0.0`.

## Imported libsignal versions

These snapshots are development baselines, not Post-Quantum Signal release tags:

- `0.87.5` — initially imported on 2 March 2026 in commit
  `f75f33e115f86ce9f0e804447da249752d33093d`.
- `0.73.3` — adopted on 17 June 2026 in commit
  `26ff061ede6512736a7c51d7bd617673ed031791` as the base for the post-quantum implementation.

## v2.0.1 — Documentation and portability update

- **Status:** In progress on `working-v2.x`
- **Base tag:** `v2.0.0`
- **Release tag:** `v2.0.1` after validation

Changes applied so far:

- Restore the Unix executable modes and shared test-fixture symlinks that the Windows-authored
  baseline snapshot had lost (the `v1.x` line shipped the same repair in `v1.0.1`).
- Consolidate all project-authored documentation into this single file and remove
  `HQC_SWAP_CHANGES.md` and `POST_QUANTUM_PQXDH.md`, replacing their stale branch, validation,
  terminology, and HQC standardisation statements with the corrected technical summary below.
- Retire the aggregated `main` branch in favour of the per-line release branches `main-v1` and
  `main-v2` (see the branch layout above).

Remaining planned changes:

- Add project-specific README content while preserving the original Signal README beneath it.
- Complete the project-authored comment audit.
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

## v1.x line releases

This line builds on the fully post-quantum PQXDH baseline released as `v1.0.0` (commit
`f55ae91d9bb9d9412763adf7aa5b67e345cba7e1`), which is also this line's base tag. The `v1.x`
releases — the `v1.0.0` baseline and the `v1.0.1` session demonstration — are documented in the
`v1.x` line's copy of these notes on `main-v1` and `working-v1.x`.

## Technical summary

This section consolidates the retired design documents. `v1.x` refers to the ML-KEM-1024 line and
`v2.x` to the HQC-256 line; the handshake construction is identical in both, so the comparison
cleanly isolates the KEM.

### Fully post-quantum PQXDH design (both lines)

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

The KEM is selected at prekey-generation time, and each line uses its own domain-separation
labels:

| Line | HKDF label | Transcript label |
| --- | --- | --- |
| `v1.x` | `PQXDH_MLKEM1024_MLDSA87_SHA-256` | `PQXDH_MLKEM1024_MLDSA87_transcript` |
| `v2.x` | `PQXDH_HQC256_MLDSA87_SHA-256` | `PQXDH_HQC256_MLDSA87_transcript` |

### Primitives

| Primitive | Role | Library | Type tag | Sizes (bytes) |
| --- | --- | --- | --- | --- |
| ML-DSA-87 (FIPS 204) | Identity / signatures | `libcrux-ml-dsa` 0.0.8 | `0x09` | pk 2592, sk 4896, sig 4627 |
| HQC-256 | KEM prekeys (`v2.x` default) | vendored `hqc-kem` | `0x0B` | pk 7237, sk 7333, ct 14421, ss 32 |
| ML-KEM-1024 (FIPS 203) | KEM prekeys (`v1.x`); benchmark baseline in `v2.x` | `libcrux-ml-kem` 0.0.2 | `0x0A` | pk 1568, sk 3168, ct 1568, ss 32 |
| X25519 | Double Ratchet ratchet key only | `curve25519-dalek` | `0x05` | pk 32 |
| HKDF-SHA-256 | Root/chain key derivation | `hkdf` / `sha2` | — | 64-byte output |

ML-DSA-87, ML-KEM-1024, and HQC-256 all sit at NIST security level 5.

### Wire and storage additions

`PreKeySignalMessage` (`wire.proto`) gains `pq_one_time_pre_key_id (9)`,
`pq_one_time_ciphertext (10)`, and `identity_signature (11)`. `PendingKyberPreKey`
(`storage.proto`) gains `pq_one_time_pre_key_id (3)`, `pq_one_time_ciphertext (4)`, and
`identity_signature (5)` so the same authenticator and ciphertexts are re-sent on every
`PreKeySignalMessage` until Bob acknowledges the session.

### v2.x HQC-256 integration specifics

- `rust/protocol/src/kem/hqc256.rs` implements the existing `kem::Parameters` trait over the
  pure-Rust `hqc-kem` crate, so HQC-256 plugs into the generic KEM API with no handshake changes.
- `hqc-kem` builds against `rand` 0.10 while libsignal uses `rand` 0.9, and the two `CryptoRng`
  traits are incompatible. The wrapper therefore draws the keygen seed and the encapsulation
  message and salt from the caller's CSPRNG and calls HQC's deterministic entry points, keeping
  all randomness caller-sourced.
- The crate is vendored at `third-party/hqc-kem/` because the upstream `from_bytes!` macro had an
  inverted byte-length check that rejected correct lengths and accepted wrong ones, breaking key
  and ciphertext reconstruction from stored bytes; the vendored copy fixes the comparison.
  Research finding: the pure-Rust HQC ecosystem is markedly less mature than ML-KEM's formally
  verified libcrux implementation.
- Cargo features: `hqc256` is the default on the `v2.x` line, and `mlkem1024` is retained as a
  non-default, benchmark-only feature.

### Measured KEM comparison (recorded for v2.0.0)

Sizes in bytes:

| Quantity | ML-KEM-1024 | HQC-256 | HQC ÷ ML-KEM |
| --- | --- | --- | --- |
| Public key | 1568 | 7237 | ≈ 4.6× |
| Secret key | 3168 | 7333 | ≈ 2.3× |
| Ciphertext | 1568 | 14421 | ≈ 9.2× |
| Shared secret | 32 | 32 | 1× |

Criterion medians from the `kem` benchmark (optimised build):

| Operation | ML-KEM-1024 | HQC-256 | HQC ÷ ML-KEM |
| --- | --- | --- | --- |
| `generate` | ~15.1 µs | ~692 µs | ~46× |
| `encapsulate` | ~12.2 µs | ~1.38 ms | ~114× |
| `decapsulate` | ~24.9 µs | ~3.53 ms | ~142× |

Per handshake, the two KEM ciphertexts in a `PreKeySignalMessage` grow from roughly 3.1 KB with
ML-KEM to roughly 28.8 KB with HQC, and the two bundle public keys from roughly 3.1 KB to roughly
14.5 KB. Kyber1024 tracks ML-KEM-1024 closely in the same benchmark, confirming the lattice
baseline.

Conclusion: for a bandwidth- and latency-sensitive messenger, ML-KEM-1024 is the decisively more
efficient level-5 choice, so Signal's selection is well justified on engineering grounds. HQC-256's
value is algorithmic diversity on a code-based hardness assumption — NIST selected it in March
2025 as the backup to ML-KEM, with standardisation as FIPS 207 in progress — which suits it to a
fallback or hybrid role rather than a drop-in replacement.

### Scope and caveats (all releases)

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
cargo bench -p libsignal-protocol --features "hqc256 mlkem1024" --bench kem
```

Building requires a C/C++ linker toolchain and `protoc`, which `rust/protocol/build.rs` uses to
compile the wire and storage protobuf definitions.

## Shared release notice

All `v1.x` and `v2.x` releases are unofficial research artefacts. They are not affiliated with,
endorsed by, or supported by Signal, and they have not received a production cryptographic
security audit.
