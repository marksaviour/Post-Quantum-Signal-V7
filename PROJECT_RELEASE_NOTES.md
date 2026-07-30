<!--
Copyright 2026 Mark Saviour Farrugia.
SPDX-License-Identifier: AGPL-3.0-only
-->

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

## Measurement harness — unreleased, `working-v1.x`

Preparation of this line for the Chapter 5 measurement. Every change is confined to
`benches/`, `examples/`, `tests/`, and these notes; `rust/protocol/src/` carries no behavioural
change, so results measured here remain comparable with the tagged releases above.

### Instruments on this line

| Instrument | Produces | Status |
| --- | --- | --- |
| `examples/sizes.rs` | Serialised sizes for both KEM modes, at fixed canonical inputs | Added |
| `benches/session.rs` — `session_initiate` | Initiator span, both KEM modes | Added |
| `benches/session.rs` — `session_decrypt_first_message_modes` | Responder span, both KEM modes | Added |
| `benches/session.rs` — `session_encrypt`, `session_encrypt_decrypt` | Steady-state session spans | Inherited from upstream |
| `benches/kem.rs` | — | Inherited; **not** a Version 1 measurement source |
| `benches/ratchet.rs`, `benches/sealed_sender.rs` | — | Inherited; unused by this project |

The two spans that Chapter 4.3 bounds explicitly are the initiator span, from processing the
responder's bundle to the serialised initial `PreKeySignalMessage`, and the responder span, from
that serialised message to the derived session using a fresh store. Store creation and cloning sit
outside both timed regions. Each is measured in last-resort-only and last-resort-plus-one-time
mode, giving the four benchmark identifiers `initiate session and encrypt first message`,
`initiate session and encrypt first message, last-resort only`,
`session decrypt first message, full mode`, and
`session decrypt first message, last-resort only`.

Run the instruments with the Version 1 feature set explicitly, never with defaults:

```bash
cargo run   -p libsignal-protocol --example sizes  --no-default-features --features mlkem1024
cargo bench -p libsignal-protocol --bench  session --no-default-features --features mlkem1024
```

`examples/sizes.rs` differs from the `v2.x` copy in one place. The `v2.x` copy selects its KEM with
a `cfg(feature = "hqc256")` gate; this line pins the constant instead, because `hqc256` is not a
feature this manifest declares and naming it here warns under `unexpected_cfgs`, which would breach
the clippy condition on the correctness gate below. The two copies are otherwise identical.

### Corrected KEM type in the store-backed test fixture

`TestStoreBuilder::add_kyber_pre_key` generated a `Kyber1024` prekey rather than an `MLKEM1024`
one. Upstream `0.73.3` had three KEM generation sites in `tests/support/mod.rs`, all `Kyber1024`.
The `v1.0.0` conversion changed two of them and added two further sites for the one-time prekey,
giving the five this line now has, but it missed the third upstream site, inside `TestStoreBuilder`.
The surrounding identifiers all retain Signal's inherited "kyber" vocabulary, so
`kyber_pre_key_pair` holding a `Kyber1024` constant read as consistent.

`with_kyber_pre_key` is reached by three of the nine tests Chapter 4.2 names as evidence —
`test_prekey_handshake_without_one_time_kem`, `test_bad_signed_pre_key_signature`, and
`test_bad_kyber_pre_key_signature` — and by the last-resort-only arms of both new benchmark spans.
Until this fix, the store-backed full-protocol path in last-resort-only mode had never been
exercised with ML-KEM-1024 on this line.

The tests pass both before and after, which is the point: the handshake is KEM-agnostic and both
primitives are level 5 with identical 1568-byte keys and ciphertexts, so no round trip and no size
assertion could have revealed the substitution. It is worth recording as evidence for the
limitation Chapter 4.5 already states, since those three tests were running a handshake whose HKDF
`info` label asserted `PQXDH_MLKEM1024_MLDSA87_SHA-256` while the encapsulation was Kyber1024. The
label asserts the algorithm suite; it does not enforce it.

### `benches/kem.rs` is not a Version 1 measurement source

`benches/kem.rs` on this line is unmodified upstream Signal code and still carries
`required-features = ["kyber768"]`. Its cases and its feature set both differ from the corrected
KEM target, which Chapter 4.3 runs from the common primitive harness derived from `v2.0.0` with
`hqc256` and `mlkem1024` enabled. It is left untouched deliberately. Do not run it and report the
output as a Version 1 result. It is skipped by the correctness gate below, because the Version 1
feature set does not enable `kyber768`.

### ML-DSA-87 is measured once, from the common primitive harness

`benches/mldsa.rs` is deliberately absent from this line. ML-DSA-87 is byte-identical across both
release lines, with both resolving `libcrux-ml-dsa` 0.0.8, so it is measured once from the common
primitive harness on the same lockfile-and-diff argument Chapter 4.3 already applies to the KEM
target. Measuring identical code twice would produce two numbers differing only by noise and invite
a comparison the chapter does not make. Chapter 4.3 must state this explicitly; the alternative,
should it be revisited, is to copy `benches/mldsa.rs` here and add a `[[bench]]` entry for it.

### The runnable demonstrations differ from the `v2.x` line by design

`examples/full_session.rs` and `examples/pqxdh.rs` are not kept in step with the `v2.x` copies, and
the divergence should not be reported as drift. Each line's demonstration names the KEM that line
actually builds, so the ML-KEM-1024 wording here is correct and the HQC-256 wording there is
correct. The remaining differences are an identifier rename on `v2.x` from `signed_kem_pair` to
`signed_kyber_pair`, which moves back toward the inherited "kyber" vocabulary implicated in the
fixture defect above, and a `v2.x` heading describing the artefact as the complete post-quantum
Signal protocol, which overstates it: the Double Ratchet after the handshake still uses X25519, as
this line's wording and Chapter 3.1.1's scoping both say.

Two corrections are outstanding **on `v2.x`, not here**: restore the wording to match this line's,
and restore the upstream `Copyright 2024 Signal Messenger, LLC.` notice to both files. Those are
the only two files in which the `v2.0.1` header audit replaced Signal's notice instead of adding
alongside it, which AGPL-3.0 does not permit.

### Correctness gate

Chapter 4.2 makes a recorded correctness run a precondition for accepting any timing measurement.
This run was performed on the tree of the immediately preceding commit; re-run and re-record it if
any further change lands before the measurement blocks begin.

```bash
cargo test   -p libsignal-protocol --no-default-features --features mlkem1024
cargo clippy -p libsignal-protocol --no-default-features --features mlkem1024 --all-targets
```

- **Environment:** `rustc` 1.87.0-nightly (617aad8c2 2025-02-24), `cargo` 1.87.0-nightly
  (1d1d646c0 2025-02-21), pinned by `rust-toolchain.toml` to `nightly-2025-02-25`.
- **Resolved primitives:** `libcrux-ml-kem` 0.0.2, `libcrux-ml-dsa` 0.0.8, `hkdf` 0.12.4,
  `sha2` 0.10.8, `curve25519-dalek` 4.1.3 (Signal fork), `criterion` 0.5.1.
- **Result:** 68 passed, 0 failed, 2 ignored.

| Target | Passed | Failed | Ignored |
| --- | --- | --- | --- |
| `libsignal_protocol` unit tests | 45 | 0 | 0 |
| `tests/groups.rs` | 8 | 0 | 1 |
| `tests/ratchet.rs` | 3 | 0 | 0 |
| `tests/session.rs` | 10 | 0 | 0 |
| `tests/sealed_sender.rs` | 0 | 0 | 0 |
| Doc-tests | 2 | 0 | 1 |

`tests/sealed_sender.rs` is empty under this feature set because Sealed Sender is gated off, and
the two ignored cases are the upstream slow group test and one non-executable doc example.

All nine tests Chapter 4.2 names by identifier are present and passing:
`test_full_pq_prekey_handshake`, `test_prekey_handshake_without_one_time_kem`,
`test_alice_and_bob_agree_with_one_time_kem_prekey`,
`test_alice_and_bob_agree_without_one_time_kem_prekey`, `test_bad_signed_pre_key_signature`,
`test_bad_kyber_pre_key_signature`, `test_bob_rejects_bad_transcript_signature`,
`prekey_message_failed_decryption_does_not_update_stores`, and `test_repeat_bundle_message`.

Clippy reports two warnings, both pre-existing `v1.0.0` library findings already recorded under
`v1.0.1` below: `large_enum_variant` in `protocol.rs` and `cast_possible_truncation` in
`ratchet.rs`. No new finding arises from any instrument added here. Clippy was re-run after the
integrated exchange case was added to `benches/session.rs` and the four bounded span cases were
aligned with Chapter 4.3 — every store clone moved into an `iter_batched` setup closure, and both
responder spans now beginning from the serialised message bytes rather than a pre-parsed message —
and it reported those same two findings and nothing further, with
`cargo bench --bench session --no-run` compiling the target cleanly.

The domain-separation labels were re-confirmed as the ML-KEM variants,
`PQXDH_MLKEM1024_MLDSA87_SHA-256` and `PQXDH_MLKEM1024_MLDSA87_transcript`. They enter the HKDF
`info` value and the signed transcript, so substituting the HQC forms would silently invalidate
every Version 1 result.

### Still outstanding before Chapter 5

The baseline harness does not exist on any branch. Commit `26ff061` is unmodified upstream: it has
no size capture, no span benchmarks, a Kyber1024 KEM, no ML-DSA identity, and no transcript
signature, so neither harness ports across unchanged. Chapter 4.5 admits only results from pinned
harness commits whose archived diffs confirm protocol code is unchanged, so the baseline harness
must be a benchmark-and-example-files-only addition on top of `26ff061`, with that diff archived.
Until it exists, Sections 5.3 and 5.4 have no baseline column and RQ2 cannot be answered as posed.

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
```

`default = ["mlkem1024"]`, so plain invocations build this line's configuration. State the feature
set explicitly anyway for anything whose output is reported, as the measurement-harness section
above does. `cargo bench --bench kem` is deliberately not listed: that target is inherited upstream
code and is not a Version 1 measurement source.

Building requires a C/C++ linker toolchain and `protoc`, which `rust/protocol/build.rs` uses to
compile the wire and storage protobuf definitions.

## Shared release notice

All `v1.x` and `v2.x` releases are unofficial research artefacts. They are not affiliated with,
endorsed by, or supported by Signal, and they have not received a production cryptographic
security audit.
