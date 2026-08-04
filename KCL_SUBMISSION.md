# KCL MSc Dissertation Submission — Reader's Guide and File Map

Module: 7CCSMPRJ Individual Project
Author: Mark Saviour Farrugia (K25128781)
Programme: MSc Cybersecurity, King's College London
Supervisor: Dr Benjamin Dowling

This repository is a fork of upstream libsignal (snapshot 0.73.3). The
project contribution converts Signal's hybrid PQXDH handshake into a
fully post-quantum handshake and adds the apparatus to evaluate it. This
file is the reader's map to the archive; PROJECT_RELEASE_NOTES.md is the
detailed design-and-rationale companion, and README.md is upstream
Signal's own documentation, retained unchanged.

## How to read this archive

The great majority of files in this fork are upstream libsignal and were
neither written nor modified for this project. The project touched a
small, specific set of files, listed under "What was changed" below.
Everything not listed there should be treated as unmodified upstream
code that the project did not use.

## Top-level file map

- rust/ — the Rust workspace. Only ONE crate in it was modified:
  rust/protocol/ (libsignal-protocol). All other crates (account-keys,
  attest, bridge, core, crypto, keytrans, media, message-backup, net,
  and the rest) are UPSTREAM and UNUSED by this project.
- rust/protocol/ — the crate containing the entire project
  contribution. See the crate-level map below.
- third-party/hqc-kem/ — ADDED (vendored). A pure-Rust HQC-256
  implementation adapted from the RustCrypto KEMs project, vendored
  because the project pins an unreleased revision and fixes an inverted
  byte-length check in its deserialisation. Not the author's own work;
  it keeps its own upstream README and licence.
- evidence/ — ADDED (on the evidence branch). The measurement harness,
  schedule, correctness-gate records, environment manifests, and size
  captures. See evidence/README.md there.
- PROJECT_RELEASE_NOTES.md — ADDED. The project's design, primitive,
  and measured-findings record, and the authoritative change log.
- KCL_SUBMISSION.md, AUTHORSHIP.md — ADDED. This guide and the
  authorship statement.
- java/, swift/, node/ — UPSTREAM and UNUSED. These language bridges
  assume Curve25519 identities and were deliberately not ported; builds
  are always scoped to the Rust crate with -p libsignal-protocol.
- doc/, bin/, acknowledgments/, .github/, and all dotfiles and manifests
  at the root (Cargo.toml, Cargo.lock, LICENSE, README.md,
  RELEASE_NOTES.md, RELEASE.md, TESTING.md, SECURITY.md,
  CODING_GUIDELINES.md, LibSignalClient.podspec, justfile,
  rust-toolchain) — UPSTREAM. Cargo.toml and Cargo.lock carry the
  project's added dependencies but are otherwise upstream.

## Map of rust/protocol/ (where the contribution lives)

Added files (written for this project):
- src/kem/hqc256.rs — ADDED. Implements the KEM Parameters trait over
  the vendored hqc-kem crate, plugging HQC-256 into the generic KEM API.
- src/dsa.rs — ADDED. The ML-DSA-87 signing-identity integration.
- examples/pqxdh.rs — ADDED. Handshake demonstration.
- examples/full_session.rs — ADDED. Full public-API session flow.
- examples/sizes.rs — ADDED. Deterministic serialised-size capture.
- benches/kem.rs — ADDED. KEM generate/encapsulate/decapsulate benchmark
  with type-prefixed size columns.
- benches/mldsa.rs — ADDED. ML-DSA-87 keygen/sign/verify benchmark.
- benches/session.rs — ADDED. Initiator and responder handshake spans in
  both KEM modes.

Edited files (upstream files changed for this project):
- src/kem.rs and src/kem/{mlkem1024.rs, kyber1024.rs} — EDITED to add
  and register the post-quantum KEM types used by the two lines.
- src/ratchet.rs — EDITED for the fully post-quantum secret derivation
  and the domain-separation labels.
- src/state/bundle.rs — EDITED for the signed KEM prekeys and the
  optional one-time prekey.
- src/proto/wire.proto and src/proto/storage.proto — EDITED to add the
  post-quantum one-time prekey id, ciphertext, and identity-signature
  fields.
- tests/session.rs — EDITED to add the PQXDH handshake coverage and the
  negative (tampering) tests.

Everything else under rust/protocol/src/ is UPSTREAM and unchanged by
the handshake work. src/sealed_sender.rs is upstream and is gated off,
because Sealed Sender needs Diffie-Hellman that a signing-only identity
cannot provide.

## Building and running

Pinned Rust nightly; exact version in rust-toolchain and in the evidence
manifests. Requires a C/C++ linker and protoc. From the repo root:

- Version 2 handshake tests:
  cargo test -p libsignal-protocol --no-default-features --features hqc256
- Version 1 handshake tests:
  cargo test -p libsignal-protocol --no-default-features --features mlkem1024
- Vendored HQC-256 crate tests:
  cargo test --manifest-path third-party/hqc-kem/Cargo.toml
- Handshake and session demonstrations:
  cargo run -p libsignal-protocol --example pqxdh
  cargo run -p libsignal-protocol --example full_session
- Deterministic sizes:
  cargo run --release -p libsignal-protocol --example sizes
- Benchmarks:
  cargo bench -p libsignal-protocol --features "hqc256 mlkem1024" --bench kem
  cargo bench -p libsignal-protocol --bench mldsa
  cargo bench -p libsignal-protocol --bench session

The five-block measurement schedule is on the evidence branch under
evidence/schedule/.

## Licence

GNU Affero General Public License version 3, inherited from upstream
libsignal. See LICENSE.
