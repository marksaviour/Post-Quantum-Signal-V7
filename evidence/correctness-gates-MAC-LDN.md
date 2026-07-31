# Correctness gates, MAC-LDN
Date: 31 July 2026
Conditions: mains charger connected; nonessential applications quit. Environment: manifests/MAC-LDN.md.

Baseline, branch baseline at 7c20bca (protocol source identical to v0.0.0):
  cargo test -p libsignal-protocol
  89 passed, 0 failed, 4 ignored (lib 44/0/0; groups 11/0/1; ratchet 3/0/0; sealed_sender 11/0/0; session 18/0/2; doc 2/0/1)

Version 1, working-v1.x at 11e9fd1:
  cargo test -p libsignal-protocol --no-default-features --features mlkem1024
  68 passed, 0 failed, 2 ignored (lib 45/0/0; groups 8/0/1; ratchet 3/0/0; sealed_sender empty under this feature set; session 10/0/0; doc 2/0/1)

Version 2, working-v2.x at 70e0812:
  cargo test -p libsignal-protocol --no-default-features --features hqc256
  68 passed, 0 failed, 2 ignored (per-set shape identical to Version 1)

HQC KEM crate, vendored, same tree:
  cargo test --manifest-path third-party/hqc-kem/Cargo.toml
  6 passed, 0 failed (HQC-128, HQC-192, HQC-256 known-answer and round-trip), plus 1 documentation test

Ignored tests are upstream's slow tests and one upstream documentation example.
