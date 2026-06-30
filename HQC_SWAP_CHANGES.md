# HQC-256 Swap — Change Log & Implementation Record

This document records every change made to replace the post-quantum **KEM** in the fully
post-quantum PQXDH handshake from **ML-KEM-1024** to **HQC-256**, on the `working` branch. It covers
what changed, where, why, the errors encountered along the way, and how the result was validated.

- **Baseline:** commit `f55ae91` — *"Convert PQXDH to a fully post-quantum handshake (ML-KEM-1024 +
  ML-DSA-87)"*.
- **Goal:** evaluate whether Signal's choice of ML-KEM-1024 is optimal, by swapping in the
  code-based HQC-256 and comparing size and speed.
- **Design invariant:** the handshake is **KEM-agnostic** — ML-DSA-87 identity/authentication, the
  `0xFF*32 ‖ ss1 ‖ [ss2]` secret, the Double Ratchet, and the wire/storage shape are unchanged. Only
  *which KEM the prekeys use* and the domain-separation labels change.
- **Scope:** confined to the Rust `libsignal-protocol` crate plus one vendored dependency. Java /
  Swift / Node bindings remain out of scope (as in the prior ML-DSA work). Build everything with
  `-p libsignal-protocol`.

---

## 1. Commits (on `working`, atop `f55ae91`)

| Commit | Summary | Plan step |
| --- | --- | --- |
| `51ba815` | Add hqc-kem dependency and hqc256 Cargo feature | 1 |
| `0d39683` | Add HQC-256 KEM wrapper behind the `kem::Parameters` trait | 2 |
| `4bcaaa9` | Switch the PQXDH handshake from ML-KEM-1024 to HQC-256 | 3 |
| `a4d2458` | Add HQC-256 vs ML-KEM-1024 KEM benchmark comparison | 4 |

Uncommitted at time of writing (validation + docs): the vendored crate `third-party/hqc-kem/`, the
dependency repoint in `Cargo.toml` / `Cargo.lock`, an unused-import removal in `hqc256.rs`,
`POST_QUANTUM_PQXDH.md`, and this file.

---

## 2. Changed files (vs `f55ae91`)

Cumulative `git diff --stat` (12 tracked files, **+512 / −75**), plus untracked/external additions:

| File | Lines | Kind | Summary |
| --- | --- | --- | --- |
| `rust/protocol/src/kem/hqc256.rs` | +83 | **new** | HQC-256 wrapper implementing the `kem::Parameters` trait over `hqc-kem`. |
| `rust/protocol/src/kem.rs` | ~56 | modified | New `KeyType::HQC256` (tag `0x0B`), dispatch arms, module decl, doc, unit tests. |
| `rust/protocol/src/ratchet.rs` | ~8 | modified | Domain-separation labels `PQXDH_MLKEM1024_*` → `PQXDH_HQC256_*` + comments. |
| `rust/protocol/tests/support/mod.rs` | ~20 | modified | Prekey generation → `KeyType::HQC256` + comments. |
| `rust/protocol/tests/ratchet.rs` | ~10 | modified | Prekey generation → `KeyType::HQC256` + comments. |
| `rust/protocol/examples/pqxdh.rs` | ~18 | modified | Prekey generation + printed text → HQC-256. |
| `rust/protocol/benches/session.rs` | ~4 | modified | Session-bench prekey → `KeyType::HQC256`. |
| `rust/protocol/benches/kem.rs` | ~36 | modified | 3-way KEM comparison + size report. |
| `rust/protocol/Cargo.toml` | ~15 | modified | `hqc-kem` optional dep, `hqc256` feature, default flip, bench features. |
| `Cargo.toml` (workspace) | ~7 | modified | `hqc-kem` dependency (now vendored path) + workspace `exclude`. |
| `Cargo.lock` | ~176 | modified | `hqc-kem` + transitive crates (`sha3`, `shake`, `keccak`, `rand 0.10`, …). |
| `POST_QUANTUM_PQXDH.md` | ~154 | modified | Branch note, primitives table, labels, demo output, new §13 comparison. |
| `third-party/hqc-kem/**` | ~24 files | **new (vendored)** | Patched copy of `hqc-kem` 0.1.0 (one-line deserialization fix). |
| `~/.cargo/config.toml` | new | **machine-local (not in repo)** | Sets `PROTOC` so Cargo finds `protoc` in any terminal. |

---

## 3. Build prerequisites added (environment, not source)

These are standard libsignal build requirements (not specific to HQC) that had to be satisfied on the
build machine. They are recorded here because they were necessary to compile and validate the swap.

1. **MSVC C++ Build Tools** (`cl.exe` / `link.exe` + Windows SDK). Required to link any
   `-windows-msvc` Rust build. Installed via *Visual Studio Build Tools 2026* (`VC.Tools.x86.x64`
   workload). Cargo locates it automatically via `vswhere`.
2. **`protoc`** (Protocol Buffers compiler). `rust/protocol/build.rs` uses `prost-build` to compile
   `wire.proto` / `storage.proto`, which needs the `protoc` binary. Installed to
   `C:\Users\marksaviour\protoc\` (protoc 35.1).
3. **`~/.cargo/config.toml`** (machine-local; *not* committed):
   ```toml
   [env]
   PROTOC = 'C:\Users\marksaviour\protoc\bin\protoc.exe'
   ```
   Cargo injects `PROTOC` for every invocation, so the build works in any terminal without per-session
   environment setup.

---

## 4. Detailed changes

### 4.1 `rust/protocol/src/kem/hqc256.rs` — **new** HQC-256 wrapper

The single new source file. It implements the existing `kem::Parameters` trait (the per-KEM
extension point) over the `hqc-kem` crate, so HQC plugs into the generic `kem::KeyPair` /
`PublicKey` / `SecretKey` API with no handshake changes.

- **Sizes** are taken from the crate's constants (lines 33–37): pk 7237, sk 7333, ct 14421, ss 32.
- **RNG bridge (key design point).** `hqc-kem` builds against `rand` 0.10 while libsignal uses
  `rand` 0.9 — the two `CryptoRng` traits are incompatible, so the caller's RNG cannot be passed
  directly. Instead the wrapper draws the keygen **seed** / encapsulation **message + salt** from the
  caller's CSPRNG (`fill_bytes`) and calls HQC's **deterministic** entry points. This keeps all
  randomness caller-sourced and is equivalent to the randomized API.

```rust
fn generate<R: rand::CryptoRng + ?Sized>(csprng: &mut R) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
    let mut seed = [0u8; 32];
    csprng.fill_bytes(&mut seed);
    let (ek, dk) = Hqc::generate_key_deterministic(&seed);
    (KeyMaterial::new(ek.as_ref().into()), KeyMaterial::new(dk.as_ref().into()))
}
```

- `encapsulate` (lines 51–68): rebuilds the `EncapsulationKey` from the stored public-key bytes via
  `TryFrom`, draws `message`/`salt` from the caller RNG, calls `encapsulate_deterministic`.
- `decapsulate` (lines 70–82): rebuilds `DecapsulationKey` + `Ciphertext` from bytes, then
  `dk.decapsulate(&ct)` (infallible — HQC uses the Fujisaki–Okamoto transform with implicit
  rejection).

Reference: [rust/protocol/src/kem/hqc256.rs](rust/protocol/src/kem/hqc256.rs).

### 4.2 `rust/protocol/src/kem.rs` — wire `KeyType::HQC256` into the KEM layer

- Module declaration (feature-gated): `#[cfg(feature = "hqc256")] mod hqc256;`.
- New enum variant `KeyType::HQC256` (lines 214–216).
- Wire **type tag `0x0B`** in `value()` (lines 227–228) — distinct from Kyber768 `0x07`, Kyber1024
  `0x08`, ML-KEM-1024 `0x0A`.
- Dispatch arm in `parameters()` (lines 242–243): `KeyType::HQC256 => &hqc256::Parameters`.
- `TryFrom<u8>` arm (lines 258–259): `0x0B => Ok(KeyType::HQC256)`.
- Module doc updated to mention HQC-256.
- **Unit tests** added: `test_hqc256_keypair` (size + encapsulate/decapsulate round-trip) and
  `test_hqc256_rejects_wrong_ciphertext_type` (a Kyber ciphertext is rejected by an HQC key).

Reference: [rust/protocol/src/kem.rs](rust/protocol/src/kem.rs) (enum 205–217, `value()` 219–230,
`parameters()` 235–246, `TryFrom` 248–263).

### 4.3 `rust/protocol/src/ratchet.rs` — domain-separation labels

The handshake logic is KEM-agnostic, so the only change is the HKDF / transcript domain-separation
strings (lines 22 and 25):

```rust
const PQXDH_LABEL: &[u8] = b"PQXDH_HQC256_MLDSA87_SHA-256";
const PQXDH_TRANSCRIPT_LABEL: &[u8] = b"PQXDH_HQC256_MLDSA87_transcript";
```

(Previously `PQXDH_MLKEM1024_MLDSA87_*`.) Plus the adjacent doc comments. Reference:
[rust/protocol/src/ratchet.rs](rust/protocol/src/ratchet.rs).

### 4.4 Prekey generation repointed to HQC-256

Because the handshake KEM is chosen at *prekey-generation* time, the swap is realised by changing
`kem::KeyPair::generate(KeyType::MLKEM1024, …)` → `KeyType::HQC256` everywhere prekeys are made:

- [rust/protocol/tests/support/mod.rs](rust/protocol/tests/support/mod.rs) — `create_pre_key_bundle`,
  `initialize_pq_sessions`, and `add_kyber_pre_key` (the last was `Kyber1024`).
- [rust/protocol/tests/ratchet.rs](rust/protocol/tests/ratchet.rs) — the three handshake tests.
- [rust/protocol/examples/pqxdh.rs](rust/protocol/examples/pqxdh.rs) — the demo's prekeys and its
  printed sizes/labels.
- [rust/protocol/benches/session.rs](rust/protocol/benches/session.rs) — the signed prekey in the
  session benchmark.

### 4.5 `rust/protocol/benches/kem.rs` — comparison harness

Rewritten to benchmark `generate` / `encapsulate` / `decapsulate` for `[HQC256, MLKEM1024,
Kyber1024]` (all NIST level 5) and to print a size report (pk / sk / ct / ss). This produces the
data behind the "was ML-KEM optimal?" analysis. Reference:
[rust/protocol/benches/kem.rs](rust/protocol/benches/kem.rs).

### 4.6 Cargo configuration

- [rust/protocol/Cargo.toml](rust/protocol/Cargo.toml): added `hqc-kem = { workspace = true,
  optional = true }`; added feature `hqc256 = ["dep:hqc-kem"]`; flipped `default` from `["mlkem1024"]`
  to `["hqc256"]` (ML-KEM kept as a non-default, benchmark-only feature); set the `kem` bench's
  `required-features = ["mlkem1024", "hqc256"]`.
- [Cargo.toml](Cargo.toml) (workspace): the `hqc-kem` dependency (initially a pinned git rev, then
  repointed to the vendored `path = "third-party/hqc-kem"`); added `exclude = ["third-party/hqc-kem"]`
  so the vendored crate builds as a plain dependency, not a workspace member.
- `Cargo.lock`: records `hqc-kem` and its transitive crates (`sha3`, `shake`, `keccak`,
  `sponge-cursor`, `rand 0.10`, …). Note `rand` 0.9 and 0.10 coexist with no conflict.

### 4.7 `POST_QUANTUM_PQXDH.md` — documentation

Branch note declaring the HQC-256 variant; primitives table updated (HQC-256 row + ML-KEM-1024 as
benchmark baseline); labels updated; demo-output block updated to HQC sizes; and a new **§13 ML-KEM
vs HQC comparison** (sizes, measured timings, algorithmic-diversity discussion, the optimality
verdict, and a validation checklist). Reference: [POST_QUANTUM_PQXDH.md](POST_QUANTUM_PQXDH.md).

### 4.8 `third-party/hqc-kem/` — **vendored, patched** dependency

A copy of `hqc-kem` 0.1.0 (RustCrypto/KEMs @ `8f1fd8c`) with a one-line fix (see §5.4). Vendored
because the bug is unfixed upstream and the crate is unreleased. It is `exclude`d from the workspace
and consumed as a path dependency.

---

## 5. Errors encountered & resolutions

### 5.1 `linker 'link.exe' not found`
The machine had no MSVC C/C++ toolchain (empty `…\Microsoft Visual Studio\18`, no `vswhere`). All
Rust linking failed. **Resolution:** install Visual Studio Build Tools (C++ workload). Cargo then
finds the linker via `vswhere`.

### 5.2 `Could not find 'protoc'`
`prost-build` (in `rust/protocol/build.rs`) requires the `protoc` binary. **Resolution:** install
protoc 35.1; point Cargo at it via `~/.cargo/config.toml` `[env] PROTOC = …`.

### 5.3 Unused-import warning in `hqc256.rs`
First compile produced `warning: unused import: rand::RngCore`. The `fill_bytes` calls resolve via
the `CryptoRng` supertrait, so the explicit import was redundant. **Resolution:** removed
`use rand::RngCore as _;`.

### 5.4 **Upstream `hqc-kem` deserialization bug (the blocker)**
`test_hqc256_keypair` failed at encapsulation: `BadKEMKeyLength(HQC256, 7237)`. Root cause: the
`from_bytes!` macro in `hqc-kem`'s `types.rs` had an **inverted length check** — it errored when the
length was *correct* and accepted when *wrong*. This breaks reconstructing an `EncapsulationKey`,
`Ciphertext`, or `SharedSecret` from bytes (which the wrapper must do, since libsignal stores keys
as raw bytes). The bug is present in the latest upstream commit (the file has only ever had one
commit) and breaks the crate's own documented round-trip.

**Resolution:** vendor the crate and fix the one character (`third-party/hqc-kem/src/types.rs`):

```rust
// before (upstream):
if bytes.len() == $bytes { return Err(...); }
// after (PQS-V7 fix):
if bytes.len() != $bytes { return Err(...); }
```

Then repoint the dependency to the vendored path. (`DecapsulationKey` had a separate, correct
hand-written `TryFrom`, which is why the secret-key path and the wrong-type test were unaffected.)

> **Finding for the dissertation:** the pure-Rust HQC ecosystem is immature — an unreleased v0.1.0
> with a basic round-trip bug — whereas ML-KEM has mature, formally-verified implementations
> (libcrux). This bears directly on the "was ML-KEM the pragmatic choice?" question.

### 5.5 `protoc` error recurring in new terminals
After installing protoc and setting a User-scope `PROTOC`, new Cursor terminals still failed.
**Cause:** Cursor was already running, so its spawned terminals inherited Cursor's pre-existing
environment (no `PROTOC`). **Resolution:** the `~/.cargo/config.toml` `[env]` approach (§3.3), which
Cargo reads directly and is independent of the shell environment.

### 5.6 Process notes (Windows/iCloud)
- PowerShell line continuation is a backtick (`` ` ``), not bash's `\` — a multi-line `git add`
  failed on a literal `\`; `git add` is atomic so nothing was staged.
- `Get-ChildItem` rendered some `.cargo` / iCloud paths as empty even when files existed;
  `robocopy` was used to reliably vendor the crate.

---

## 6. Validation results

### 6.1 Tests — `cargo test -p libsignal-protocol` (all green)
| Suite | Result |
| --- | --- |
| lib unit tests | 45 passed (incl. `test_hqc256_keypair`, `test_hqc256_rejects_wrong_ciphertext_type`) |
| `tests/ratchet.rs` | 3 passed (Alice/Bob agree over HQC-256; bad transcript signature rejected) |
| `tests/session.rs` | 10 passed (full PQ handshake; `test_bad_signed_pre_key_signature`, `test_bad_kyber_pre_key_signature`) |
| `tests/groups.rs` | 8 passed (1 ignored) |
| doctests | 2 passed (1 ignored) |

### 6.2 Demo — `cargo run -p libsignal-protocol --example pqxdh`
Agreement succeeds over HQC-256 with no X25519 in the secret; both tamper-rejection checks fire.

### 6.3 Sizes (bytes; size report from the benchmark)
| Quantity | ML-KEM-1024 | HQC-256 | HQC ÷ ML-KEM |
| --- | --- | --- | --- |
| Public key | 1568 | 7237 | ≈ 4.6× |
| Secret key | 3168 | 7333 | ≈ 2.3× |
| Ciphertext | 1568 | 14421 | ≈ 9.2× |
| Shared secret | 32 | 32 | 1× |

### 6.4 Speed (`cargo bench … --bench kem`, criterion medians)
| Operation | ML-KEM-1024 | HQC-256 | HQC ÷ ML-KEM |
| --- | --- | --- | --- |
| `generate` | ~15.1 µs | ~692 µs | ~46× |
| `encapsulate` | ~12.2 µs | ~1.38 ms | ~114× |
| `decapsulate` | ~24.9 µs | ~3.53 ms | ~142× |

(`Kyber1024` tracks ML-KEM-1024 closely — ~15.0 / 15.1 / 33.1 µs — confirming the lattice baseline.)

**Conclusion:** HQC-256 is ~2 orders of magnitude slower and ~5–9× larger than ML-KEM-1024 at level
5. For a bandwidth/latency-sensitive messenger, ML-KEM is the decisively more efficient choice; HQC's
merit is algorithmic diversity (code-based vs lattice), not performance.

---

## 7. Build & run

```powershell
# Prerequisites: MSVC C++ Build Tools, protoc (PROTOC via ~/.cargo/config.toml)
cargo build -p libsignal-protocol
cargo test  -p libsignal-protocol
cargo run   -p libsignal-protocol --example pqxdh
cargo bench -p libsignal-protocol --features "hqc256 mlkem1024" --bench kem
```
