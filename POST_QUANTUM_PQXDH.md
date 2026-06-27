# Fully Post-Quantum PQXDH for libsignal

This document describes the conversion of Signal's **PQXDH** key agreement (as implemented in this
fork of `libsignal`) from a *hybrid* construction (classical X25519 **plus** a post-quantum KEM)
into a **fully post-quantum handshake**: the X25519 Diffie–Hellman terms are removed from the key
agreement entirely, confidentiality comes from **ML-KEM-1024** encapsulations, and authentication
comes from **ML-DSA-87** signatures.

It covers: the design, a word-based explanation, pseudocode, every file added/changed, the testing
strategy and test inventory, and how to run the system.

---

## 1. TL;DR

| Aspect | Before (hybrid PQXDH) | After (fully PQ PQXDH) |
| --- | --- | --- |
| Identity key | Curve25519 (X25519 agreement **and** XEdDSA signatures) | **ML-DSA-87** (signatures only, no agreement) |
| Confidentiality | 3–4 × X25519 DH **+** optional Kyber/ML-KEM | **ML-KEM-1024** signed prekey **+** optional one-time ML-KEM-1024 prekey |
| Authentication of Bob | Identity signs the EC + Kyber prekeys (XEdDSA) | Identity signs all prekeys (**ML-DSA-87**) |
| Authentication of Alice | Implicit (her identity is a DH input) | **Explicit ML-DSA-87 signature over the handshake transcript** |
| KDF label | `WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024` | `PQXDH_MLKEM1024_MLDSA87_SHA-256` |
| Secret input | `0xFF*32 ‖ DH ‖ DH ‖ DH ‖ [DH] ‖ [KEM]` | `0xFF*32 ‖ ss1 ‖ [ss2]` |
| X25519 still present? | Everywhere | **Only** as the Double Ratchet `ratchet_key` (out of scope) |

The handshake is now fully post-quantum. The **Double Ratchet** that runs *after* the handshake
still uses X25519 for its DH step (this was an explicit scoping decision — see
[9 Scope & caveats](#9-scope--caveats)).

---

## 2. Cryptographic primitives

| Primitive | Role | Library | Type tag | Sizes (bytes) |
| --- | --- | --- | --- | --- |
| **ML-DSA-87** (FIPS 204) | Identity / signatures | `libcrux-ml-dsa` 0.0.8 | `0x09` | pk 2592, sk 4896, sig 4627 |
| **ML-KEM-1024** (FIPS 203) | KEM prekeys | `libcrux-ml-kem` 0.0.2 | `0x0A` | pk 1568, ct 1568, ss 32 |
| X25519 | Double Ratchet `ratchet_key` only | `curve25519-dalek` | `0x05` | pk 32 |
| HKDF-SHA-256 | Root/chain key derivation | `hkdf` / `sha2` | — | 64-byte output |

ML-DSA-87 is paired with ML-KEM-1024 so that signatures and KEM both sit at **NIST security
level 5**.

---

## 3. How the new system works (word-based)

### 3.1 Identity keys
A user's long-term identity is now an **ML-DSA-87 signing keypair**. It is used *only* to produce
and verify signatures. It can no longer perform Diffie–Hellman, which is the whole point: a
quantum adversary that records traffic today cannot recover the session key later, because there is
no Diffie–Hellman value to break.

### 3.2 Bob's published bundle
Bob publishes a prekey bundle containing:
1. A **signed X25519 ratchet key** (formerly the "EC signed prekey"). This contributes **nothing**
   to the shared secret; it exists solely so the Double Ratchet has a DH key to start from.
2. A **signed (last-resort) ML-KEM-1024 prekey**.
3. An optional **one-time ML-KEM-1024 prekey**.

Every item is signed by Bob's **ML-DSA-87** identity key. This is how Bob is authenticated.

### 3.3 Alice's handshake
1. Alice fetches Bob's bundle and **verifies all the ML-DSA signatures** with Bob's identity key.
   If any fails she aborts.
2. Alice **encapsulates** to Bob's signed ML-KEM prekey, producing `(ss1, ct1)`, and — if present —
   to Bob's one-time ML-KEM prekey, producing `(ss2, ct2)`.
3. She builds the secret input `0xFF*32 ‖ ss1 ‖ ss2` and runs it through HKDF-SHA-256 with the new
   label to obtain the root key and the first chain key.
4. She **signs the handshake transcript** with her ML-DSA identity. The transcript binds both
   identities, both ciphertexts, Bob's ratchet key and her base key. This signature is the
   **Alice→Bob authenticator** and is carried in the `PreKeySignalMessage`.
5. She bootstraps the Double Ratchet (the only remaining X25519 step) and sends her first message.

### 3.4 Bob's handshake
1. Bob **decapsulates** `ct1` (and `ct2` if present) with his KEM secret keys, recovering the same
   `ss1`/`ss2`.
2. He derives the identical root/chain keys via the same HKDF.
3. He **verifies Alice's ML-DSA transcript signature** with her identity key. On failure he rejects
   with `SignatureValidationFailed`.
4. He completes the session and can decrypt Alice's message and reply.

Because both sides derive the key material purely from the KEM shared secrets, confidentiality and
forward secrecy (from the one-time KEM prekey) are post-quantum. Both parties are explicitly
authenticated: **Bob** via his signed prekeys, **Alice** via her signed transcript.

---

## 4. How the new system works (pseudocode)

### 4.1 Bob's bundle (server-published)

```text
bundle = {
    identity_key            : MLDSA87.PublicKey            # Bob's identity (verification key)
    signed_ratchet_key      : X25519.PublicKey             # Double Ratchet DH key (NOT in secret)
    signed_ratchet_key_sig  : MLDSA87.sign(bob_IK_sk, signed_ratchet_key)
    signed_kem_prekey       : MLKEM1024.PublicKey          # last-resort KEM prekey
    signed_kem_prekey_sig   : MLDSA87.sign(bob_IK_sk, signed_kem_prekey)
    one_time_kem_prekey?    : MLKEM1024.PublicKey          # optional one-time KEM prekey
    one_time_kem_prekey_sig?: MLDSA87.sign(bob_IK_sk, one_time_kem_prekey)
}
```

### 4.2 Shared transcript (signed by Alice, verified by Bob)

```text
LABEL = "PQXDH_MLKEM1024_MLDSA87_transcript"

transcript(alice_IK, ct1, ct2, bob_IK, bob_ratchet_key, alice_base_key):
    # every component is length-prefixed (u32 big-endian) to remove concatenation ambiguity
    return  lp(LABEL)
         ‖ lp(alice_IK.serialize())
         ‖ lp(ct1)
         ‖ lp(ct2)                  # empty byte-string if no one-time prekey
         ‖ lp(bob_IK.serialize())
         ‖ lp(bob_ratchet_key.serialize())
         ‖ lp(alice_base_key.serialize())
```

### 4.3 Alice (initiator)

```text
initialize_alice(bundle):
    # (0) Authenticate Bob's bundle
    require MLDSA87.verify(bundle.identity_key, bundle.signed_ratchet_key,  bundle.signed_ratchet_key_sig)
    require MLDSA87.verify(bundle.identity_key, bundle.signed_kem_prekey,   bundle.signed_kem_prekey_sig)
    if bundle.one_time_kem_prekey:
        require MLDSA87.verify(bundle.identity_key, bundle.one_time_kem_prekey, bundle.one_time_kem_prekey_sig)

    base_key            = X25519.generate()                 # session id + transcript binding
    sending_ratchet_key = X25519.generate()                 # first Double Ratchet key

    # (1) KEM encapsulations -> the ONLY source of the shared secret
    (ss1, ct1) = MLKEM1024.encapsulate(bundle.signed_kem_prekey)
    (ss2, ct2) = bundle.one_time_kem_prekey
                 ? MLKEM1024.encapsulate(bundle.one_time_kem_prekey)
                 : (none, none)

    # (2) Derive root/chain keys  (NO X25519 in this secret)
    secret = 0xFF*32 ‖ ss1 ‖ (ss2 if present)
    (root_key, chain_key) = HKDF_SHA256(salt=∅, ikm=secret,
                                        info="PQXDH_MLKEM1024_MLDSA87_SHA-256", L=64)

    # (3) Alice -> Bob authenticator
    t   = transcript(alice_IK, ct1, ct2 ?? "", bundle.identity_key,
                     bundle.signed_ratchet_key, base_key)
    sig = MLDSA87.sign(alice_IK_sk, t)

    # (4) Bootstrap the Double Ratchet  (the one remaining X25519 DH)
    (send_root, send_chain) = ratchet_chain(root_key,
                                            dh = X25519(sending_ratchet_key.sk,
                                                        bundle.signed_ratchet_key))
    session.receiver_chain[bundle.signed_ratchet_key] = chain_key
    session.sender_chain[sending_ratchet_key]         = send_chain

    # carried (in PreKeySignalMessage) until Bob acknowledges:
    session.pending = { ct1, ct2, identity_signature = sig,
                        base_key, signed_pre_key_id, kem_pre_key_id, one_time_kem_pre_key_id }
    return session
```

### 4.4 Bob (responder)

```text
initialize_bob(message, my_prekeys):
    # (1) Recover the same shared secrets
    ss1 = MLKEM1024.decapsulate(my_prekeys.signed_kem_sk, message.ct1)
    ss2 = message.ct2 ? MLKEM1024.decapsulate(my_prekeys.one_time_kem_sk, message.ct2) : none

    # (2) Derive identical root/chain keys
    secret = 0xFF*32 ‖ ss1 ‖ (ss2 if present)
    (root_key, chain_key) = HKDF_SHA256(salt=∅, ikm=secret,
                                        info="PQXDH_MLKEM1024_MLDSA87_SHA-256", L=64)

    # (3) Verify Alice's authenticator  -> reject on failure
    t = transcript(message.identity_key, message.ct1, message.ct2 ?? "",
                   my_IK, my_prekeys.signed_ratchet_key, message.base_key)
    if not MLDSA87.verify(message.identity_key, t, message.identity_signature):
        return Error(SignatureValidationFailed)

    # (4) Establish session; receiver chain is created when Alice's first ratchet message arrives
    session.sender_chain[my_prekeys.signed_ratchet_key] = chain_key
    return session
```

---

## 5. Before vs after (the secret input)

```text
# BEFORE — hybrid PQXDH (X3DH + KEM)
secret = 0xFF*32
       ‖ DH(IK_A,  SPK_B)        # X25519
       ‖ DH(EK_A,  IK_B)         # X25519
       ‖ DH(EK_A,  SPK_B)        # X25519
       ‖ [ DH(EK_A, OPK_B) ]     # X25519, optional EC one-time prekey
       ‖ [ KEM_ss ]              # optional single Kyber/ML-KEM prekey
KDF   = HKDF-SHA256("WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024")

# AFTER — fully post-quantum PQXDH
secret = 0xFF*32 ‖ ss1 ‖ [ ss2 ]      # ss1 = signed ML-KEM prekey, ss2 = one-time ML-KEM prekey
KDF   = HKDF-SHA256("PQXDH_MLKEM1024_MLDSA87_SHA-256")
```

There is **no X25519 Diffie–Hellman in the shared secret** anymore.

---

## 6. Files added

| File | Purpose |
| --- | --- |
| `rust/protocol/src/dsa.rs` | New ML-DSA-87 wrapper module (`PublicKey`, `SecretKey`, `KeyPair`, `sign`/`verify`, length-prefixed serialization). Mirrors the style of `kem.rs`. |
| `rust/protocol/examples/pqxdh.rs` | Runnable end-to-end demonstration of the fully-PQ handshake (sizes, agreement, tamper rejection). |
| `POST_QUANTUM_PQXDH.md` | This document. |

## 7. Files changed

| File | Change |
| --- | --- |
| `Cargo.toml` (workspace) | Added `libcrux-ml-dsa = "0.0.8"`. |
| `rust/protocol/Cargo.toml` | Added the `libcrux-ml-dsa` dependency; made `mlkem1024` a **default** feature; added an off-by-default `sealed_sender` feature; bench targets gated accordingly. |
| `rust/protocol/src/lib.rs` | Added `pub mod dsa;`; gated `sealed_sender` behind the new feature. |
| `rust/protocol/src/identity_key.rs` | `IdentityKey` / `IdentityKeyPair` rebuilt on `dsa` (ML-DSA-87). Identity now signs/verifies (no agreement). |
| `rust/protocol/src/ratchet.rs` | Rewrote the handshake: KEM-only `secret_input`, new HKDF label, transcript builder, ML-DSA sign (Alice) / verify (Bob). |
| `rust/protocol/src/ratchet/params.rs` | `AliceSignalProtocolParameters` / `BobSignalProtocolParameters` now carry ML-DSA identities, ML-KEM prekeys (signed + one-time), the X25519 ratchet key, the ciphertexts and the transcript signature. |
| `rust/protocol/src/session.rs` | `process_prekey_bundle` (Alice) verifies ML-DSA prekey signatures and builds the KEM params; `process_prekey` (Bob) supplies the ciphertexts + signature and consumes the one-time KEM prekey. |
| `rust/protocol/src/session_cipher.rs` | Threads the one-time KEM ciphertext + transcript signature into `PreKeySignalMessage`; identity logging uses `serialize()`. |
| `rust/protocol/src/protocol.rs` | `PreKeySignalMessage` gains `pq_one_time_*` and `identity_signature`; constructor/parser updated. |
| `rust/protocol/src/proto/wire.proto` | New `PreKeySignalMessage` fields: `pq_one_time_pre_key_id (9)`, `pq_one_time_ciphertext (10)`, `identity_signature (11)`. |
| `rust/protocol/src/proto/storage.proto` | `PendingKyberPreKey` gains `pq_one_time_pre_key_id (3)`, `pq_one_time_ciphertext (4)`, `identity_signature (5)`. |
| `rust/protocol/src/state/bundle.rs` | `PreKeyBundle` reshaped: signed X25519 ratchet key + **mandatory** signed ML-KEM prekey + optional one-time ML-KEM prekey; EC one-time prekey removed. |
| `rust/protocol/src/state/session.rs` | Pending session stores ct2 + signature; new setters/accessors (`get_pq_one_time_ciphertext`, `get_identity_signature`, …). |
| `rust/protocol/src/crypto.rs` | `#![allow(dead_code)]` for AES-CTR/HMAC helpers now used only by the gated Sealed Sender. |
| `rust/protocol/src/fingerprint.rs` | Curve25519 known-answer fingerprint vectors replaced by behavioural tests over generated ML-DSA identities. |
| `rust/protocol/tests/support/mod.rs` | Test helpers (`create_pre_key_bundle`, `initialize_sessions_v3/v4`, `make_bundle_with_latest_keys`) ported to the PQ API. |
| `rust/protocol/tests/ratchet.rs` | Replaced X3DH known-answer tests with PQ handshake tests. |
| `rust/protocol/tests/session.rs` | Rewritten as a PQ integration suite (handshake + Double Ratchet scenarios). |
| `rust/protocol/tests/groups.rs` | Sealed-sender group tests gated behind the `sealed_sender` feature. |
| `rust/protocol/tests/sealed_sender.rs` | Whole file gated behind the `sealed_sender` feature. |
| `rust/protocol/benches/session.rs` | Inline bundle construction updated to the PQ `PreKeyBundle::new` signature. |

---

## 8. Wire & storage format changes

### `PreKeySignalMessage` (wire.proto)
```protobuf
message PreKeySignalMessage {
  optional uint32 registration_id   = 5;
  optional uint32 pre_key_id        = 1;   // (legacy EC one-time prekey; now unused)
  optional uint32 signed_pre_key_id = 6;   // -> Bob's signed X25519 ratchet key
  optional uint32 kyber_pre_key_id  = 7;   // -> Bob's signed ML-KEM-1024 prekey  (ct1)
  optional bytes  kyber_ciphertext  = 8;   //    ct1
  optional bytes  base_key          = 2;   // Alice's X25519 base key (session id)
  optional bytes  identity_key      = 3;   // Alice's ML-DSA-87 identity (verification key)
  optional bytes  message           = 4;   // inner SignalMessage
  // --- fully post-quantum additions ---
  optional uint32 pq_one_time_pre_key_id = 9;    // -> Bob's one-time ML-KEM-1024 prekey  (ct2)
  optional bytes  pq_one_time_ciphertext = 10;   //    ct2
  optional bytes  identity_signature     = 11;   // Alice's ML-DSA-87 transcript authenticator
}
```

### `PendingKyberPreKey` (storage.proto)
Stores Alice's not-yet-acknowledged handshake outputs so the same authenticator/ciphertexts are
re-sent on every `PreKeySignalMessage` until Bob replies:
```protobuf
message PendingKyberPreKey {
  uint32 pre_key_id                  = 1;   // signed ML-KEM prekey id
  bytes  ciphertext                  = 2;   // ct1
  optional uint32 pq_one_time_pre_key_id = 3;
  bytes  pq_one_time_ciphertext      = 4;   // ct2
  bytes  identity_signature          = 5;   // transcript authenticator
}
```

---

## 9. Scope & caveats

- **The Double Ratchet remains X25519.** The handshake is fully post-quantum, but the ongoing
  session's DH ratchet (`ratchet_key`) still uses X25519. So this delivers a **fully-PQ
  *handshake*, not a fully-PQ *session***. Making the ratchet post-quantum (cf. Signal's "Triple
  Ratchet"/SPQR work) is a separate, larger effort.
- **Sealed Sender is disabled.** It performs Diffie–Hellman against the identity key, which an
  ML-DSA (signing-only) identity cannot do. It is gated behind an off-by-default `sealed_sender`
  feature and is out of scope; it would need its own KEM-based redesign.
- **Language bindings are out of scope.** The change is confined to the Rust `libsignal-protocol`
  crate. The Java/Swift/Node bridges still assume a 32-byte Curve25519 identity and are **not**
  updated, so the *workspace* build will not compile — always scope commands with
  `-p libsignal-protocol`.
- **Wire/format compatibility is intentionally broken.** This is a research artefact; it does not
  interoperate with stock Signal clients.

---

## 10. Security properties

- **PQ confidentiality:** the session key derives only from ML-KEM-1024 shared secrets; a
  harvest-now-decrypt-later quantum adversary gains nothing from recorded transcripts.
- **PQ forward secrecy:** the optional one-time ML-KEM prekey (`ss2`) provides forward secrecy for
  the initial message; once Bob deletes it, that message cannot be recovered.
- **PQ authentication (both directions):** Bob is authenticated by ML-DSA signatures over his
  prekeys; Alice is authenticated by an ML-DSA signature over the full handshake transcript.
- **Transcript binding:** the authenticator covers both identities, both KEM ciphertexts, Bob's
  ratchet key and Alice's base key (each length-prefixed), preventing mix-and-match / unknown
  key-share style manipulation. Tampering with any bound field causes Bob to reject with
  `SignatureValidationFailed`.
- **Domain separation:** all ML-DSA operations use the context string `Signal_PQXDH_MLDSA87`, and
  the transcript is prefixed with `PQXDH_MLKEM1024_MLDSA87_transcript`.

---

## 11. Testing

All tests are in the `libsignal-protocol` crate and pass with no warnings.

```bash
# Run the whole suite (lib unit tests + integration tests + doctests)
cargo test -p libsignal-protocol
```

Latest result:

```
lib       : 45 passed; 0 failed; 0 ignored
groups    :  8 passed; 0 failed; 1 ignored
ratchet   :  3 passed; 0 failed; 0 ignored
session   : 10 passed; 0 failed; 0 ignored
doctests  :  2 passed; 0 failed; 1 ignored
```

### 11.1 Test inventory (PQ-relevant)

**`src/dsa.rs`** (unit)
- `sign_and_verify_round_trip` — ML-DSA sign/verify; tampered message and wrong key both rejected.
- `serialize_round_trip` — key serialization round-trips and reconstructed keys still verify.

**`src/identity_key.rs`** (unit)
- `test_identity_key_from`, `test_serialize_identity_key_pair` — ML-DSA identity (de)serialization.
- `test_alternate_identity_signing` — PNI-style alternate-identity ML-DSA signatures.

**`tests/ratchet.rs`** (handshake)
- `test_alice_and_bob_agree_with_one_time_kem_prekey` — both sides derive identical chain keys
  using `ss1 + ss2`.
- `test_alice_and_bob_agree_without_one_time_kem_prekey` — agreement with `ss1` only.
- `test_bob_rejects_bad_transcript_signature` — a corrupted authenticator is rejected with
  `SignatureValidationFailed`.

**`tests/session.rs`** (end-to-end)
- `test_full_pq_prekey_handshake` — bundle → `PreKeySignalMessage` → reply → many ordered &
  out-of-order ratchet messages.
- `test_prekey_handshake_without_one_time_kem` — handshake succeeds with only the signed KEM prekey.
- `test_bad_signed_pre_key_signature` — bad ML-DSA signature on the X25519 ratchet key is rejected.
- `test_bad_kyber_pre_key_signature` — bad ML-DSA signature on the ML-KEM prekey is rejected.
- `test_repeat_bundle_message` — multiple `PreKeySignalMessage`s decrypt; processing is idempotent.
- `test_basic_simultaneous_initiate` — both parties initiate at once and converge on one session.
- `prekey_message_failed_decryption_does_not_update_stores` — a tampered inner ciphertext fails to
  decrypt and leaves Bob's stores untouched.
- `test_unacknowledged_sessions_eventually_expire` — stale unacknowledged sessions become unusable.
- `test_basic_session`, `test_message_key_limits` — Double Ratchet exercisers over PQ sessions.

### 11.2 Useful commands

```bash
cargo test -p libsignal-protocol -- --list                 # list every test
cargo test -p libsignal-protocol --test ratchet            # PQXDH handshake tests only
cargo test -p libsignal-protocol --test session            # end-to-end session tests only
cargo test -p libsignal-protocol --lib dsa                 # ML-DSA wrapper unit tests
cargo test -p libsignal-protocol --test ratchet \
    test_bob_rejects_bad_transcript_signature -- --nocapture
```

---

## 12. The runnable demo

```bash
cargo run -p libsignal-protocol --example pqxdh
```

Expected output:

```text
=== Fully post-quantum PQXDH  (ML-KEM-1024 + ML-DSA-87) ===

Primitive sizes (bytes, excluding 1-byte type tags):
  ML-DSA-87 identity public key : 2592
  ML-DSA-87 identity secret key : 4896
  ML-DSA-87 signature           : 4627
  ML-KEM-1024 public key        : 1568

[1] Bob signs his ML-KEM prekey with ML-DSA; Alice verifies it: OK
[2] Alice encapsulates to Bob's signed + one-time ML-KEM prekeys -> ct1 (1569 B), ct2 (1569 B)
[3] Alice signs the handshake transcript with ML-DSA -> authenticator (4627 B)
[4] Bob decapsulates and verifies Alice's transcript signature: OK

>>> Agreement succeeded with NO X25519 in the secret (secret = 0xFF*32 || ss1 || ss2).
    shared chain key = <hex>

[neg] Tampered transcript signature correctly REJECTED.
[neg] Tampered ML-KEM prekey signature correctly REJECTED: yes

All checks passed.
```

(The 1569-byte ciphertexts are the 1568-byte ML-KEM-1024 ciphertext plus a 1-byte type tag.)

---
