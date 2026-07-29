<!--
Copyright 2026 Mark Saviour Farrugia.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Decapsulation fixture defect and fix

Machine: `PC-LDN`. Harness file: `rust/protocol/benches/kem.rs`. No protocol
source was touched.

## The defect

The decapsulation benchmark cycled a lazy iterator chain:

```rust
let mut ct_sk_pairs = key_pairs.iter().map(move |kp| { /* encapsulate */ }).cycle();
b.iter(|| { let (ct, sk) = ct_sk_pairs.next().unwrap(); /* decapsulate */ });
```

`Iterator::map` is lazy and `cycle` restarts the underlying iterator, so the
closure body, including the encapsulation, ran on every `next()` inside the
timed region. Every published decapsulation figure was therefore an
encapsulation plus a decapsulation. The failure was silent: the numbers looked
plausible.

## The fix

The pairs are collected into a `Vec` before cycling, so `next()` only hands out
a reference to an already-built pair. The `generate` and `encapsulate` cases were
already correctly materialised and were left untouched.

## Effect, measured

Both runs used `cargo bench -p libsignal-protocol --features "hqc256 mlkem1024"
--bench kem -- HQC256_decapsulate` at Criterion 0.5.1 defaults.

| | Median | 95% bootstrap CI | Outliers among 100 measurements |
| --- | --- | --- | --- |
| Before the fix | 4.3982 ms | [4.3661 ms, 4.4330 ms] | 5 (5.00%) high mild |
| After the fix | 2.5635 ms | [2.5513 ms, 2.5807 ms] | 6 (6.00%) high mild, 2 (2.00%) high severe |

Criterion's own change detection reported `[-42.251% -41.715% -41.135%]`
(p = 0.00 < 0.05), classified as "Performance has improved."

The 1.83 ms removed is the cost of one HQC-256 encapsulation, which is the
quantity that should never have been inside the timed region. The fix took
effect.

## Consequence for earlier results

Any HQC-256 decapsulation figure recorded before this fix, including the
approximately 3.53 ms median in the `v2.0.0` release notes and the derived
"142x slower than ML-KEM" ratio, overstates decapsulation cost and must not be
carried into Chapter 5. ML-KEM-1024 and Kyber1024 decapsulation figures are
affected by the same defect in proportion to their own encapsulation cost.
