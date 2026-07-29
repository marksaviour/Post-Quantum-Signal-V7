<!--
Copyright 2026 Mark Saviour Farrugia.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Five-block run schedule and rotation order

Written before any timing run, as Chapter 4.3 requires. Chapter 4.3 calls for five
independent Criterion invocations per cell per machine, organised into five
complete blocks, where each block contains every applicable artefact,
configuration, and benchmark case exactly once, and the case order is cyclically
rotated between blocks.

## Why one invocation per case

Criterion executes the cases within a target in registration order. That order
cannot be rotated between blocks without editing the harness, and editing the
harness between blocks would change the harness commit, which Chapter 4's
admissibility rule forbids. Rotating case order therefore requires one Criterion
invocation per case, selected with a Criterion name filter:

```
cargo bench -p libsignal-protocol <features> --bench <target> -- "<exact case name>"
```

A filtered invocation still runs the fixture setup for every registered group
function in that target. Setup is outside every timed region, so this affects
wall-clock cost only, not the measurements.

## Cells

Twenty-three cells per machine. Primitive cells are properties of the algorithms
rather than of an artefact, so they are measured once per machine from the `v2`
tree with both KEM features enabled, which is the only configuration that builds
all three KEMs together.

### Primitives, `v2` tree, features `hqc256 mlkem1024`

| Id | Target | Case |
| --- | --- | --- |
| P01 | `kem` | `HQC256_generate` |
| P02 | `kem` | `HQC256_encapsulate` |
| P03 | `kem` | `HQC256_decapsulate` |
| P04 | `kem` | `MLKEM1024_generate` |
| P05 | `kem` | `MLKEM1024_encapsulate` |
| P06 | `kem` | `MLKEM1024_decapsulate` |
| P07 | `kem` | `Kyber1024_generate` |
| P08 | `kem` | `Kyber1024_encapsulate` |
| P09 | `kem` | `Kyber1024_decapsulate` |
| P10 | `mldsa` | `MLDSA87_generate` |
| P11 | `mldsa` | `MLDSA87_sign` |
| P12 | `mldsa` | `MLDSA87_verify` |

### Handshake, `v2` tree (HQC-256 default), target `session`

| Id | Case |
| --- | --- |
| H2a | `initiate session and encrypt first message` |
| H2b | `initiate session and encrypt first message, last-resort only` |
| H2c | `session decrypt first message, full mode` |
| H2d | `session decrypt first message, last-resort only` |

### Handshake, `v1` tree (ML-KEM-1024 default), target `session`

Case names are identical to the `v2` tree so Chapter 5 compares like with like.

| Id | Case |
| --- | --- |
| H1a | `initiate session and encrypt first message` |
| H1b | `initiate session and encrypt first message, last-resort only` |
| H1c | `session decrypt first message, full mode` |
| H1d | `session decrypt first message, last-resort only` |

### Baseline, `baseline-bench-1.0`, target `baseline_pqxdh`

The baseline's two configurations are **not** semantically equivalent to the
variants' two KEM modes. The baseline varies the presence of an optional one-time
X25519 curve prekey; the variants vary the presence of an optional one-time KEM
prekey. They are named so as not to imply otherwise.

| Id | Case |
| --- | --- |
| B1 | `baseline initiate session and encrypt first message` |
| B2 | `baseline initiate session and encrypt first message, no one-time curve key` |
| B3 | `baseline decrypt first message` |

## Canonical order

```
P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12 H2a H2b H2c H2d H1a H1b H1c H1d B1 B2 B3
```

## Rotation rule

Block `b` for `b` in 1..5 is the canonical order rotated left by `5 * (b - 1)`
positions, wrapping at 23. Every block therefore contains all 23 cells exactly
once, and each cell occupies five well-separated positions across the campaign,
so no cell is systematically measured first or last.

### Block 1, rotate left 0

```
P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12 H2a H2b H2c H2d H1a H1b H1c H1d B1 B2 B3
```

### Block 2, rotate left 5

```
P06 P07 P08 P09 P10 P11 P12 H2a H2b H2c H2d H1a H1b H1c H1d B1 B2 B3 P01 P02 P03 P04 P05
```

### Block 3, rotate left 10

```
P11 P12 H2a H2b H2c H2d H1a H1b H1c H1d B1 B2 B3 P01 P02 P03 P04 P05 P06 P07 P08 P09 P10
```

### Block 4, rotate left 15

```
H2d H1a H1b H1c H1d B1 B2 B3 P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12 H2a H2b H2c
```

### Block 5, rotate left 20

```
B2 B3 P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12 H2a H2b H2c H2d H1a H1b H1c H1d B1
```

## What is recorded per invocation

For every invocation: the exact command, the full harness commit hash, the
feature set, the block number, the position within the block, and the machine
identifier. Each Criterion output directory is copied into
`evidence/criterion/` under a name encoding those fields.

## Machines

Runs are repeated independently on each machine. Figures are never averaged or
compared across machines, per Chapter 4.

| Machine | Manifest | Status |
| --- | --- | --- |
| `PC-LDN` | `evidence/manifests/PC-LDN.md` | Validation block executed; five-block campaign outstanding |
| second machine | not yet recorded | Outstanding |

## Sizes

`examples/sizes.rs` is deterministic and is run once per artefact, not five
times, and not as part of these blocks. Its stdout is captured to
`evidence/sizes/`.
