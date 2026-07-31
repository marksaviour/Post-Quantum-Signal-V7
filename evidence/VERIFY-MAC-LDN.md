# MAC-LDN campaign — verification handoff

Point Claude at this file plus the paths below and ask it to verify the campaign.
All paths are absolute. Recorded 2026-07-31 on MacBook Pro (Apple M1 Pro, 16 GB, macOS 26.5.2).

## A. Artefact trees (source + git provenance)

| Role | Path | Expect branch @ commit | Check |
|---|---|---|---|
| v2 (HQC-256) | `/Users/marksaviour/Desktop/artefact/full-PQ-PQXDH` | `working-v2.x` @ `70e0812` | `git rev-parse HEAD`; `git status --porcelain` empty (source clean) |
| v1 (ML-KEM-1024) | `/Users/marksaviour/Desktop/artefact/pq-v1` | `working-v1.x` @ `11e9fd1` | linked git worktree; `git rev-parse HEAD` |
| baseline (Kyber + classical) | `/Users/marksaviour/Desktop/artefact/pq-baseline` | `baseline` @ `7c20bca` | linked git worktree; `git rev-parse HEAD` |

`git -C <v2> worktree list` should show all three at the paths above (none `prunable`).

## B. Evidence archive (the record of record) — under the v2 tree

Base: `/Users/marksaviour/Desktop/artefact/full-PQ-PQXDH/evidence/`

| Location | Contents | Expected |
|---|---|---|
| `manifests/MAC-LDN.md` | machine + toolchain manifest | 1 file |
| `correctness-gates-MAC-LDN.md` | gate record | baseline 89/0/4, v1 68/0/2, v2 68/0/2, hqc-kem 6 + 1 doc |
| `sizes/` | serialised wire sizes, one per artefact | 3 files (`sizes-{v2-70e0812,v1-11e9fd1,baseline-7c20bca}-MAC-LDN.txt`) |
| `harness-diffs/` | `git diff v0.0.0 v0.1.0` (+ `--stat`) | 2 files (4 files / 783 insertions) |
| `schedule/run-block.ps1` | the measurement harness (drives Criterion) | drives each cell as anchored `^case$` filter |
| `schedule/run-schedule.md` | the 30-cell / 5-block rotation spec | canonical order + rotation rule |
| `criterion/` | raw Criterion output, one dir per cell per block | **150 cell dirs + 150 `.log` + `run-log.csv`** |
| `criterion/run-log.csv` | one row per invocation | **150 rows** |

### run-log.csv acceptance criteria
- **150 rows**; split `v2=85, v1=25, baseline=40`; each block `b1..b5 = 30`.
- `exit_code` = `0` for every row.
- `harness_commit` ∈ {`70e0812…`, `11e9fd1…`, `7c20bca…`} with **no `(working tree dirty)`** on any row.

## C. Correctness gates (re-runnable, ~seconds)
From the v2 tree:
- `(cd ../pq-baseline && cargo test -p libsignal-protocol)` → 89 passed / 0 failed / 4 ignored
- `(cd ../pq-v1 && cargo test -p libsignal-protocol --no-default-features --features mlkem1024)` → 68 / 0 / 2
- `cargo test -p libsignal-protocol --no-default-features --features hqc256` → 68 / 0 / 2
- `cargo test --manifest-path third-party/hqc-kem/Cargo.toml` → 6 passed + 1 doc test

## D. Bench-id integrity (why the anchored filter is safe)
Bench sources under `<tree>/rust/protocol/benches/`: `kem.rs`, `mldsa.rs`, `session.rs` (v2/v1), `classical.rs`, `baseline_pqxdh.rs` (baseline), and example `examples/sizes.rs`.
Every case name is registered via a bare `c.bench_function("<case>", …)` — **no `benchmark_group`** — so the full Criterion id equals the case string and `run-block.ps1`'s `^<case>$` filter matches exactly one benchmark (no silent 0-benchmark runs).

## E. Notes for the verifier
- The per-cell outputs for v1/baseline are ALSO present in their own worktrees
  (`…/pq-v1/evidence/criterion` = 25 cells, `…/pq-baseline/evidence/criterion` = 40 cells);
  those are the originals — the v2 `evidence/criterion/` holds the gathered union of all 150 plus a merged `run-log.csv`.
- Clean-tree setup lives in `/Users/marksaviour/Desktop/artefact/full-PQ-PQXDH/.git/info/exclude`
  (local, untracked): it excludes `/evidence/` so untracked outputs never flag the tree dirty.
  Committing still works because step 8 force-adds (`git add -A -f evidence/`).
- After the push (step 8), the canonical location becomes the **`evidence` branch of
  `github.com/marksaviour/full-PQ-PQXDH`** — verify with `git fetch origin evidence` then inspect that branch.

## F. One-shot local check
```bash
cd /Users/marksaviour/Desktop/artefact/full-PQ-PQXDH
git worktree list
pwsh -NoProfile -Command '
$r = Import-Csv evidence/criterion/run-log.csv
"rows={0}  nonzero_exit={1}  dirty={2}" -f $r.Count, @($r|?{$_.exit_code -ne "0"}).Count, @($r|?{$_.harness_commit -match "dirty"}).Count
"artefacts: " + (($r|Group-Object artefact|%{"$($_.Name)=$($_.Count)"}) -join "  ")
"blocks:    " + (($r|Group-Object block|Sort-Object Name|%{"b$($_.Name)=$($_.Count)"}) -join "  ")'
# expect: rows=150 nonzero_exit=0 dirty=0 ; v2=85 v1=25 baseline=40 ; b1..b5=30
ls evidence/criterion | grep -E '^MAC-LDN_block' | grep -v '\.log$' | wc -l   # expect 150
```
