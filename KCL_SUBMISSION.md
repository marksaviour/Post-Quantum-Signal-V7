# KCL MSc Dissertation Submission — Reader's Guide (evidence branch)

Module: 7CCSMPRJ Individual Project
Author: Mark Saviour Farrugia (K25128781)
Programme: MSc Cybersecurity, King's College London
Supervisor: Dr Benjamin Dowling

This branch holds the recorded measurement evidence: the benchmark
campaigns for both machines, the correctness-gate records, the
environment manifests, the serialised-size captures, and the measurement
harness and schedule. It is all under evidence/, and evidence/README.md
is the detailed guide. The buildable source that produced this evidence
lives on the other branches.

## File map of evidence/

- evidence/README.md — the detailed guide to the record.
- evidence/schedule/ — the measurement harness: run-block.ps1 (the block
  runner) and run-schedule.md (the 30-cell rotation specification).
- evidence/criterion/ — the per-machine run logs and raw Criterion
  output, one directory per cell per block, plus the merged run-log.csv.
- evidence/manifests/ — one environment manifest per machine.
- evidence/correctness-gates-*.md — the recorded functional-test gates
  per machine.
- evidence/harness-diffs/ — the recorded diff of the measurement harness
  against the pre-harness baseline.
- evidence/notes-*.md, evidence/VERIFY-*.md, evidence/local-git-exclude-*
  — the per-campaign provenance notes and verification records.

## Branch map of this repository

- working-v2.x, main-v2 — Version 2 source. working-v1.x, main-v1 —
  Version 1 source. baseline — pinned upstream comparator. evidence —
  this branch.

## Licence

GNU Affero General Public License version 3. See LICENSE.
