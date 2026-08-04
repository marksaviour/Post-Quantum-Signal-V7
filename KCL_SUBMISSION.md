# KCL MSc Dissertation Submission — Reader's Guide (baseline branch)

Module: 7CCSMPRJ Individual Project
Author: Mark Saviour Farrugia (K25128781)
Programme: MSc Cybersecurity, King's College London
Supervisor: Dr Benjamin Dowling

This branch is the pinned baseline comparator: an UNMODIFIED checkout of
upstream libsignal v0.73.3, whose operative post-quantum KEM is
round-three Kyber-1024. It contains NO project-authored source. It
exists only to serve as the measurement baseline against which the two
fully post-quantum variants are compared, so there is no file map of
project changes on this branch — there are none.

## Branch map of this repository

- working-v2.x, main-v2 — HQC-256 + ML-DSA-87 variant (Version 2).
- working-v1.x, main-v1 — ML-KEM-1024 + ML-DSA-87 variant (Version 1).
- baseline — this branch, pinned upstream libsignal v0.73.3, unmodified.
- evidence — recorded campaigns and supporting records.

The file-by-file map of the project contribution is in KCL_SUBMISSION.md
on the main-v2 and main-v1 branches. This baseline branch deliberately
carries no PROJECT_RELEASE_NOTES.md because it is unmodified upstream.

## Building and running

Builds as upstream libsignal. The baseline correctness gate used in the
dissertation is:
  cargo test -p libsignal-protocol

## Licence

GNU Affero General Public License version 3. See LICENSE.
