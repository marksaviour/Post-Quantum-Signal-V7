Two prior full executions of the five blocks on this machine were discarded.
The first: accumulating untracked measurement outputs flagged the harness commit
dirty mid-campaign; a local git exclude of /evidence/ was added mid-run and the
affected cells were re-executed outside their scheduled rotation positions. It
served as the macOS shakedown. The second: the pre-run wipe deleted the tracked
placeholder evidence/criterion/.gitkeep, so every v2 invocation recorded a
pending deletion and a dirty tree; all 150 cells completed with exit code 0, but
the provenance stamp failed. The placeholder was restored and the wipe procedure
now preserves tracked placeholders. The recorded campaign below is a single
uninterrupted pass with a clean tree from the first invocation, under the
conditions stated in manifests/MAC-LDN.md.

The repository resides under an iCloud-synced Desktop. Around the recorded
campaign, sync resurrected outputs of the discarded second execution: a
duplicate run log and thirteen block-1 logs under macOS conflict names, and
prior cell data that Criterion stored as its comparison baseline in base/
subtrees, recording the campaign itself under new/. Only new/ data is
evidence; the resurrected residue was purged from this archive. A block-level
consistency check across all thirty cells showed block 1 within 1.7 percent of
blocks 2 to 5 with the sign pattern of thermal warm-up, not contention. Future
campaigns run outside cloud-synced folders or with sync paused.
