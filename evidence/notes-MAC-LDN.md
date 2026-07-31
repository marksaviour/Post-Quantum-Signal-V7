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
