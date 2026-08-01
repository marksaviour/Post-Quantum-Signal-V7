# Correctness gates, PC-LDN
Date: 2026-08-01
Conditions: mains AC power; power plan and background load attested in manifests/PC-LDN.md; iCloud sync quit; gates run under the same conditions as the timed campaign.
The result lines below are the captured output of the commands as executed on this machine.

Baseline, branch baseline at 7c20bca: cargo test -p libsignal-protocol

test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s
test result: ok. 11 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.45s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.44s
test result: ok. 18 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 3.31s
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.51s



Version 1, working-v1.x at 11e9fd1: cargo test --no-default-features --features mlkem1024

test result: ok. 45 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.47s
test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.47s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.22s
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.37s



Version 2, working-v2.x at 70e0812: cargo test --no-default-features --features hqc256

test result: ok. 45 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.41s
test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.48s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.16s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.21s
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.40s



HQC KEM crate: cargo test --manifest-path third-party/hqc-kem/Cargo.toml

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s



An earlier PC gate run predating the campaign environment protocol was recorded
in the Version 1 release notes and is superseded by this record.
