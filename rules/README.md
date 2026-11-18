# LocalEDR Rules & Standard OS Allowlists

> Phase 0 placeholder — owned by Worker 2 (`crates/ledr-rules` & `crates/ledr-daemon`) in Phase 1+.

## Planned Contents

1. **Initial Sigma Subset Rules** (Decision Record L-12):
   - Single-event and immediate-parent field matching (`Image`, `ParentImage`, `CommandLine`, `DestinationIp`, `QueryName`, `TargetFilename`).
   - Supports prefix, suffix, substring (`all` conjunction), and bounded precompiled regexes compiled at startup into an Aho-Corasick automaton within a ~2 MB memory budget.
2. **Standard OS Allowlists** (Decision Record L-04):
   - **Two-tier verification model**:
     - Signed OS/vendor binaries: normalized path pattern + Authenticode `signer_subject` and `root_thumbprint`.
     - Unsigned binaries: normalized executable path + exact `SHA-256` hash.
