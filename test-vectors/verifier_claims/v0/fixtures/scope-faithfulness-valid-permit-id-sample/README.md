# scope-faithfulness-valid-permit-id-sample

Valid declared sample by permit_id.

## What It Tests

Selective declared sample by permit_id; sidecar matching count equals disclosed records.

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses 4 scope
member record(s); the committed Merkle root is `sha256:0ccebdbe920c6bab6f76e25e9d903769d94b159309e987764efa86a4f068c195`.
