# scope-faithfulness-valid-provider

Valid declared sample by provider.

## What It Tests

Selective disclosure by provider metadata.

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses 3 scope
member record(s); the committed Merkle root is `sha256:16cbebcfab23025ae52f70b0b58a8016fd0ff223a3672636b90a4d9bb5851bb5`.
