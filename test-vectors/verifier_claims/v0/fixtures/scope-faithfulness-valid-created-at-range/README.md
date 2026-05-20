# scope-faithfulness-valid-created-at-range

Valid declared sample by created_at range.

## What It Tests

Time-range predicate with created_at.gte/lt.

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses 4 scope
member record(s); the committed Merkle root is `sha256:0d3d57afdf888c3e4f032f42eacbd5784195c08948e819379561c04e16b8974a`.
