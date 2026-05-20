# scope-faithfulness-valid-event-type

Valid declared sample by event_type.

## What It Tests

Selective disclosure by event_type.

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses 2 scope
member record(s); the committed Merkle root is `sha256:02762992d2dc20693cf962de8d4d6220bf7fddccb2d10982b8fbdcdf7509545a`.
