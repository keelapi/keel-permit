# scope-faithfulness-valid-presentation-policy-restricted

Valid declared sample with presentation policy redaction.

## What It Tests

Predicate plus presentation_policy redaction; verifier checks declared policy application, not entitlement correctness.

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses 6 scope
member record(s); the committed Merkle root is `sha256:39a27e1b55774ed0072f1c48662c59faed07ee05e3df8ebb812073b78b98764d`.
