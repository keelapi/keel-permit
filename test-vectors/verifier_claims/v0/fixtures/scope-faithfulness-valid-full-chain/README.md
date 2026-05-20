# scope-faithfulness-valid-full-chain

Valid scope-faithful full project chain.

## What It Tests

Full project chain from genesis to checkpoint head; predicate project_id.

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses 8 scope
member record(s); the committed Merkle root is `sha256:e228187fd151a1203ea3611e297273946f3606d7431b80e44f01e3cd992dfa70`.
