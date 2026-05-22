# dispatch-absence-after-revocation-neg-missing-sidecar

Missing scope-state sidecar prevents absence adjudication.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation `dispatch.egress_bound` events.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `insufficient_evidence` with `CHECKPOINT_SCOPE_STATE_MISSING`.
