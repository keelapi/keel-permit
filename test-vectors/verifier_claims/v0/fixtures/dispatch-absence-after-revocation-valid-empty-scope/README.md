# dispatch-absence-after-revocation-valid-empty-scope

Valid post-revocation dispatch absence with empty matching scope.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment whose post-revocation `dispatch.egress_bound` matching count is zero.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `supported`.
