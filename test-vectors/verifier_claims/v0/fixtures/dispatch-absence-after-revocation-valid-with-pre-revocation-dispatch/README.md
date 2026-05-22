# dispatch-absence-after-revocation-valid-with-pre-revocation-dispatch

Valid post-revocation dispatch absence with pre-revocation dispatch evidence.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment whose post-revocation `dispatch.egress_bound` matching count is zero. A pre-revocation `dispatch.egress_bound` record is supplied as bridge evidence and does not match the bounded `occurred_at` range.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `supported`.
