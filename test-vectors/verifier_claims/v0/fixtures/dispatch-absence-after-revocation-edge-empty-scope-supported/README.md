# dispatch-absence-after-revocation-edge-empty-scope-supported

Empty post-revocation dispatch scope is supported.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation `dispatch.egress_bound` events.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `supported` with `PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED`.
