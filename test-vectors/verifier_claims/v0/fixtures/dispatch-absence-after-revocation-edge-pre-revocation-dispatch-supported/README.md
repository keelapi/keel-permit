# dispatch-absence-after-revocation-edge-pre-revocation-dispatch-supported

Pre-revocation dispatch does not disprove post-revocation absence.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation `dispatch.egress_bound` events. A pre-revocation `dispatch.egress_bound` record is supplied as bridge evidence and does not match the bounded `occurred_at` range.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `supported` with `PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED`.
