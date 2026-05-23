# dispatch-absence-after-revocation-neg-bridge-record-matches-predicate

Bridge record matching dispatch predicate disproves absence.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation `dispatch.egress_bound` events.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `disproved` with `EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE`.
