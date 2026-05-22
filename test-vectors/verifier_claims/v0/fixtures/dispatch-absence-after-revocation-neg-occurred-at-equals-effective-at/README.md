# dispatch-absence-after-revocation-neg-occurred-at-equals-effective-at

Dispatch at revocation effective_at disproves absence.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation `dispatch.egress_bound` events.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `disproved` with `EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT`.
