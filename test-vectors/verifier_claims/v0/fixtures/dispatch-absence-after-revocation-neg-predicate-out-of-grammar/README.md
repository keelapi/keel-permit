# dispatch-absence-after-revocation-neg-predicate-out-of-grammar

Absence predicate outside permit v1 grammar.

## What It Tests

The pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation `dispatch.egress_bound` events.

## Expected Verdict

`permit.dispatch_absence_after_revocation.v1` is expected to return `unverifiable_scope` with `EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR`.
