# permit-decision-neg-tampered-decision

Permit decision with tampered canonical decision.

## What It Tests

The pack mutates a signed issuance-time permit decision binding: The signed canonical payload decision is changed after the canonical hash and signature are produced.

## Expected Verdict

`permit.decision.v1` is expected to return `disproved` with `PERMIT_DECISION_CANONICAL_HASH_MISMATCH`.
