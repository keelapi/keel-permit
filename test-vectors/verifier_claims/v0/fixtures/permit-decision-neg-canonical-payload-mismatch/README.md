# permit-decision-neg-canonical-payload-mismatch

Permit decision canonical payload mismatch.

## What It Tests

The pack mutates a signed issuance-time permit decision binding: The signed canonical payload is valid, but the requested decision evidence expects a different decision.

## Expected Verdict

`permit.decision.v1` is expected to return `disproved` with `PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH`.
