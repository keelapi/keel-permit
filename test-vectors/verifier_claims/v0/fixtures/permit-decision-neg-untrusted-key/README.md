# permit-decision-neg-untrusted-key

Permit decision signed by untrusted key.

## What It Tests

The pack mutates a signed issuance-time permit decision binding: The binding is internally valid but names a permit-binding key absent from the public trust root.

## Expected Verdict

`permit.decision.v1` is expected to return `insufficient_evidence` with `PERMIT_DECISION_UNTRUSTED_KEY`.
