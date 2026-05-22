# permit-decision-neg-bad-signature

Permit decision with invalid signature.

## What It Tests

The pack mutates a signed issuance-time permit decision binding: The binding signature is produced by an untrusted key while the canonical payload still names the trusted key.

## Expected Verdict

`permit.decision.v1` is expected to return `disproved` with `PERMIT_DECISION_SIGNATURE_INVALID`.
