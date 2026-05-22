# permit-revoked-neg-missing-field

Permit revocation missing required field.

## What It Tests

The pack mutates signed `permit.revoked` evidence: The required reason_code field is removed from the signed revocation event evidence.

## Expected Verdict

`permit.revoked.v1` is expected to return `insufficient_evidence` with `PERMIT_REVOKED_EVIDENCE_MISSING`.
