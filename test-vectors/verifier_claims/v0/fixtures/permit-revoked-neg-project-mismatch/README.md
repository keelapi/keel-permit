# permit-revoked-neg-project-mismatch

Permit revocation project mismatch.

## What It Tests

The pack mutates signed `permit.revoked` evidence: The export declares a different project scope than the signed revocation event.

## Expected Verdict

`permit.revoked.v1` is expected to return `disproved` with `PERMIT_REVOKED_PROJECT_ID_MISMATCH`.
