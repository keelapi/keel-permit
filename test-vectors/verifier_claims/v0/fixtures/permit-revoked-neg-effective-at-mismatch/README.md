# permit-revoked-neg-effective-at-mismatch

Permit revocation effective_at mismatch.

## What It Tests

The pack mutates signed `permit.revoked` evidence: The signed revocation event uses an effective_at timestamp different from revoked_at, which v1 reserves for future scheduling semantics.

## Expected Verdict

`permit.revoked.v1` is expected to return `disproved` with `PERMIT_REVOKED_EFFECTIVE_AT_MISMATCH`.
