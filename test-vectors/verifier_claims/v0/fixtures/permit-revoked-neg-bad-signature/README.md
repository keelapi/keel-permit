# permit-revoked-neg-bad-signature

Permit revocation with invalid signature.

## What It Tests

The pack mutates signed `permit.revoked` evidence: The revocation event signature is produced by a key outside the public permit-binding trust root.

## Expected Verdict

`permit.revoked.v1` is expected to return `disproved` with `PERMIT_REVOKED_SIGNATURE_INVALID`.
