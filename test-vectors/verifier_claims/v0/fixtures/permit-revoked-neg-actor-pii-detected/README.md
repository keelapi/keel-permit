# permit-revoked-neg-actor-pii-detected

Permit revocation actor identity contains PII.

## What It Tests

The pack mutates signed `permit.revoked` evidence: The signed actor_id uses an email-address shape instead of an opaque UUID.

## Expected Verdict

`permit.revoked.v1` is expected to return `disproved` with `PERMIT_REVOKED_ACTOR_PII_DETECTED`.
