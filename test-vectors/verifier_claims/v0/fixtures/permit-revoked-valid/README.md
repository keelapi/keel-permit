# permit-revoked-valid

Valid signed permit revocation event.

## What It Tests

The pack contains a signed `permit.revoked` event with `permit_id`, `project_id`, opaque actor identity, taxonomy `reason_code`, and `effective_at == revoked_at`.

## Expected Verdict

`permit.revoked.v1` is expected to return `supported`.
