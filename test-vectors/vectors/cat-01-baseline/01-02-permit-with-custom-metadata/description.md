# 01-02 — Valid Permit with custom_metadata Extension Carrier

## What this exercises

Verifies that a conforming v1.5.0 validator accepts a permit carrying
`custom_metadata` with a `shadow_override` key. A conforming verifier MUST
report `PASS`.

This exercises the closed-with-escape-valve semantics introduced in v1.5.0:
the outer `AuditExportPermitSource` object remains closed
(`additionalProperties: false`), but the `custom_metadata` field is an
explicitly designated open carrier (`additionalProperties: true`).

## Inputs

- `input/permit.json` — single Permit, `decision = "allow"`, with:
  ```json
  "custom_metadata": {
    "shadow_override": {
      "outcome": "blocked"
    }
  }
  ```
- `input/export.jsonl` — newline-delimited records (genesis chain entry + Permit-creation event + Permit + closure record).
- `input/manifest.json` — manifest with `content_hash` of the export.
- `input/signature.bin` — detached Ed25519 signature over `manifest.json` UTF-8 bytes.
- `input/trust-root.json` — test-only trust root.

## Expected behavior

A conforming verifier:

- Reports `result: "PASS"`.
- Reports `failure_codes: []`.
- Does NOT reject the permit due to the presence of `custom_metadata` or `shadow_override`.

## Why this is "scaffolded" not "complete"

Fixture content uses placeholder hashes. Generator tooling is pending (same as
01-01). This vector documents the conformance requirement and will be made
concrete when the fixture generator is committed.

## Spec reference

- `spec/permit-v1.md` §2.3 (optional fields table — `custom_metadata` row)
- `spec/permit-v1.md` §12 (closed-with-escape-valve semantics)
- `schemas/permit-v1.schema.json` — `custom_metadata` property on `AuditExportPermitSource`
