# Permit Revoked Event v1

This document specifies the signed `permit.revoked` event payload and the
`permit.revoked.v1` verifier claim.

`permit.revoked.v1` is a post-cutover claim for newly emitted signed revocation
events. It does not retrofit historical mutable permit rows into revocation
events.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Event Shape

The strict JSON Schema is
[`../schemas/permit-revoked-event.schema.json`](../schemas/permit-revoked-event.schema.json).

Required fields:

| Field | Type | Description |
|---|---|---|
| `permit_id` | UUID | Identifier of the revoked permit. |
| `project_id` | UUID | Identifier of the issuing project. This value is signed to prevent cross-project replay. |
| `actor_id` | UUID | Opaque revocation actor identifier. |
| `actor_kind` | enum | One of `user`, `service_account`, `system`, or `api_key`. |
| `reason_code` | string | Machine-readable taxonomy code. Free text is not part of the signed v1 payload. |
| `revoked_at` | RFC 3339 timestamp | Governance event time for the revocation. |
| `effective_at` | RFC 3339 timestamp | Effective revocation time. v1 requires this to equal `revoked_at`. |
| `signature` | base64 | Ed25519 signature over the canonical revocation payload hash. |

The schema is closed. Unknown fields MUST be rejected.

## 3. Canonical Payload

The signed payload is the event object with `signature` removed. The payload is
serialized with `keel.canonical_json.payload.v1`: sorted keys, compact
separators, UTF-8, `ensure_ascii=false`, and no volatile-key stripping.

The canonical hash is lowercase hex SHA-256 of those canonical JSON bytes. The
Ed25519 signature signs the UTF-8 bytes of that canonical hash, using a
permit-binding signing key.

The signature field carries base64 for the raw 64-byte Ed25519 signature.

## 4. Identity Binding

Both `permit_id` and `project_id` are mandatory signed fields. A verifier MUST
compare both values against the claim scope. A matching permit ID with a
different project ID is `disproved` with
`PERMIT_REVOKED_PROJECT_ID_MISMATCH`.

`actor_id` MUST be opaque. It MUST NOT carry an email address, display name,
natural-language label, external ticket, or customer-controlled identifier. A
verifier that detects PII-shaped actor identity material MUST return
`disproved` with `PERMIT_REVOKED_ACTOR_PII_DETECTED`.

## 5. Effective Time

v1 revocation is immediate. `effective_at` MUST equal `revoked_at`.

Scheduled revocation is reserved for a future version. A v1 event with
different `effective_at` and `revoked_at` MUST return `disproved` with
`PERMIT_REVOKED_EFFECTIVE_AT_NOT_EQUAL_REVOKED_AT`.

## 6. Legacy Status Snapshots

Pre-cutover revoked permits remain runtime-only lifecycle status snapshots.
They are legacy revocation status snapshots, not revocation evidence for
`permit.revoked.v1`.

A verifier MUST NOT infer a signed revocation event from a historical permit row
whose mutable `status` is `revoked`. If the signed event payload is missing,
the claim verdict is `insufficient_evidence`.

## 7. Claim Verdicts

`supported`: the strict event payload is present, `effective_at == revoked_at`,
the signed `permit_id` and `project_id` match the claim scope, and the Ed25519
signature verifies under a trusted permit-binding key active at `revoked_at`.

`disproved`: the signature fails, the signed project identity does not match,
`effective_at` differs from `revoked_at`, actor identity violates the opaque-ID
rule, or the canonical payload hash does not match the signed bytes.

`insufficient_evidence`: required event payload, signature, trust-root evidence,
or permit/project identity evidence is missing.

`unverifiable_scope`: the canonicalization profile, key manifest profile, or
actor taxonomy is unsupported.

## 8. Failure Codes

Applicable standard failure codes are defined in
[`failure-codes.md`](failure-codes.md):

- `PERMIT_REVOKED_SIGNATURE_INVALID`
- `PERMIT_REVOKED_PROJECT_ID_MISMATCH`
- `PERMIT_REVOKED_EFFECTIVE_AT_NOT_EQUAL_REVOKED_AT`
- `PERMIT_REVOKED_ACTOR_PII_DETECTED`
- `UNKNOWN_SIGNING_KEY`
- `KEY_EXPIRED_AT_SIGNING_TIME`
- `SIGNING_KEY_REVOKED`

The pinned semantic artifact is
[`../semantics/permit/revoked_event_v1.json`](../semantics/permit/revoked_event_v1.json).
