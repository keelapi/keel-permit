# Permit v2

A **Permit v2** is a pre-execution decision record with an additive
multi-party signature envelope. It preserves the Permit v1 audit-export object
as the base permit shape and adds an explicit format discriminator plus
signature slots for issuer, operator, buyer-principal, and historical
attestation evidence.

This document specifies the **wire format `v2`** of the Permit object. Permit v2
does not replace Permit v1. A v2-capable verifier MUST select rules by
`permit_format_version`: an absent value or `"v1"` is verified under Permit v1
rules; `"v2"` is verified under this document.

---

## 1. Conformance keywords

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Relationship to Permit v1

Permit v2 is additive over [`permit-v1.md`](permit-v1.md). Every Permit v2 object
MUST satisfy the Permit v1 required field set and MUST additionally carry:

| Field | Type | Description |
|---|---|---|
| `permit_format_version` | string | MUST be `"v2"`. |

The Permit v2 schema is closed. Validators MUST reject unknown top-level
fields. Permit v1 validators are also closed and MUST reject v2-only fields
when a v2 object is presented to a v1-only verifier.

## 3. Multi-party signature envelope

Permit v2 defines five signature slots:

| Slot | Status | Signer | Purpose |
|---|---|---|---|
| `signature` | active | issuer | Issuer signature, compatible with existing v1 issuer signing material. |
| `operator_approval` | active | issuer organization operator | Dual-control approval inside the issuing organization. |
| `counter_signature` | active | buyer principal | Buyer pre-dispatch authorization for a specific execution intent. |
| `audit_attestation` | active | buyer principal | Buyer post-hoc attestation that a historical permit existed in a batch. |
| `provider_attestation` | reserved | provider | Reserved for a separate design pass. It MUST NOT appear in Permit v2 objects. |

The active v2-specific slots are optional at the JSON Schema layer because
their requiredness is lifecycle-dependent. For example, `audit_attestation` is
not available before historical audit processing. When a slot is present, its
sub-object schema is closed and validators MUST reject unknown fields inside
the sub-object.

## 4. Issuer signature slot

The `signature` slot records issuer-originated signing evidence. Its shape is
compatible with existing v1 issuer signing material and does not introduce a
new v2 payload type.

```json
{
  "signer_id": "opaque UUID",
  "key_id": "issuer key identifier",
  "signed_at": "UTC timestamp with microsecond precision",
  "signed_payload_hash": "sha256 hex",
  "signature": "base64 Ed25519 signature"
}
```

The issuer signature binds the issuer-defined v1-compatible permit canonical
payload. Verifiers that evaluate issuer signatures MUST resolve the issuer key
according to the applicable issuer key manifest or trust-root profile.

## 5. Operator approval slot

The `operator_approval` slot is an issuer-organization dual-control signature.
It has the following closed shape:

```json
{
  "payload_type": "permit.operator_approval.v1",
  "signer_id": "opaque UUID",
  "key_id": "sha256 fingerprint",
  "signed_at": "UTC timestamp with microsecond precision",
  "signed_payload_hash": "sha256 hex",
  "signature": "base64 Ed25519 signature"
}
```

The canonical signed payload is the canonical JSON bytes of exactly:

```json
{
  "payload_type": "permit.operator_approval.v1",
  "permit_id": "opaque UUID",
  "issuer_signature_hash": "sha256 hex",
  "permit_canonical_hash": "sha256 hex",
  "operator_id": "opaque UUID",
  "signed_at": "UTC timestamp with microsecond precision"
}
```

`signer_id` in the envelope MUST identify the same operator as
`operator_id` in the signed payload.

## 6. Counter-signature slot

The `counter_signature` slot is a buyer pre-dispatch authorization over a
specific execution intent. It has the following closed shape:

```json
{
  "payload_type": "permit.counter_signature.v1",
  "signer_id": "opaque UUID",
  "key_id": "sha256 fingerprint",
  "signed_at": "UTC timestamp with microsecond precision",
  "signed_payload_hash": "sha256 hex",
  "signature": "base64 Ed25519 signature",
  "execution_intent_hash": "sha256 hex"
}
```

The canonical signed payload is the canonical JSON bytes of exactly:

```json
{
  "payload_type": "permit.counter_signature.v1",
  "permit_id": "opaque UUID",
  "issuer_signature_hash": "sha256 hex",
  "permit_canonical_hash": "sha256 hex",
  "buyer_principal_id": "opaque UUID",
  "execution_intent_hash": "sha256 hex",
  "signed_at": "UTC timestamp with microsecond precision"
}
```

`signer_id` in the envelope MUST identify the same buyer principal as
`buyer_principal_id` in the signed payload.

## 7. Audit-attestation slot

The `audit_attestation` slot is a buyer post-hoc attestation that a historical
permit existed in a specific audit batch. It has the following closed shape:

```json
{
  "payload_type": "permit.audit_attestation.v1",
  "signer_id": "opaque UUID",
  "key_id": "sha256 fingerprint",
  "signed_at": "UTC timestamp with microsecond precision",
  "signed_payload_hash": "sha256 hex",
  "signature": "base64 Ed25519 signature",
  "batch_id": "string"
}
```

The canonical signed payload is the canonical JSON bytes of exactly:

```json
{
  "payload_type": "permit.audit_attestation.v1",
  "permit_id": "opaque UUID",
  "issuer_signature_hash": "sha256 hex",
  "permit_canonical_hash": "sha256 hex",
  "buyer_principal_id": "opaque UUID",
  "batch_id": "string",
  "signed_at": "UTC timestamp with microsecond precision"
}
```

`signer_id` in the envelope MUST identify the same buyer principal as
`buyer_principal_id` in the signed payload.

## 8. Payload domain separation

Each v2-specific signed payload carries an explicit `payload_type` literal:

| Slot | `payload_type` |
|---|---|
| `operator_approval` | `"permit.operator_approval.v1"` |
| `counter_signature` | `"permit.counter_signature.v1"` |
| `audit_attestation` | `"permit.audit_attestation.v1"` |

The `payload_type` is a cryptographic domain separator. Verifiers MUST reject a
signature when the signed payload's `payload_type` does not match the slot being
verified. A valid `operator_approval` signature MUST NOT be accepted as a
`counter_signature` or `audit_attestation`, even when the rest of the payload
fields are otherwise well formed.

## 9. Canonicalization and hashes

Canonical signed payload bytes use the repository canonical JSON profile:
object keys sorted lexicographically, no insignificant whitespace, and UTF-8
encoding. `signed_payload_hash` is the lowercase SHA-256 hex digest of those
canonical bytes.

`issuer_signature_hash` is the lowercase SHA-256 hex digest of the issuer
signature evidence. `permit_canonical_hash` is the lowercase SHA-256 hex digest
of the v1-compatible canonical permit payload that the multi-party slots bind
to. These values are explicit inputs to each v2-specific signed payload so that
operator, buyer, and audit attestations cannot be replayed onto a different
issuer signature or permit body.

Timestamps in v2-specific signature slots and signed payloads MUST be UTC ISO
8601 timestamps with microsecond precision and a `Z` suffix.

## 10. Signing-time key validity

The v2-specific slots use account-scoped Ed25519 public keys. Verifiers MUST
resolve keys by `(account_id, key_id)` as of the slot's `signed_at` timestamp,
not by current key state.

Routine key rotation after signing remains valid. A revocation or compromise
effective at or before `signed_at` invalidates the slot. A revocation or
compromise effective after `signed_at` MUST NOT invalidate an otherwise valid
historical signature.

## 11. Procurement and audit posture

Existing audit standards verify controls, logs, and authorization processes,
but do not standardize cryptographically verifiable buyer assent at the
individual AI-action level. Keel introduces this as a higher-granularity
governance primitive.

Permit v2's buyer-principal signatures are intended to make individual
AI-action assent verifiable without depending solely on retrospective process
evidence. Existing controls and logs remain relevant evidence, but they are not
the cryptographic source of buyer assent for a specific governed action.

## 12. Failure codes

Conforming verifiers MUST emit failure codes from
[`failure-codes.md`](failure-codes.md). The v2-specific signature slots use the
`PERMIT_OPERATOR_APPROVAL_*`, `PERMIT_COUNTER_SIGNATURE_*`,
`PERMIT_AUDIT_ATTESTATION_*`, and `PAYLOAD_TYPE_MISMATCH` codes defined there.

## 13. Future fields

Permit v2 is a closed format. `provider_attestation` is reserved for a future
design pass and MUST NOT be accepted by this version. Implementations MUST NOT
add issuer-private top-level fields or slot fields to v2 objects; such changes
require a successor permit format version.
