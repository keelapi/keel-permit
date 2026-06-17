# Key Status Event v1

This document specifies the signed `key.status.v1` event payload for
account-scoped key revocation and compromise evidence.

`key.status.v1` is append-only evidence. It does not make mutable key registry
rows, caller manifests, or unsigned status fields sufficient by themselves.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Event Shape

The strict JSON Schema is
[`../schemas/key-status-event.schema.json`](../schemas/key-status-event.schema.json).

Required common fields:

| Field | Type | Description |
|---|---|---|
| `event_type` | string | Literal `key.status.v1`. |
| `account_id` | UUID | Identifier of the account that owns the key. |
| `key_scope` | enum | One of `operator`, `buyer_principal`, `mcp_server`, or `provider_principal`. |
| `key_id` | hex string | SHA-256 key identifier of the account-scoped public key. |
| `status` | enum | `revoked` or `compromised`. |
| `signer` | object | Signing key metadata: purpose, key id, and algorithm. |
| `event_hash` | hex string | SHA-256 hash of the canonical signed fields. |
| `signature` | base64 | Ed25519 signature over `event_hash`. |

When `status` is `revoked`, `revoked_at` is REQUIRED and `compromised_at` MUST
be absent.

When `status` is `compromised`, `compromised_at` is REQUIRED and `revoked_at`
MUST be absent.

The schema is closed. Unknown fields MUST be rejected.

## 3. Canonical Payload

The signed payload is the event object with `event_hash` and `signature`
removed. The payload is serialized with `keel.canonical_json.payload.v1`:
sorted keys, compact separators, UTF-8, `ensure_ascii=false`, and no
volatile-key stripping.

`event_hash` is lowercase hex SHA-256 of those canonical JSON bytes. The
Ed25519 signature signs the UTF-8 bytes of `event_hash`.

The signature field carries base64 for the raw 64-byte Ed25519 signature.

## 4. Identity Binding

`account_id`, `key_scope`, and `key_id` are mandatory signed fields. A verifier
MUST compare all three values against the key record being evaluated. A
matching `key_id` alone is not sufficient.

The `signer` object MUST identify the `permit_binding_signing` purpose and the
public key manifest key id used to verify the signature. A verifier MUST
resolve that signer through a pinned trusted key manifest, not through a caller
manifest.

## 5. Status Semantics

`revoked` means the key is no longer valid at and after `revoked_at`.

`compromised` means the key is no longer valid at and after `compromised_at`.
Broader retrospective compromise policy is outside this v1 event shape and is
left to higher-level verifier claims.

## 6. Claim Use

This event is a foundational input for witnessed key-status completeness and
revocation-temporal claims. It is not sufficient by itself to prove completeness
of the key-status domain.
