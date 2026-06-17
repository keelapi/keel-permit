# Key Status Manifest v1

This document specifies the signed `permit_v2.key_status_manifest.v1` artifact
covering account-scoped public keys and their witnessed `key.status.v1`
references.

The manifest is a public verification input. It does not by itself prove
completeness of key-status evidence; completeness is established by higher
level verifier claims that pin the manifest and compose it with checkpoint
scope-state evidence.

For Permit binding v7 and later, this manifest does not choose the account or
registry partition for Permit v2 slot key lookup. That selector comes from the
signed permit bytes; unsigned manifest account metadata may corroborate the
signed selector but MUST NOT override it.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Manifest Shape

The strict JSON Schema is
[`../schemas/key-status-manifest.schema.json`](../schemas/key-status-manifest.schema.json).

Required top-level fields:

| Field | Type | Description |
|---|---|---|
| `manifest_type` | string | Literal `permit_v2.key_status_manifest.v1`. |
| `canonicalization_profile` | string | Literal `keel.canonical_json.payload.v1`. |
| `computed_at` | RFC 3339 timestamp | Issuer time at which the manifest was computed. |
| `account_id` | UUID or null | Account scope covered by the manifest, or null for an issuer-wide manifest. |
| `key_scopes` | array | Exact list: `operator`, `buyer_principal`, `mcp_server`, `provider_principal`. |
| `keys` | array | Public key records covered by the manifest. |
| `signer` | object | Signing key metadata: purpose, key id, and algorithm. |
| `manifest_hash` | hex string | SHA-256 hash of the canonical signed fields. |
| `signature` | base64 | Ed25519 signature over `manifest_hash`. |

The schema is closed. Unknown top-level fields and unknown key-entry fields
MUST be rejected.

## 3. Key Entries

Each `keys[]` entry MUST include:

| Field | Description |
|---|---|
| `account_id`, `key_scope`, `key_id` | Signed identity tuple for the key. A matching `key_id` alone is not sufficient. |
| `algorithm`, `public_key` | Public Ed25519 verification material. |
| `status` | One of `active`, `revoked`, or `compromised`. |
| `valid_from`, `valid_until`, `revoked_at`, `compromised_at` | Signed validity and terminal-status timestamps. Null means absent. |
| `metadata` | Non-PII issuer metadata. |
| `event_refs` | References to verified `key.status.v1` governance-chain events. |
| `principal` | Public principal namespace for the key scope. |

`event_refs[]` entries MUST carry `event_type`, `event_id`, `record_hash`,
`sequence_number`, and `status`. The referenced governance event payload MUST
be a valid signed `key.status.v1` event, and the signed `account_id`,
`key_scope`, `key_id`, and `status` values MUST match the manifest reference.

## 4. Canonical Payload

The signed payload is the manifest object with `manifest_hash` and `signature`
removed. The payload is serialized with `keel.canonical_json.payload.v1`:
sorted keys, compact separators, UTF-8, `ensure_ascii=false`, and no
volatile-key stripping.

`manifest_hash` is lowercase hex SHA-256 of those canonical JSON bytes. The
Ed25519 signature signs the UTF-8 bytes of `manifest_hash`.

The signature field carries base64 for the raw 64-byte Ed25519 signature.

## 5. Signer Binding

The `signer` object MUST identify the `permit_binding_signing` purpose and the
public key manifest key id used to verify the signature. A verifier MUST
resolve that signer through pinned trusted key material, not through an
untrusted caller manifest.

## 6. Claim Use

This manifest is a foundational input for
[`key.status.completeness.v1`](key-status-completeness-v1.md) and
revocation-temporal composition. It is not sufficient by itself to prove that
all relevant key-status events have been observed.
