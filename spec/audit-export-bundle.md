# Audit Export Bundle

An **audit export bundle** is the unit of evidence delivery. It contains a set of permits, optional chain entries, optional usage and replay evidence, and (when signed) a companion manifest containing the bundle's content hash, signature, public key, key identifier, and chain integrity snapshot.

This document specifies the bundle file format, the schema versions, and the manifest sidecar.

---

## 1. Conformance keywords

MUST, MUST NOT, SHOULD, MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Bundle object

```json
{
  "bundle_type": "audit_export_bundle",
  "schema_version": 2,
  "format": "json",
  "project_id": "uuid",
  "time_range_basis": "permit.created_at",
  "from": "RFC 3339",
  "to": "RFC 3339",
  "generated_at": "RFC 3339",
  "record_count": 1,
  "include_chain_entries": true,
  "records": [ /* §3 */ ]
}
```

| Field | Required | Notes |
|---|---|---|
| `bundle_type` | yes | MUST be the literal string `"audit_export_bundle"`. |
| `schema_version` | yes | `1` or `2`. See §4. |
| `format` | yes | MUST be `"json"`. CSV and JSONL are out-of-scope for cryptographic verification (see §7). |
| `project_id` | yes | Issuing project identifier. |
| `time_range_basis` | yes | The field used as the time anchor; MUST be `"permit.created_at"` for v1.0 of this spec. |
| `from` | yes | Inclusive lower bound, RFC 3339. |
| `to` | yes | Exclusive upper bound, RFC 3339. |
| `generated_at` | yes | When the bundle was produced. |
| `record_count` | yes | Number of records in `records[]`. |
| `include_chain_entries` | optional | Default `false`. MUST be present and `true` when `schema_version == 2` and chain entries are included. MUST be omitted or `false` when `schema_version == 1`. |
| `records` | yes | Array of `record_count` audit export records. |

## 3. Record object

Each entry in `records[]`:

```json
{
  "permit": { /* Permit object per permit-v1.md §2 */ },
  "permit_evidence": [ /* implementation-defined evidence attachments */ ],
  "latest_usage_ledger": { /* optional */ },
  "usage_log": { /* optional */ },
  "replay_evidence": { /* optional */ },
  "chain_entries": [ /* schema_version 2 only — chain entries linking to this permit */ ]
}
```

`permit` is REQUIRED. All other fields are OPTIONAL. When `schema_version == 2` and the bundle's `include_chain_entries == true`, every record MUST carry `chain_entries`. When `schema_version == 1`, `chain_entries` MUST be absent.

## 4. Schema versions

| `schema_version` | Records | Chain entries | Use case |
|---|---|---|---|
| `1` | yes | no | Records-only bundle. Suitable for compliance review, business reporting, downstream ingestion. Cryptographic verification is limited to the bundle-level signature on the manifest. |
| `2` | yes | yes | Records plus chain entries. Required for chain-walk verification of the included export window — the verifier recomputes record hashes and validates continuity per [`chain-entry.md`](chain-entry.md). |

A verifier MUST reject bundles with any `schema_version` value other than `1` or `2`. Future spec revisions may add `3+`; old verifiers will reject and SHOULD report the version in the failure message.

## 5. Manifest sidecar

When the bundle is signed, the issuer publishes a companion manifest as a separate JSON file. The manifest commits to the exact byte content of the bundle file.

```json
{
  "export_id": "uuid",
  "project_id": "uuid|null",
  "export_type": "string",
  "format": "string",
  "compressed": false,
  "record_count": 1,
  "content_hash": "sha256:<hex>",
  "signature": "ed25519:<base64>",
  "public_key": "ed25519:<base64>",
  "key_id": "string",
  "signed_at": "RFC 3339",
  "keel_version": "string",
  "chain_integrity": {
    "verified_at": "RFC 3339",
    "chain_length": 0,
    "last_verified_hash": "hex-sha256|null",
    "error": "string|null"
  },
  "filters_hash": "sha256:<hex>"
}
```

### 5.1 Manifest fields

This specification defines the companion manifest normatively in prose. This repository does not yet publish a JSON Schema for the manifest sidecar; adding one is reserved for a non-breaking spec-document update. Until then, conforming verifiers MUST enforce the field and signing rules in this section directly.

- `content_hash` MUST equal `"sha256:" + hex(SHA-256(bundle_file_bytes))`. The hash is computed over the bundle file as it sits on disk, including any compression — i.e., over the bytes a consumer would run `sha256sum` on.
- `signature` MUST be `ed25519:` followed by the base64 encoding of the Ed25519 signature over the UTF-8 bytes of `content_hash`.
- `public_key` MUST be `ed25519:` followed by the base64 encoding of the public key.
- `key_id` is an issuer-stable identifier referencing the public key. Verifiers MUST be able to resolve `key_id` to a public key through the issuer's key manifest.
- `signed_at` MUST be the time the manifest was signed.
- `chain_integrity` is OPTIONAL and reports the issuer's most recent chain integrity check. If `error` is non-null, `last_verified_hash` MAY be null and `chain_length` MAY be `0`; the bundle is still verifiable but the issuer is disclosing a chain integrity concern.
- `filters_hash` MUST commit to the exact filter set the caller requested when generating the bundle. The hash is computed via the issuer's canonicalization rules; see [`canonical-json.md`](canonical-json.md).
- A `keel_version` field is emitted by the Keel reference implementation as the issuer-version stamp. Alternative issuers SHOULD emit an analogous `<issuer>_version` field; the literal name `keel_version` is not normative.

### 5.2 Signing rules

The signature is over the **UTF-8 bytes of `content_hash`**, not over the manifest JSON itself. This indirection is intentional: the signature commits to the bundle's content, and the manifest is a presentation envelope for that commitment. A verifier MUST NOT attempt to verify the signature against the manifest bytes directly.

The signing key purpose MUST be `export_signing` in the issuer's key manifest.

### 5.3 Companion file naming

The manifest filename SHOULD be `<bundle_filename>.manifest.json`. Implementations MAY use other conventions provided the relationship is documented.

## 6. Verification

A conforming verifier, given a bundle file and its manifest:

1. MUST verify `manifest.content_hash` against the bundle file bytes; on mismatch, fail.
2. MUST resolve `manifest.key_id` against the issuer's key manifest, scoping to purpose `export_signing` and to a `valid_from`/`valid_to` window containing `manifest.signed_at`.
3. MUST verify the Ed25519 signature against the resolved key; on failure, fail.
4. If the bundle has `schema_version == 2`, MUST walk each record's `chain_entries` per [`chain-entry.md`](chain-entry.md) §5, emitting the appropriate `WALK_*` failure code on any violation.
5. For each record where the permit's `decision == "allow"` and a closure record is available, SHOULD verify the closure record per [`closure-v2.md`](closure-v2.md) §8.

A bundle that passes all applicable checks is considered cryptographically intact for the included export window. It does not by itself prove complete lifetime history outside that window unless the first and last supplied chain entries are tied to anchored checkpoints or another documented continuity proof.

## 7. Non-JSON formats

CSV and JSONL representations of the same data MAY be produced for human inspection or downstream ingestion, but they fall outside the cryptographic verification surface. The signed manifest's `content_hash` covers exactly one byte sequence; consumers verifying the manifest MUST work with that byte sequence, not a re-rendered alternative format.

## 8. Compression

A bundle MAY be gzip-compressed. The manifest MUST set `compressed: true` and the `content_hash` MUST cover the compressed bytes. Decompression is performed by the consumer after signature verification.

## 9. Reserved fields

The following field names are reserved for future versions:

- `signature_v2` (reserved for richer signature envelopes — e.g., dual-signed by issuer and customer counter-signature).
- `witnesses` (reserved for additional anchoring records — e.g., RFC 3161 timestamp tokens linked to the bundle, multi-witness anchoring).

## 10. Plan-tier visibility

This spec is agnostic to plan-tier or pricing constructs. Issuers MAY restrict bundle access, signing, or chain-entry inclusion based on commercial tier; such restrictions are out of scope for the wire format and have no bearing on conformance.
