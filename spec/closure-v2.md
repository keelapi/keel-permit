# Closure Record (closure_v1, closure_v2)

A **closure record** is the signed artifact that links a Permit to its execution outcome. For successful dispatched executions, it commits to (a) the canonical provider/tool wire-body bytes that were dispatched, (b) the bytes Keel received from the provider/tool, (c) the bytes handed to the client response writer, and (d) the status under which the execution completed.

This document specifies two closure-record formats: `closure_v1` and `closure_v2`. A conforming verifier MUST accept both indefinitely.

---

## 1. Conformance keywords

MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Format selection

A closure record carries a `binding_version` field whose value selects the format:

| Value | Format |
|---|---|
| `"closure_v1"` | Closure record without `dispatch_request_digest_v1`. Backwards-compatibility format. |
| `"closure_v2"` | Closure record with `dispatch_request_digest_v1` cross-referenced to the permit's `binding_request_hash`. Default for new closures. |

A verifier MUST reject any closure record with an unknown `binding_version` value, emitting `WALK_UNKNOWN_CLOSURE_FORMAT` (see [`failure-codes.md`](failure-codes.md)).

## 3. Closure status

`closure_status` MUST be one of the following values. The set is closed; verifiers MUST reject unknown values.

| Value | Meaning |
|---|---|
| `closed` | Full round-trip closed with provider and client digests present. |
| `client_disconnected` | Client disconnected or cancelled before normal completion. |
| `provider_error` | Provider error or stream error after dispatch. |
| `timeout` | Timeout before normal completion. |
| `dispatch_error` | Dispatch failed before a provider response was available. |
| `provider_digest_missing` | Closure recorded, but provider response digest evidence missing. |
| `client_digest_missing` | Closure recorded, but client delivery digest evidence missing. |
| `missing_closure` | Reconciliation recorded that no closure evidence was found. |

### 3.1 Digest-presence matrix

The presence of digest fields is normative per `closure_status`:

| `closure_status` | `dispatch_request_digest_v1` (closure_v2) | `provider_response_digest_v1` | `client_response_digest_v1` |
|---|---|---|---|
| `closed` | REQUIRED; MUST equal the permit's `binding_request_hash` | REQUIRED | REQUIRED |
| `client_disconnected` | SHOULD be present if dispatch occurred | nullable | nullable / partial |
| `provider_error` | SHOULD be present if dispatch occurred | nullable / partial | nullable |
| `timeout` | SHOULD be present if dispatch occurred | nullable / partial | nullable / partial |
| `dispatch_error` | nullable | nullable | nullable |
| `provider_digest_missing` | SHOULD be present if dispatch occurred | nullable | nullable |
| `client_digest_missing` | SHOULD be present if dispatch occurred | REQUIRED when available | nullable |
| `missing_closure` | n/a (skipped) | n/a (skipped) | n/a (skipped) |

For abnormal closure states, `dispatch_request_digest_v1` MAY be null or omitted when no provider/tool dispatch occurred or when the issuer is reconciling historical evidence that predates dispatch binding. Keel normally emits the field with `null` when it is unavailable. A verifier MUST emit `WALK_CLOSURE_DIGEST_MISSING` when a digest required by the matrix above is absent. A non-null digest MUST match the corresponding chain event payload; a mismatch MUST emit `WALK_CLOSURE_DIGEST_MISMATCH`. A non-null `dispatch_request_digest_v1` that does not equal the permit's `binding_request_hash` MUST emit `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH`.

## 4. Digest definitions

All digests in this section are hex-encoded SHA-256. The **input bytes** to SHA-256 differ per digest — only `dispatch_request_digest_v1` is hashed over canonicalized bytes. The provider/tool and client response digests hash the **raw response bytes** received or handed to the response writer respectively, with no canonicalization step. This distinction is normative.

| Digest | Hash input | Canonicalization |
|---|---|---|
| `dispatch_request_digest_v1` | Canonical provider/tool wire-body bytes | [`canonical-json.md`](canonical-json.md) §3 |
| `provider_response_digest_v1` | Bytes received from the provider/tool | None — raw bytes |
| `client_response_digest_v1` | Bytes handed to the response writer | None — raw bytes |

### 4.1 `dispatch_request_digest_v1` (closure_v2 only)

Hash input: the canonical provider/tool JSON request-body bytes at the moment immediately before HTTP dispatch.

Source of truth: the permit's `binding_request_hash`. The closure record copies this value rather than recomputing it. The closure payload also carries:

```json
"dispatch_request_digest_semantics": "approved_request_body_bytes_at_dispatch_time"
```

### 4.2 `provider_response_digest_v1`

Hash input: the **raw bytes** received by the issuer's dispatch layer from the provider. No canonicalization.

- For non-streaming responses: the response body bytes as received over the HTTP wire.
- For streaming responses: the byte-wise concatenation of all received chunks, in receipt order, hashed at stream-close.
- For mid-stream provider errors: the byte-wise concatenation of received chunks up to the error.

The closure payload carries:

```json
"provider_response_digest_semantics": "provider_bytes_received_by_keel"
```

The semantics label `provider_bytes_received_by_keel` is the literal value emitted by the Keel reference implementation; alternative issuers SHOULD adopt an analogous string identifying their own dispatch layer (e.g., `provider_bytes_received_by_<issuer>`). Verifiers MUST NOT rely on the literal token `keel` in this field.

### 4.3 `client_response_digest_v1`

Hash input: the **raw bytes** of the response body handed to the client response writer by the application server, after any post-provider transformation by the issuer (output filtering, content moderation rewrites, etc.). No canonicalization.

- For non-streaming: the response body bytes as handed to the application server's response writer.
- For streaming: the byte-wise concatenation of all chunks flushed to the response writer, in delivery order.
- For client disconnects: the byte-wise concatenation of chunks delivered before disconnect.

The closure payload carries:

```json
"client_response_digest_semantics": "response_bytes_handed_to_asgi_not_tcp_receipt"
```

The semantics label is **normative**: this digest covers bytes handed to the application server's response writer (in the Keel reference implementation, the ASGI boundary), not bytes confirmed received at the TCP layer. Verifiers MUST NOT make claims about TCP-level delivery from this digest. Alternative issuers using a non-ASGI runtime SHOULD adopt an analogous label naming their delivery boundary.

If no post-provider transformation occurs and the connection completes cleanly without the application server framing the response differently, `provider_response_digest_v1 == client_response_digest_v1`.

## 5. Closure payload (closure_v2)

```json
{
  "binding_version": "closure_v2",
  "permit_id": "uuid",
  "execution_id": "string",
  "correlation_id": "string",
  "provider": "string|null",
  "model": "string|null",
  "dispatch_request_digest_v1": "hex-sha256|null",
  "provider_response_digest_v1": "hex-sha256|null",
  "client_response_digest_v1": "hex-sha256|null",
  "closure_status": "<one of §3>",
  "status_code": 200,
  "provider_response_id": "string|null",
  "dispatch_request_digest_semantics": "approved_request_body_bytes_at_dispatch_time",
  "provider_response_digest_semantics": "<implementation-defined>",
  "client_response_digest_semantics": "response_bytes_handed_to_asgi_not_tcp_receipt",
  "request_created_at": "RFC 3339",
  "started_at": "RFC 3339",
  "completed_at": "RFC 3339",
  "provider_response_received_at": "RFC 3339|null",
  "client_response_delivered_at": "RFC 3339|null",
  "closure_signed_at": "RFC 3339",
  "binding_key_id": "string",
  "usage_reported_at": "RFC 3339|null"
}
```

`usage_reported_at` is OPTIONAL. For `closure_status: "closed"`, `dispatch_request_digest_v1`, `provider_response_digest_v1`, and `client_response_digest_v1` are REQUIRED and non-null. For abnormal closure statuses, `dispatch_request_digest_v1` MAY be null or omitted as described in §3.1. All other listed fields are REQUIRED in `closure_v2`.

## 6. Closure payload (closure_v1)

`closure_v1` differs from `closure_v2` only by the absence of `dispatch_request_digest_v1` and `dispatch_request_digest_semantics`. All other fields and semantics are unchanged. Implementations MUST NOT emit new closures in `closure_v1`; verifiers MUST continue to accept `closure_v1` indefinitely.

## 7. Signing

A closure record is signed with Ed25519 over the SHA-256 of the canonical JSON serialization of the payload (see [`canonical-json.md`](canonical-json.md)).

### 7.1 Signing inputs

```
canonical_hash   = SHA-256(canonical_json(payload))
signed_message   = canonical_hash (UTF-8 hex digest)
signature        = ed25519_sign(signing_key, signed_message)
```

The hex string of `canonical_hash` is what the Ed25519 algorithm signs. Implementations MUST NOT sign the raw JSON bytes directly; this hash-of-canonical-bytes indirection is what allows verifiers to hash the payload they receive and compare to the signed hash.

### 7.2 Sealed envelope

The closure artifact carries:

```json
{
  "payload": { ... },
  "canonical_hash": "hex-sha256",
  "signature": "ed25519:<base64>",
  "binding_key_id": "string"
}
```

- `canonical_hash` MUST equal `SHA-256(canonical_json(payload))`.
- `signature` MUST verify against the public key identified by `binding_key_id` in the issuer's key manifest.
- `binding_key_id` MUST resolve to a key whose `valid_from`/`valid_to` window contains `payload.closure_signed_at`.

A verifier MUST emit `WALK_CLOSURE_SIGNATURE_INVALID` if any of these checks fail.

## 8. Verification rules

A conforming verifier, given a closure artifact and the corresponding permit and key manifest:

1. MUST recompute `canonical_json(payload)` and SHA-256 the result; if the result does not equal `canonical_hash`, fail with `WALK_CLOSURE_SIGNATURE_INVALID`.
2. MUST resolve `binding_key_id` against the key manifest, scoping by `closure_signed_at` and key purpose `permit_binding_signing`.
3. MUST verify the Ed25519 signature against the resolved key; on failure, emit `WALK_CLOSURE_SIGNATURE_INVALID`.
4. MUST validate the digest-presence matrix (§3.1) for the recorded `closure_status`; on violation, emit `WALK_CLOSURE_DIGEST_MISSING`.
5. For `binding_version == "closure_v2"`, MUST compare any non-null `dispatch_request_digest_v1` to the corresponding permit's `binding_request_hash`; on mismatch, emit `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH`. For `closure_status: "closed"`, a missing or null `dispatch_request_digest_v1` MUST emit `WALK_CLOSURE_DIGEST_MISSING`.
6. MUST cross-reference `provider_response_digest_v1` and `client_response_digest_v1` against the corresponding chain events (`provider.response.received` and `client.response.delivered` or their issuer-defined equivalents); on mismatch, emit `WALK_CLOSURE_DIGEST_MISMATCH`.

## 9. Streaming rules

For streaming responses:

- `provider_response_digest_v1` covers all bytes received from the provider/tool, in receipt order, regardless of delivery to the client response writer.
- `client_response_digest_v1` covers all bytes handed to the client response writer, in delivery order.

If the stream is interrupted, both digests reflect partial data — whatever was processed up to the interruption — and `closure_status` MUST be the value that explains the interruption per §3.

Per-chunk digest commitments are out of scope for `closure_v2` and are reserved for a future format version.

## 10. Forbidden claims

A closure record's digests do not constitute proof of TCP-level delivery, network reachability, or end-user reading. The semantics labels in §4 are the normative scope. Marketing or documentation MUST NOT extend claims beyond those scopes.
