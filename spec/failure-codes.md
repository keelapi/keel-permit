# Verification Failure Codes

This document specifies the normative failure-code taxonomy a conforming verifier MUST emit when integrity verification fails. Every failure code corresponds to a specific class of tampering, drift, or malformed artifact.

---

## 1. Conformance keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Code summary

| Code | Layer | Trigger |
|---|---|---|
| `WALK_RECORD_HASH_MISMATCH` | chain entry | An entry's `record_hash` does not equal the SHA-256 of its hash inputs. |
| `WALK_PREV_HASH_DISCONTINUITY` | chain entry | An entry's `prev_hash` does not equal the previous entry's `record_hash` in the same scope. |
| `WALK_SEQUENCE_INVERSION` | chain entry | Two entries within a scope share a `sequence_number`, or as-received order is non-monotonic. |
| `WALK_UNKNOWN_CHAIN_FORMAT` | chain entry | A chain entry carries an unrecognized `chain_format_version`. |
| `WALK_CLOSURE_SIGNATURE_INVALID` | closure | A closure record's Ed25519 signature does not verify, or `canonical_hash` does not match the recomputed hash of `payload`. |
| `WALK_CLOSURE_DIGEST_MISSING` | closure | A digest required by the digest-presence matrix for the recorded `closure_status` is absent. |
| `WALK_CLOSURE_DIGEST_MISMATCH` | closure | A `provider_response_digest_v1` or `client_response_digest_v1` in the closure does not match the corresponding chain event payload. |
| `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH` | closure | A `closure_v2` `dispatch_request_digest_v1` does not equal the permit's `binding_request_hash`. |
| `WALK_UNKNOWN_CLOSURE_FORMAT` | closure | A closure record carries an unrecognized `binding_version`. |

A verifier MUST emit exactly one of these codes per detected violation. Implementations MAY emit multiple codes when a single artifact contains multiple independent violations.

## 3. `WALK_RECORD_HASH_MISMATCH`

**When**: For a chain entry, the value computed by the algorithm in [`chain-entry.md`](chain-entry.md) §3 does not equal the entry's `record_hash` field.

**What it indicates**: at least one of the entry's hash-input fields was modified after sealing — most commonly `event_id`, `event_type`, `payload`-derived fields, `created_at`, `outcome`, `severity`, `prev_hash`, or `sequence_number`. The verifier cannot determine which field changed; it can only identify the entry position.

**Verifier action**: report the entry's `event_id`, `chain_scope`, and `sequence_number`. Do not attempt to repair or skip.

## 4. `WALK_PREV_HASH_DISCONTINUITY`

**When**: For a chain entry with `sequence_number == n+1`, its `prev_hash` field does not equal the `record_hash` of the entry at `sequence_number == n` in the same `chain_scope`.

**What it indicates**: the chain has been broken at this position. Either an entry was deleted, an entry was inserted, the previous entry was modified, or this entry was forged.

**Verifier action**: report the `chain_scope`, the position `n+1`, and the discontinuity boundary. Continued verification beyond a discontinuity is implementation-defined; conservative verifiers SHOULD halt scope-level verification at the first discontinuity.

## 5. `WALK_SEQUENCE_INVERSION`

**When**: Within a `chain_scope`, two entries share the same `sequence_number`, or the as-received entries are not monotonically increasing in `sequence_number`.

**What it indicates**: a reordering, duplication, or insertion attack — or a malformed export.

**Verifier action**: report the `chain_scope` and the conflicting `sequence_number` values. As with `WALK_PREV_HASH_DISCONTINUITY`, conservative verifiers SHOULD halt scope-level verification.

## 6. `WALK_UNKNOWN_CHAIN_FORMAT`

**When**: A chain entry's `chain_format_version` is not recognized by the verifier.

**What it indicates**: either the artifact was produced by a newer issuer version than the verifier supports, or the field has been corrupted.

**Verifier action**: report the entry and the unrecognized version. The verifier MUST NOT attempt to verify the entry under a different version's rules.

## 7. `WALK_CLOSURE_SIGNATURE_INVALID`

**When**: For a closure artifact (closure record + envelope), at least one of:
- The recomputed canonical hash of the payload does not equal the envelope's `canonical_hash`.
- The Ed25519 signature does not verify against the public key resolved from the issuer's key manifest.
- `binding_key_id` does not resolve to a key whose `valid_from`/`valid_to` window contains `closure_signed_at`.

**What it indicates**: the closure record was modified after signing, the wrong key is being applied, or the signature was forged.

**Verifier action**: report the `permit_id`, `binding_key_id`, and the specific sub-failure (hash mismatch, key resolution failure, or signature failure).

## 8. `WALK_CLOSURE_DIGEST_MISSING`

**When**: The `closure_status` requires a digest field per the matrix in [`closure-v2.md`](closure-v2.md) §3.1, and that field is absent.

**What it indicates**: the closure was sealed under a status that demands evidence the closure does not carry. This is either a producer bug or a deliberate omission of evidence.

**Verifier action**: report the `permit_id`, the recorded `closure_status`, and the missing field name(s).

## 9. `WALK_CLOSURE_DIGEST_MISMATCH`

**When**: A `provider_response_digest_v1` or `client_response_digest_v1` in the closure record does not equal the corresponding digest recorded in the chain event payload (e.g., `provider.response.received` or `client.response.delivered`, or the issuer's equivalent).

**What it indicates**: either the closure record or one of the chain events was modified after sealing, or the wrong correlation linked the two artifacts.

**Verifier action**: report the `permit_id`, the digest field name, the closure-side value (truncated for display), and the chain-event-side value (truncated).

## 10. `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH`

**When**: A non-null `closure_v2` record's `dispatch_request_digest_v1` does not equal the corresponding permit's `binding_request_hash`.

**What it indicates**: the request body that was bound to the permit at dispatch time differs from the request body that was committed in the closure. This is the canonical "approved request != executed request" tampering signature.

**Verifier action**: report the `permit_id`, the permit-side `binding_request_hash` (truncated), and the closure-side `dispatch_request_digest_v1` (truncated).

## 11. `WALK_UNKNOWN_CLOSURE_FORMAT`

**When**: A closure record's `binding_version` is not `"closure_v1"` or `"closure_v2"`, or any future format version explicitly registered by this spec.

**What it indicates**: either a newer producer than the verifier supports, or a corrupted artifact.

**Verifier action**: report the `permit_id` and the unrecognized `binding_version`. The verifier MUST NOT attempt to verify under a different format's rules.

## 12. Code stability

The codes in this document are **stable identifiers**. New codes MAY be added by future spec revisions; existing codes MUST NOT be renamed, repurposed, or removed. A code's literal string is part of the public contract for downstream tooling (alerting, dashboards, automated incident response).

## 13. Verifier output format

This spec does not constrain how a verifier surfaces failure codes — JSON, structured logs, exit codes, human-readable text are all permitted. The MUST is that the literal code strings appear unchanged.

A verifier that emits a non-standard code where a standard code applies is non-conforming.
