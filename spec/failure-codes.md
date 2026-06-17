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
| `WALK_CLOSURE_ORPHAN` | closure | A closure record references a `permit_id` that is not present in the verified evidence scope. |
| `WALK_UNKNOWN_CLOSURE_FORMAT` | closure | A closure record carries an unrecognized `binding_version`. |
| `WALK_PERMIT_DISPATCH_BINDING_MISMATCH` | permit | A permit's `binding_request_hash` does not match the canonical dispatched provider/tool request bytes. |
| `MANIFEST_PARSE_ERROR` | manifest | A required manifest file is not parseable JSON. |
| `MANIFEST_HASH_MISMATCH` | manifest | A manifest `content_hash` does not match the referenced artifact bytes. |
| `MANIFEST_SIGNATURE_MISSING` | manifest | A required manifest signature is absent. |
| `MANIFEST_SIGNATURE_INVALID` | manifest | A manifest signature is present but does not verify against the resolved signing key. |
| `UNKNOWN_SIGNING_KEY` | key manifest | A referenced signing `key_id` cannot be resolved in the applicable trust root or key manifest. |
| `KEY_EXPIRED_AT_SIGNING_TIME` | key manifest | The signing key was not valid at the artifact's recorded signing time. |
| `SIGNING_KEY_REVOKED` | key manifest | The signing key was revoked or marked compromised for the artifact's trust policy. |
| `WALK_PERMIT_CHAIN_ENVELOPE_VIOLATION` | permit chain | A child Permit's `authority_envelope` is not a subset of its parent's under the declared envelope version. |
| `WALK_PERMIT_CHAIN_EXPIRY_VIOLATION` | permit chain | A child Permit's `expires_at` exceeds the parent's. |
| `WALK_PERMIT_CHAIN_UNKNOWN_ENVELOPE_VERSION` | permit chain | The `authority_envelope_version` is not in the verifier's supported set. |
| `WALK_PERMIT_CHAIN_MISSING_COMPARATOR` | permit chain | The comparator registry is not resolvable from the evidence pack. |
| `WALK_PERMIT_CHAIN_ENVELOPE_INCONSISTENT` | permit chain | A Permit's top-level `expires_at` and `authority_envelope.expires_at` disagree. |
| `WALK_PERMIT_CHAIN_RECEIPT_MISSING` | permit chain | A claim required an execution receipt and none is present. |
| `WALK_PERMIT_CHAIN_ANCESTOR_MISSING` | permit chain | Lineage does not reach a root within the supplied pack and no completeness checkpoint covers the ancestor scope. |
| `PERMIT_DECISION_SIGNATURE_INVALID` | permit decision | A permit decision binding signature does not verify under the resolved permit-binding key. |
| `PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH` | permit decision | The issuance-time canonical payload does not hash to `binding_canonical_hash`, or the payload decision does not match the adjudicated decision. |
| `PERMIT_DECISION_KEY_NOT_TRUSTED` | permit decision | No trusted permit-binding key resolves for the decision binding at signing time. |
| `PERMIT_REVOKED_SIGNATURE_INVALID` | permit revoked | A signed `permit.revoked` event signature does not verify under a trusted permit-binding key. |
| `PERMIT_REVOKED_PROJECT_ID_MISMATCH` | permit revoked | A signed `permit.revoked` event is presented for a different `project_id` than the claim scope. |
| `PERMIT_REVOKED_EFFECTIVE_AT_NOT_EQUAL_REVOKED_AT` | permit revoked | A v1 `permit.revoked` event has `effective_at` different from `revoked_at`. |
| `PERMIT_REVOKED_ACTOR_PII_DETECTED` | permit revoked | A revocation actor value is not an opaque UUID or actor identity fields carry PII-shaped data. |
| `PERMIT_OPERATOR_APPROVAL_INVALID` | permit v2 signature | An `operator_approval` signature, payload hash, or envelope shape is invalid. |
| `PERMIT_OPERATOR_APPROVAL_KEY_NOT_TRUSTED` | permit v2 signature | No issuer-organization operator key resolves at the approval signing time. |
| `PERMIT_OPERATOR_APPROVAL_SIGNER_MISMATCH` | permit v2 signature | The `operator_approval.signer_id` does not match the signed `operator_id`. |
| `PERMIT_COUNTER_SIGNATURE_INVALID` | permit v2 signature | A `counter_signature` signature, payload hash, or envelope shape is invalid. |
| `PERMIT_COUNTER_SIGNATURE_KEY_NOT_TRUSTED` | permit v2 signature | No buyer-principal key resolves at the counter-signature signing time. |
| `PERMIT_COUNTER_SIGNATURE_SIGNER_MISMATCH` | permit v2 signature | The `counter_signature.signer_id` does not match the signed `buyer_principal_id`. |
| `PERMIT_COUNTER_SIGNATURE_INTENT_MISMATCH` | permit v2 signature | The envelope `execution_intent_hash` does not match the signed counter-signature payload. |
| `PERMIT_AUDIT_ATTESTATION_INVALID` | permit v2 signature | An `audit_attestation` signature, payload hash, or envelope shape is invalid. |
| `PERMIT_AUDIT_ATTESTATION_KEY_NOT_TRUSTED` | permit v2 signature | No buyer-principal key resolves at the audit-attestation signing time. |
| `PERMIT_AUDIT_ATTESTATION_SIGNER_MISMATCH` | permit v2 signature | The `audit_attestation.signer_id` does not match the signed `buyer_principal_id`. |
| `PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH` | permit v2 signature | The envelope `batch_id` does not match the signed audit-attestation payload. |
| `PAYLOAD_TYPE_MISMATCH` | permit v2 signature | A v2 signature slot carries or signs a `payload_type` outside the slot's registered domain. |
| `EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR` | export scope | A declared scope predicate uses an operator or range shape outside scope-predicate v1. |
| `EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE` | export scope | A bridge, proof, or continuity record satisfies the declared predicate. |

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

## 12. Manifest, key, and profile codes

### 12.1 Manifest and signing-key codes

`MANIFEST_PARSE_ERROR`, `MANIFEST_HASH_MISMATCH`, `MANIFEST_SIGNATURE_MISSING`, `MANIFEST_SIGNATURE_INVALID`, `UNKNOWN_SIGNING_KEY`, `KEY_EXPIRED_AT_SIGNING_TIME`, and `SIGNING_KEY_REVOKED` apply to signed evidence-pack verification as defined in [`audit-export-bundle.md`](audit-export-bundle.md) §5-§6.

**Verifier action**: report the manifest or trust-root artifact, the referenced `key_id` when applicable, and the specific sub-failure. A verifier MUST NOT continue to claim artifact integrity when a required manifest hash, signature, or signing-key validity check fails.

### 12.2 Permit and Permit Chain profile codes

`WALK_PERMIT_DISPATCH_BINDING_MISMATCH` applies when a verifier has the dispatched provider/tool request bytes and the permit's `binding_request_hash` does not match their canonical digest.

`WALK_CLOSURE_ORPHAN` applies when a closure record references a `permit_id` outside the verified evidence scope.

`WALK_PERMIT_CHAIN_*` codes apply to the Permit Chain profile defined in [`permit-chain-v1.md`](permit-chain-v1.md). The profile-specific claim statuses remain `supported`, `disproved`, `insufficient_evidence`, and `unverifiable_scope`; these failure codes identify the concrete failed layer.

**Verifier action**: report the relevant `permit_id`, parent/child boundary, envelope version, or missing comparator/receipt requirement. The verifier MUST NOT silently downgrade a semantic Permit Chain failure into a generic chain-walk failure when the cryptographic chain itself is intact.

## 13. Permit Decision and Revocation Codes

Every code in this section maps to the existing v0 verdict enum: `supported`,
`disproved`, `insufficient_evidence`, or `unverifiable_scope`. No new verdict
values are introduced.

### 13.1 Permit Decision Codes

| Code | Verdict | Trigger |
|---|---|---|
| `PERMIT_DECISION_SIGNATURE_INVALID` | `disproved` | `binding_signature` is present but does not verify over `binding_canonical_hash` under the resolved permit-binding key. |
| `PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH` | `disproved` | The supplied issuance-time canonical payload does not hash to `binding_canonical_hash`, the payload `decision` is not the adjudicated decision, or the pack attempts to substitute later mutable row state for issuance-time evidence. |
| `PERMIT_DECISION_KEY_NOT_TRUSTED` | `insufficient_evidence` | The pack does not supply a trusted permit-binding key active at `binding_issued_at` or the signing time declared for the decision evidence. |

### 13.2 Permit Revoked Codes

| Code | Verdict | Trigger |
|---|---|---|
| `PERMIT_REVOKED_SIGNATURE_INVALID` | `disproved` | The `permit.revoked` payload signature does not verify under a trusted permit-binding key active at `revoked_at`. |
| `PERMIT_REVOKED_PROJECT_ID_MISMATCH` | `disproved` | The signed `project_id` differs from the permit/project scope under adjudication. |
| `PERMIT_REVOKED_EFFECTIVE_AT_NOT_EQUAL_REVOKED_AT` | `disproved` | The v1 event has `effective_at` different from `revoked_at`. Scheduled revocation is not a v1 behavior. |
| `PERMIT_REVOKED_ACTOR_PII_DETECTED` | `disproved` | The actor identity is not an opaque UUID, or the event contains actor email, name, display label, or other PII-shaped identity material. Strict v1 payloads reject these fields; this code is a defensive failure for lax or translated evidence inputs. |

### 13.3 Permit v2 Signature Envelope Codes

Every code in this section maps to the existing v0 verdict enum: `supported`,
`disproved`, `insufficient_evidence`, or `unverifiable_scope`. No new verdict
values are introduced.

| Code | Verdict | Trigger |
|---|---|---|
| `PERMIT_OPERATOR_APPROVAL_INVALID` | `disproved` | The `operator_approval` sub-object is malformed, its `signed_payload_hash` does not equal the canonical operator-approval payload hash, or its Ed25519 signature does not verify. |
| `PERMIT_OPERATOR_APPROVAL_KEY_NOT_TRUSTED` | `insufficient_evidence` | The verifier cannot resolve an issuer-organization operator key for `(account_id, key_id)` that was active at `operator_approval.signed_at`. |
| `PERMIT_OPERATOR_APPROVAL_SIGNER_MISMATCH` | `disproved` | `operator_approval.signer_id` differs from the `operator_id` in the signed operator-approval payload. |
| `PERMIT_OPERATOR_APPROVAL_KEY_STATUS_COMPLETENESS_UNSUPPORTED` | `insufficient_evidence` | The v2 operator-approval claim cannot obtain supported `key.status.completeness.v1` for the exact operator key at `operator_approval.signed_at`. |
| `PERMIT_COUNTER_SIGNATURE_INVALID` | `disproved` | The `counter_signature` sub-object is malformed, its `signed_payload_hash` does not equal the canonical counter-signature payload hash, or its Ed25519 signature does not verify. |
| `PERMIT_COUNTER_SIGNATURE_KEY_NOT_TRUSTED` | `insufficient_evidence` | The verifier cannot resolve a buyer-principal key for `(account_id, key_id)` that was active at `counter_signature.signed_at`. |
| `PERMIT_COUNTER_SIGNATURE_SIGNER_MISMATCH` | `disproved` | `counter_signature.signer_id` differs from the `buyer_principal_id` in the signed counter-signature payload. |
| `PERMIT_COUNTER_SIGNATURE_INTENT_MISMATCH` | `disproved` | `counter_signature.execution_intent_hash` differs from the `execution_intent_hash` in the signed counter-signature payload. |
| `PERMIT_COUNTER_SIGNATURE_KEY_STATUS_COMPLETENESS_UNSUPPORTED` | `insufficient_evidence` | The v2 counter-signature claim cannot obtain supported `key.status.completeness.v1` for the exact buyer-principal key at `counter_signature.signed_at`. |
| `PERMIT_AUDIT_ATTESTATION_INVALID` | `disproved` | The `audit_attestation` sub-object is malformed, its `signed_payload_hash` does not equal the canonical audit-attestation payload hash, or its Ed25519 signature does not verify. |
| `PERMIT_AUDIT_ATTESTATION_KEY_NOT_TRUSTED` | `insufficient_evidence` | The verifier cannot resolve a buyer-principal key for `(account_id, key_id)` that was active at `audit_attestation.signed_at`. |
| `PERMIT_AUDIT_ATTESTATION_SIGNER_MISMATCH` | `disproved` | `audit_attestation.signer_id` differs from the `buyer_principal_id` in the signed audit-attestation payload. |
| `PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH` | `disproved` | `audit_attestation.batch_id` differs from the `batch_id` in the signed audit-attestation payload. |
| `PERMIT_AUDIT_ATTESTATION_KEY_STATUS_COMPLETENESS_UNSUPPORTED` | `insufficient_evidence` | The v2 audit-attestation claim cannot obtain supported `key.status.completeness.v1` for the exact buyer-principal key at `audit_attestation.signed_at`. |
| `PAYLOAD_TYPE_MISMATCH` | `disproved` | The signature slot or signed payload carries a `payload_type` that does not exactly match the registered value for that slot: `permit.operator_approval.v1`, `permit.counter_signature.v1`, or `permit.audit_attestation.v1`. |

## 14. Scope-State and Scope-Faithfulness Codes

Every code in this section maps to the existing v0 verdict enum: `supported`,
`disproved`, `insufficient_evidence`, or `unverifiable_scope`. No new verdict
values are introduced.

### 14.1 Sidecar Codes

| Code | Verdict | Trigger |
|---|---|---|
| `CHECKPOINT_SCOPE_STATE_MISSING` | `insufficient_evidence` | Required sidecar artifact is absent. |
| `CHECKPOINT_SCOPE_STATE_SCHEMA_INVALID` | `disproved` | Present sidecar violates strict v1 schema. |
| `CHECKPOINT_SCOPE_STATE_SIGNATURE_MISSING` | `insufficient_evidence` | Sidecar signature block or signature value is absent. |
| `CHECKPOINT_SCOPE_STATE_SIGNATURE_INVALID` | `disproved` | Ed25519 signature does not verify over canonical sidecar payload. |
| `CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED` | `insufficient_evidence` | `key_id`/purpose cannot be resolved from trust root. |
| `CHECKPOINT_SCOPE_STATE_KEY_NOT_ACTIVE` | `disproved` | Resolved key is outside active window at `signed_at`. |
| `CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING` | `insufficient_evidence` | Referenced checkpoint artifact is absent. |
| `CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH` | `disproved` | Sidecar checkpoint reference does not match verified checkpoint artifact. |
| `CHECKPOINT_SCOPE_STATE_CHAIN_SCOPE_NOT_IN_CHECKPOINT` | `disproved` | Checkpoint does not contain sidecar `chain_scope`. |
| `CHECKPOINT_SCOPE_STATE_LAST_SEQUENCE_AFTER_CHECKPOINT` | `disproved` | Sidecar commitment range exceeds checkpoint head sequence. |
| `CHECKPOINT_SCOPE_STATE_GRAMMAR_UNSUPPORTED` | `unverifiable_scope` | Predicate grammar version is not supported. |
| `CHECKPOINT_SCOPE_STATE_COMMITMENT_PROFILE_UNKNOWN` | `unverifiable_scope` | `commitment_profile` is unknown or not allowlisted. |
| `CHECKPOINT_SCOPE_STATE_PREDICATE_HASH_MISMATCH` | `disproved` | `predicate_value_hash` does not match canonical predicate value. |
| `CHECKPOINT_SCOPE_STATE_COMMITMENT_PREDICATE_DUPLICATE` | `disproved` | Multiple `scope_commitments[]` entries share the same `predicate_value_hash`. |

### 14.2 Export Codes

| Code | Verdict | Trigger |
|---|---|---|
| `EXPORT_SCOPE_DECLARATION_MISSING` | `insufficient_evidence` | Signed export payload has no `scope_faithfulness` block or segment. |
| `EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID` | `disproved` | Present declaration violates strict v1 schema. |
| `EXPORT_SCOPE_PREDICATE_UNSUPPORTED` | `unverifiable_scope` | Predicate grammar or predicate kind is outside v1. |
| `EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR` | `unverifiable_scope` | Predicate uses an operator or range shape outside scope-predicate v1, including `IN`, OR, unsupported range bounds, or an open-ended range. |
| `EXPORT_SCOPE_PREDICATE_MALFORMED` | `disproved` | Predicate claims v1 but is syntactically invalid. |
| `EXPORT_SCOPE_PREDICATE_VIOLATED` | `disproved` | A disclosure record does not satisfy the structured predicate. |
| `EXPORT_PRESENTATION_POLICY_UNSUPPORTED` | `unverifiable_scope` | `presentation_policy.version` or kind is unsupported. |
| `EXPORT_SCOPE_CHAIN_SCOPE_MISMATCH` | `disproved` | Segment fields or records disagree on `chain_scope`. |
| `EXPORT_BOUNDARY_START_MISSING` | `insufficient_evidence` | Start boundary is absent. |
| `EXPORT_BOUNDARY_START_MISMATCH` | `disproved` | Supplied evidence does not match declared start. |
| `EXPORT_BOUNDARY_START_AFTER_END` | `disproved` | Declared start sequence is after declared end sequence. |
| `EXPORT_BOUNDARY_END_MISSING` | `insufficient_evidence` | End boundary is absent. |
| `EXPORT_BOUNDARY_END_NOT_CHECKPOINT` | `disproved` | End boundary does not name a checkpoint boundary. |
| `EXPORT_BOUNDARY_CHECKPOINT_MISMATCH` | `disproved` | Declared end differs from checkpoint/sidecar head. |
| `EXPORT_BOUNDARY_STALE_CHECKPOINT` | `disproved` | Latest-at-export policy is declared and supplied freshness evidence shows a later checkpoint was available. |
| `EXPORT_BOUNDARY_FRESHNESS_EVIDENCE_MISSING` | `insufficient_evidence` | Latest-at-export policy is declared but supporting freshness evidence is absent. |
| `EXPORT_SCOPE_STATE_REFERENCE_MISSING` | `insufficient_evidence` | No sidecar reference is supplied for the segment. |
| `EXPORT_SCOPE_STATE_REFERENCE_MISMATCH` | `disproved` | Reference hash/id/checkpoint does not match resolved sidecar. |
| `EXPORT_RAW_FILTERS_MISSING` | `insufficient_evidence` | Raw canonical filters are absent. |
| `EXPORT_RAW_FILTERS_HASH_MISMATCH` | `disproved` | Raw filters do not hash to the signed `filters_hash`. |
| `EXPORT_CHAIN_PROOF_MISSING` | `insufficient_evidence` | Required chain entries or proof bridge records are absent. |
| `EXPORT_CHAIN_PROOF_DISCONTINUITY` | `disproved` | Supplied chain evidence fails local continuity. |
| `EXPORT_PROOF_BRIDGE_MISCLASSIFIED` | `disproved` | A bridge record is counted as in-scope or a disclosure record is marked bridge-only. |
| `EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE` | `disproved` | A bridge, proof, or continuity record satisfies the declared predicate; the verifier can evaluate the predicate and the evidence contradicts the claimed empty matching set. |
| `EXPORT_SCOPE_COMMITMENT_MISSING` | `insufficient_evidence` | Sidecar has no commitment for declared predicate hash. |
| `EXPORT_SCOPE_CARDINALITY_MISMATCH` | `disproved` | Signed `matching_count` differs from disclosure record count. |
| `EXPORT_SCOPE_MEMBERSHIP_ROOT_MISMATCH` | `disproved` | Recomputed Merkle root differs from signed sidecar root. |
| `EXPORT_SCOPE_RANGE_MISMATCH` | `disproved` | Disclosure min/max sequence differs from signed matching range. |

## 15. Code stability

The codes in this document are **stable identifiers**. New codes MAY be added by future spec revisions; existing codes MUST NOT be renamed, repurposed, or removed. A code's literal string is part of the public contract for downstream tooling (alerting, dashboards, automated incident response).

## 16. Verifier output format

This spec does not constrain how a verifier surfaces failure codes — JSON, structured logs, exit codes, human-readable text are all permitted. The MUST is that the literal code strings appear unchanged.

A verifier that emits a non-standard code where a standard code applies is non-conforming.
