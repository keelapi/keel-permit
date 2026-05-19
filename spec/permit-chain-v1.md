# Permit Chain v1

A **permit chain** is a per-project lineage of Permit objects bound by parent-child references, where each child permit's `authority_envelope` is mechanically constrained to be a subset of its parent's. This document specifies the wire format `v1` of the permit chain extensions and the validity rules a verifier MUST apply when evaluating chain claims.

This profile composes with [`permit-v1.md`](permit-v1.md), [`closure-v2.md`](closure-v2.md), [`chain-entry.md`](chain-entry.md), [`audit-export-bundle.md`](audit-export-bundle.md), [`canonical-json.md`](canonical-json.md), and [`failure-codes.md`](failure-codes.md). Permit Chain uses optional Permit v1 fields defined in [`permit-v1.md`](permit-v1.md) §2.3; deployments that do not use Permit Chains omit those fields.

---

## 1. Conformance keywords

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Overview

A Permit Chain extends Permit v1 with three things:

1. An **authority envelope** — a small set of mechanically comparable fields that bound what a permit is allowed to authorize.
2. A **comparator registry** — versioned semantics declaring how each envelope field is compared (subset, ≤, etc.).
3. **Issuance and execution provenance events** — eight new chain event types appended to the per-project hash chain ([`chain-entry.md`](chain-entry.md)), recording how a permit was issued, delegated, revoked, and executed against.

The result is a verifier-replayable record of bounded delegated authority within a project boundary.

### 2.1 What this profile adds

- `authority_envelope` (top-level on the Permit) — bounded capability set, mechanically comparable.
- `authority_envelope_version` (top-level on the Permit) — discriminator for envelope semantics.
- `actor_ref` (top-level on the Permit) — bring-your-own-identity binding for the subject.
- `usage_limits` (top-level on the Permit) — recorded rivalrous quotas (not conserved in `v1`; see §5.3).
- `policy_version_or_hash` (top-level on the Permit) — content-addressed reference to the resolved policy bundle at issuance time.
- `task_description` (top-level on the Permit) — free-form audit context. **Not part of the comparator input.**
- Eight chain event types under the `permit.*` namespace (§6).
- Five verifier claim types (§10).

### 2.2 What this profile does not specify

- **Cross-project or cross-organization delegation.** All chain semantics in `v1` are intra-project. Federation is out of scope; see §13.
- **Bearer-capability semantics.** A Permit is a recorded artifact, never a portable runtime grant. Authority is granted by runtime check against the event log, not by possession of the permit.
- **Aggregate quota conservation.** `usage_limits` are recorded and individually enforced at the governed boundary, but no reservation ledger conserves them across siblings in `v1`. Two child permits each with `max_calls: 10` MAY collectively exceed a parent with `max_calls: 15` if the implementation does not add reservation semantics.
- **External side-effect completion.** This profile records dispatch-time evidence; it does not specify how to record post-dispatch external completion. Issuers MAY define their own `permit.execution_completed` event, but it is not a `v1` chain event type.
- **Identity issuance or validation.** Subject identity is bound through `actor_ref` (§5.1); the chain proves what was recorded, not that the underlying identity is genuine.

## 3. Authority envelope

The `authority_envelope` is a top-level object on the Permit. Its fields are mechanically comparable under the comparator registry referenced by `authority_envelope_version`.

### 3.1 Required fields (`v0`)

The `order` and `canonicalization` columns are the verbatim identifier strings used in [`../comparator_registry/v0.json`](../comparator_registry/v0.json). Verifiers consume the registry; this table cross-references those identifiers so the spec and the registry never drift. `subset` means child ⊆ parent under set membership; `less_than_or_equal` means child ≤ parent under ordered comparison.

| Field | Type | `order` (per registry) | `canonicalization` (per registry) |
|---|---|---|---|
| `actions` | `set<string>` | `subset` | `sorted_unique_strings` |
| `tools` | `set<string>` | `subset` | `sorted_unique_strings` |
| `providers` | `set<string>` | `subset` | `sorted_unique_strings` |
| `models` | `set<string>` | `subset` | `sorted_unique_strings` |
| `data_classes` | `set<string>` | `subset` | `sorted_unique_strings` |
| `regions` | `set<string>` | `subset` | `sorted_unique_strings` |
| `expires_at` | RFC 3339 timestamp | `less_than_or_equal` | `rfc_3339_utc` |

### 3.2 Hard rules

1. Every envelope field MUST be **non-rivalrous** — its subset/≤ comparator MUST be safe to evaluate without aggregate conservation across siblings. Rivalrous quotas (token caps, call counts, cost ceilings) belong in `usage_limits` (§5.3), not in the envelope.
2. Set members are strings under `v0`. Tool versioning MUST be encoded in-string (`"credit_api@v2"`). Structured set members are reserved for a future envelope version (§13).
3. `data_classes` is a set with subset semantics, not a totally-ordered scalar. Linearly-ordered clearance hierarchies (e.g., `public < internal < confidential`) compile to sets if needed (`{public, internal, confidential}`).
4. `expires_at` participates in envelope comparison. It MUST equal the Permit's top-level `expires_at` if both are present; if they disagree, the verifier MUST emit `WALK_PERMIT_CHAIN_ENVELOPE_INCONSISTENT`.

### 3.3 Authority envelope canonicalization

The `authority_envelope` object is canonicalized using **payload canonicalization** as defined in [`canonical-json.md`](canonical-json.md) §4. Set members MUST be serialized as sorted unique strings. The output is the input to any `authority_envelope_hash` computation.

This profile does NOT introduce a new canonicalization profile. It inherits payload canonicalization from `canonical-json.md` §4 verbatim. Any future divergence from `canonical-json.md` requires a new `authority_envelope_version`, never a silent change.

### 3.4 Authority envelope versioning

The `authority_envelope_version` field MUST be a string from a registered set. The current registered version is `"authority-envelope.v0"`.

A verifier that encounters an unrecognized `authority_envelope_version` MUST return claim status `unverifiable_scope` (§10.6) and emit `WALK_PERMIT_CHAIN_UNKNOWN_ENVELOPE_VERSION` (§11). It MUST NOT attempt to apply a different version's comparator semantics.

## 4. Comparator registry

The comparator registry is a versioned JSON artifact that declares, for each envelope field, its type, order semantics, and canonicalization. It is the single source of truth for how envelope fields are compared.

### 4.1 Registry structure

The registry is a JSON object with the following shape:

```json
{
  "version": "authority-envelope.v0",
  "fields": {
    "actions": {
      "type": "set<string>",
      "order": "subset",
      "canonicalization": "sorted_unique_strings"
    }
  }
}
```

The complete `v0` registry is published at [`../comparator_registry/v0.json`](../comparator_registry/v0.json).

### 4.2 Hash-addressing into the evidence pack

A signed evidence pack that includes a Permit Chain MUST either:

- **Inline** the comparator registry artifact in the bundle, OR
- **Hash-address** the registry by its SHA-256 digest in the bundle manifest (extension to [`audit-export-bundle.md`](audit-export-bundle.md), to be specified in the next manifest revision).

A verifier walking permit-chain claims MUST resolve the registry artifact from the pack. If the registry is neither inline nor resolvable from a hash-addressed reference, the verifier MUST return `insufficient_evidence` and emit `WALK_PERMIT_CHAIN_MISSING_COMPARATOR`.

### 4.3 Versioning

Changing comparator semantics for any field — even adding a new field with a new comparator type — REQUIRES bumping the envelope version. The verifier maintains an explicit allowlist of supported envelope versions and MUST reject anything outside it as `unverifiable_scope`.

## 5. Permit Chain fields on Permit v1

The following top-level fields are OPTIONAL at the Permit v1 level and are valid under the closed Permit v1 schema. Their presence is what makes a Permit part of a Permit Chain.

### 5.1 `actor_ref`

```json
{
  "issuer": "string",
  "subject": "string",
  "display_label": "string"
}
```

| Sub-field | Required | Notes |
|---|---|---|
| `issuer` | yes | Identity-issuer label (e.g., `"entra-agent-id"`, `"project-api-key"`, `"spiffe"`, `"byo-did"`). |
| `subject` | yes | Opaque external identifier within `issuer`. |
| `display_label` | no | Human-readable label for audit display. |

The chain proves that the recorded `actor_ref` is what was issued, not that the underlying identity is genuine. Identity validation is the issuer's responsibility and is out of scope for this profile.

When `actor_ref` is present, the `subject_type` and `subject_id` fields from `permit-v1.md` §2.1 SHOULD reflect the same identity (e.g., `subject_type: "spiffe"`, `subject_id: "spiffe://trust-domain/path"`).

### 5.2 `reason` and `task_description`

Both are open-string audit context fields.

> **Hard rule:** Neither `reason` nor `task_description` participates in `child.authority_envelope ⊆ parent.authority_envelope` comparison. They are recorded for audit display and **MUST NOT** influence the verifier's comparator output. Comparator inputs that are free-form would defeat mechanical verifiability.

### 5.3 `usage_limits`

```json
{
  "max_calls": 10,
  "max_tokens": 100000,
  "estimated_cost_ceiling": "string-or-number"
}
```

Recorded in the Permit. Enforced by the issuer at the governed boundary. **Not conserved across siblings** in `v1`.

The split rule:

- Non-rivalrous capability fields go in `authority_envelope`.
- Rivalrous quotas go in `usage_limits`.

A field whose comparator gives a false sense of safety (because aggregate conservation is not enforced) does not belong in the envelope. See §3.2.

### 5.4 `policy_version_or_hash`

A content-addressed reference to the **resolved** policy bundle at issuance time. The resolved policy bundle is the composed result of project policy + plan defaults + global rules at decision time, NOT a label.

The verifier MUST be able to reconstruct the resolved policy bundle from the evidence pack. Either:

- The resolved policy bundle is inline in the pack, OR
- `policy_version_or_hash` is a SHA-256 digest of the canonical-JSON serialization of the resolved bundle, AND the bundle is hash-addressed in the pack.

A `policy_version_or_hash` value of `"policy_v2"` (a label, not a hash) is **not evidence**. The verifier MUST return `insufficient_evidence` if the resolved policy bundle is not resolvable from the pack.

## 6. Event types

Permit Chain `v1` adds eight chain event types to the per-project hash chain. All are appended via [`chain-entry.md`](chain-entry.md) `v1` rules; this profile does not change chain-entry hashing.

### 6.1 Issuance events

| `event_type` | Triggered when |
|---|---|
| `permit.issued` | A new Permit is issued (root or child). Emitted regardless of `parent_permit_id`. |
| `permit.delegated` | A child Permit is issued from a parent. Emitted IN ADDITION to `permit.issued` when `parent_permit_id` is non-null. |
| `permit.delegated_denied` | An attempted child issuance was rejected (envelope subset violation, expiry violation, or current issuance policy denied). |
| `permit.revoked` | A previously issued Permit is revoked. Append-only and prospective; backdated `revocation.effective_time` is forbidden in `v1`. |

### 6.2 Execution events

| `event_type` | Triggered when |
|---|---|
| `permit.execution_requested` | An execution attempt against a Permit reaches the governed boundary. |
| `permit.execution_allowed` | The execution-validity check (§7.2) passed and dispatch is authorized. |
| `permit.execution_denied` | The execution-validity check failed (any sub-rule). |
| `permit.execution_dispatched` | Dispatch was emitted to the provider/tool. Honest `v1` stops here; this profile does NOT specify a `permit.execution_completed` event because the issuer does not always observe the result boundary. |

### 6.3 Event payload schemas

Event payloads are issuer-defined per `chain-entry.md` §2 (`payload_json`). This profile does not constrain payload schemas beyond requiring that the payload include the relevant `permit_id` and (where applicable) `execution_id` so that a verifier can correlate events with permits and execution receipts.

## 7. Validity rules

### 7.1 Issuance validity

A child Permit is validly issued only if, at issuance time:

1. The parent Permit exists in the **same project**.
2. Any identity checks required by issuance policy succeeded at decision time and are represented in the resolved policy evidence. The issuer does not independently prove the external issuer's identity truth; the chain proves only that the recorded `actor_ref` is what was issued.
3. `child.authority_envelope ⊆ parent.authority_envelope` field-by-field under the declared `authority_envelope_version`.
4. `child.expires_at ≤ parent.expires_at` (when both are present).
5. The current issuance policy permits the issuance.

On success, the issuer MUST emit `permit.issued` for the new permit. If `parent_permit_id` is non-null, the issuer MUST additionally emit `permit.delegated` referencing the parent.

Failing any rule MUST emit `permit.delegated_denied` with a reason code identifying the violation. The chain entry payload SHOULD include enough context for the verifier to evaluate the `delegation_denied_correctly` claim (§10.5).

### 7.2 Execution validity

An execution attempt is valid only if, at execution decision time:

1. The Permit exists.
2. The Permit is unexpired at execution decision time.
3. The Permit was not revoked before execution decision time.
4. Every ancestor Permit exists.
5. Every ancestor Permit was unexpired at execution decision time.
6. Every ancestor Permit was not revoked before execution decision time.
7. `child.authority_envelope ⊆ parent.authority_envelope` along the chain.
8. The current execution policy permits the requested action.
9. An execution receipt (§8) is recorded inside the governed boundary.

When an execution attempt against a Permit reaches the governed boundary, the issuer MUST emit `permit.execution_requested` before applying the validity rules. Failing any rule MUST then emit `permit.execution_denied` with a reason code. Passing all rules MUST emit `permit.execution_allowed`, followed by `permit.execution_dispatched` if dispatch to the provider/tool actually occurs.

### 7.3 Revocation

When the issuer revokes a previously issued Permit, the issuer MUST emit `permit.revoked` with the `permit_id` of the revoked Permit and an `effective_time` (RFC 3339 UTC). Backdated `effective_time` (earlier than the revocation chain entry's `created_at`) is forbidden in `v1`; a verifier MUST treat backdated revocations as malformed.

Revocation events are append-only and prospective. They are the inputs to execution-validity rules 3 and 6 (§7.2). Policy changes do not silently invalidate already-issued authority; only `permit.revoked` does (§7.4).

### 7.4 Hybrid policy semantics

Policy changes are not retroactive.

- Historical issuance is judged under the policy active at issuance time. The recorded `policy_version_or_hash` is the authoritative reference.
- New child issuance is judged under the **current** issuance policy.
- Execution is judged under the **current** execution policy plus ancestor validity (existence, expiry, revocation).
- Policy updates do NOT silently invalidate already-issued authority. To invalidate already-issued authority, emit explicit `permit.revoked` events.

> Policy changes govern future decisions. Revocation governs already-issued authority.

This profile assumes the issuer exposes the current issuance policy and current execution policy as **distinct evaluation seams**. Implementations whose runtime collapses these into a single hook MUST introduce the split before claiming conformance to §7.2.

## 8. Execution receipt

The execution receipt is the single most important event for replayability. It MUST snapshot all decision inputs at execution decision time.

### 8.1 Required fields

```json
{
  "execution_id": "string",
  "permit_id": "uuid",
  "decision_time": "RFC 3339 timestamp",
  "requested_action": "string",
  "requested_tool": "string-or-null",
  "requested_resource_refs": ["string"],
  "ancestor_permit_ids": ["uuid"],
  "authority_envelope_hashes": ["hex-sha256"],
  "policy_version_or_hash": "string-or-hex-sha256",
  "usage_limit_state_hashes": ["hex-sha256"],
  "decision": "allow|deny",
  "reason_code": "string"
}
```

### 8.2 Snapshot semantics

If any decision input is not inline or hash-addressed to something in the pack, the offline verification claim has a hole. This is the discipline rule that determines whether "no Keel API required" is true in practice.

`authority_envelope_hashes` MUST be the array of SHA-256 digests of the canonical-JSON serialization of each ancestor's `authority_envelope` AND the executing permit's `authority_envelope`, in chain order from root to leaf.

`usage_limit_state_hashes` MAY be empty if the decision did not depend on usage-limit state. When non-empty, each hash MUST commit to a usage-limit state snapshot resolvable from the pack.

## 9. Time semantics

```
agent clock        = metadata only, never used for ordering or validity
Keel decision_time = authoritative ordering for replay
TSA time           = external anchoring, not chain ordering
```

Backdated `revocation.effective_time` is forbidden in `v1`. Revocation `effective_time` MUST be monotonic with respect to event log ordering.

## 10. Verifier claim types

A verifier evaluates a declared **claim** against the supplied evidence pack. It is not a pack-validator. The pack is the proof attempt; the claim is the question.

### 10.1 `export_integrity_only`

The pack signature, hash chain integrity, and manifest sufficiency are valid. Does not verify any chain semantics.

**Required artifacts:** signature, hash chain integrity, manifest.

### 10.2 `permit_lineage_internally_consistent`

Chain references are internally correct and envelopes are bounded. Does NOT prove the chain is rooted in a legitimately issued project root.

**Required artifacts:** chain references, envelopes (or hash-addressed envelope artifacts), comparator registry version match.

### 10.3 `permit_lineage_complete_to_root`

Adds to §10.2: lineage reaches a `permit.issued` event with no `parent_permit_id`, the root belongs to `manifest.project_id`, and all ancestor events are inside the pack or covered by a completeness checkpoint.

Execution claims SHOULD require root-completeness, not just internal consistency.

### 10.4 `execution_authorized_at_boundary`

Asks: was a specific execution validly authorized at the governed boundary?

**Required artifacts:** lineage + revocation completeness through `decision_time` + resolved policy bundle + execution receipt + usage-limit evidence (if usage limits affected the decision).

### 10.5 `delegation_denied_correctly`

Asks: was a specific `permit.delegated_denied` event the correct denial under the recorded inputs?

**Required artifacts:** parent envelope + child request + comparator registry + denial reason + chain integrity.

### 10.6 Result statuses

A verifier MUST return exactly one of the following statuses per claim:

| Status | Meaning |
|---|---|
| `supported` | Evidence in the pack supports the claim. |
| `disproved` | Evidence in the pack contradicts the claim. |
| `insufficient_evidence` | One or more required artifacts are missing or not hash-addressed; the verifier MUST enumerate the missing requirements. |
| `unverifiable_scope` | The claim's scope falls outside `manifest.export_scope`, OR the envelope version is unsupported. |

`valid` / `invalid` belongs to lower-level cryptographic primitives (signature check, hash-chain integrity). `supported` / `disproved` is the right vocabulary at the claim layer.

### 10.7 `claim_scope ⊆ export_scope` gate

After schema and signature validation, the verifier's first semantic check MUST be whether `claim_scope` falls within `manifest.export_scope`. If not, the verifier MUST return `unverifiable_scope` immediately — before evaluating any events.

### 10.8 `revocation_status` nuances within `execution_authorized_at_boundary`

The revocation sub-finding has four possible values:

| Sub-status | Meaning |
|---|---|
| `not_revoked_within_complete_scope` | No revocation event present AND completeness manifest covers the relevant scope. |
| `revoked_before_execution` | A `permit.revoked` event with `effective_time ≤ decision_time` is present in the pack. |
| `no_revocation_event_in_supplied_evidence` | No revocation event present, but the pack does not assert completeness for the relevant scope. |
| `insufficient_evidence_to_determine` | Required completeness artifacts are missing. |

Collapsing "no revocation event present" into "not revoked" is the canonical audit overclaim trap. The verifier MUST distinguish the two.

### 10.9 Result shape

```json
{
  "claim_type": "execution_authorized_at_boundary",
  "claim_scope": { "execution_id": "exec_123" },
  "status": "insufficient_evidence",
  "supported_checks": [
    "export_signature_valid",
    "hash_chain_integrity",
    "execution_receipt_present"
  ],
  "missing_requirements": [
    "revocation_completeness_through_decision_time",
    "resolved_policy_bundle_for_policy_hash"
  ],
  "revocation_status": "no_revocation_event_in_supplied_evidence",
  "verifier_version": "keel-verifier-v1",
  "supported_envelope_versions": ["authority-envelope.v0"]
}
```

The output MUST be structured and deterministic. Stable enough that signing or attestation of verifier results is a future option without breaking changes.

## 11. Failure codes

This profile reuses the failure-code taxonomy in [`failure-codes.md`](failure-codes.md) and adds the following codes specific to permit-chain semantics:

| Code | Layer | Trigger |
|---|---|---|
| `WALK_PERMIT_CHAIN_ENVELOPE_VIOLATION` | permit chain | A child Permit's `authority_envelope` is not a subset of its parent's under the declared envelope version. |
| `WALK_PERMIT_CHAIN_EXPIRY_VIOLATION` | permit chain | A child Permit's `expires_at` exceeds the parent's. |
| `WALK_PERMIT_CHAIN_UNKNOWN_ENVELOPE_VERSION` | permit chain | The `authority_envelope_version` is not in the verifier's supported set. |
| `WALK_PERMIT_CHAIN_MISSING_COMPARATOR` | permit chain | The comparator registry is not resolvable from the pack. |
| `WALK_PERMIT_CHAIN_ENVELOPE_INCONSISTENT` | permit chain | A Permit's top-level `expires_at` and `authority_envelope.expires_at` disagree. |
| `WALK_PERMIT_CHAIN_RECEIPT_MISSING` | permit chain | A claim required an execution receipt and none is present. |
| `WALK_PERMIT_CHAIN_ANCESTOR_MISSING` | permit chain | Lineage does not reach a root within the supplied pack and no completeness checkpoint covers the ancestor scope. |

These codes are stable identifiers per `failure-codes.md` §13.

## 12. Reserved field names

The following field names are reserved at the Permit level for future permit-chain versions and MUST NOT be repurposed:

- `authority_envelope_v2`
- `authority_envelope_signature` (reserved for envelope-level signatures in a future revision)
- `delegation_constraints` (reserved for non-envelope structural constraints in a future revision)

## 13. Future versions

The following are explicitly out of scope for `v1` and reserved for future versions:

- Cross-project / cross-organization delegation (federated provenance, two-pack verification, cross-instance identity trust).
- Aggregate quota conservation (reservation ledger semantics for `usage_limits`).
- Structured envelope set members (canonical serialization for non-string set elements).
- A `permit.execution_completed` event (requires the issuer to own or observe the result boundary, which is application-dependent).
- Cascading revocation policies (`v1` is single-rule prospective ancestor invalidation).
- Strict-revalidation policy mode (opt-in mode where ancestors are re-evaluated against current policy at execution time; `v1` is hybrid only).

## 14. References

- [`permit-v1.md`](permit-v1.md) — Permit object
- [`closure-v2.md`](closure-v2.md) — Execution closure record
- [`chain-entry.md`](chain-entry.md) — Tamper-evident chain entry
- [`audit-export-bundle.md`](audit-export-bundle.md) — Evidence bundle format
- [`canonical-json.md`](canonical-json.md) — Canonicalization rules
- [`failure-codes.md`](failure-codes.md) — Verification failure taxonomy
- [`../comparator_registry/v0.json`](../comparator_registry/v0.json) — Authority envelope `v0` comparator registry
- [`../test-vectors/vectors/cat-08-permit-chains/`](../test-vectors/vectors/cat-08-permit-chains/) — Conformance test vectors
- [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) — Conformance keywords
- [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) — Timestamp format
