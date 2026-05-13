# Permit v1

A **Permit** is a pre-execution decision record. It attests that an action was evaluated against a policy and that a decision was reached. When an allowed action proceeds to provider or tool dispatch, the permit can also be bound to the final provider/tool request body before execution.

A Permit is a self-describing JSON object. It can be persisted, transmitted, and exported in evidence bundles. A Permit JSON object alone is not self-authenticating; cryptographic verification requires the signed export artifacts, closure records where applicable, chain entries where applicable, and the issuer's public keys or key manifest.

This document specifies the **wire format `v1`** of the Permit object.

---

## 1. Conformance keywords

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Permit object

A Permit is a JSON object with the fields defined below. The canonical wire shape is the form serialized into audit export bundles (see [`audit-export-bundle.md`](audit-export-bundle.md)) — that is the artifact verifiers consume. Implementations MAY expose alternative runtime API shapes (e.g., nested metadata envelopes); those are out of scope for this specification.

The schema is closed: validators MUST reject unknown fields. Implementations that need to extend the wire format MUST do so through a future spec version, not by adding ad-hoc fields. See §12.

### 2.1 Required fields

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Globally unique identifier for the permit. Stable for the lifetime of the artifact. |
| `project_id` | UUID | Identifier of the issuing project (or tenancy boundary). The permit is scoped to this project. |
| `decision` | enum | One of `"allow"`, `"deny"`, `"challenge"`. The policy outcome. |
| `reason` | string | Human-readable summary of why the decision was reached. |
| `actions_json` | array | Ordered list of implementation-defined action records. Keel commonly emits `{type, message}` records. MAY be empty. Readers MUST preserve unknown object members. |
| `subject_type` | string | Subject type identifier (e.g., `"user"`, `"agent"`, `"service"`). |
| `subject_id` | string | Subject identifier within `subject_type`. |
| `action_name` | string | The action label evaluated by the policy. |
| `resource_provider` | string | Provider identifier (e.g., `"openai"`, `"anthropic"`). |
| `resource_model` | string | Model identifier within the provider. |
| `estimated_input_tokens` | integer ≥ 0 | Decision-time estimate of input tokens. |
| `estimated_output_tokens` | integer ≥ 0 | Decision-time estimate of output tokens. |
| `request_fingerprint` | hex-SHA-256 | Stable semantic fingerprint of the request after volatile metadata is stripped. This is not the final provider/tool wire-body digest. |
| `idempotency_key` | string | The idempotency key under which this permit was issued. |
| `policy_id` | string | Identifier of the policy that produced the decision. |
| `policy_version` | string | Version stamp of the policy at evaluation time. |
| `created_at` | RFC 3339 timestamp | Permit creation time, UTC. |

### 2.2 Dispatch binding field

| Field | Type | Description |
|---|---|---|
| `binding_request_hash` | hex-SHA-256 \| null | SHA-256 of the canonical provider/tool wire-body bytes bound at dispatch time; see [`canonical-json.md`](canonical-json.md) §3. When non-null, it MUST equal the `dispatch_request_digest_v1` field in the corresponding `closure_v2` record. |

For `decision == "allow"`, `binding_request_hash` MAY be `null` before dispatch, in evaluation-only exports, and for historical rows emitted before dispatch binding was introduced. It MUST be non-null before a provider/tool dispatch is emitted and MUST be non-null for a closed allow execution where provider/tool dispatch occurred.

For `decision == "deny"` and `decision == "challenge"`, `binding_request_hash` MUST be `null`; no provider/tool dispatch is authorized by that permit decision.

### 2.3 Optional fields

| Field | Type | Description |
|---|---|---|
| `parent_permit_id` | UUID | Identifier of the permit that delegated to this one, when the permit is part of a multi-step lineage. |
| `delegation_depth` | integer ≥ 0 | Number of delegation hops from the lineage root. Root permits have `delegation_depth: 0`. |
| `status` | string | Lifecycle status; see §3. |
| `expires_at` | RFC 3339 timestamp | When the permit's authorization window elapses. |
| `decision_details` | object | Structured decision detail; see §2.5. |
| `constraints_json` | object | Decision-time constraints emitted by the policy (rate limits, attribute bounds, parameter caps). Schema is policy-defined; readers MUST treat unknown shapes as opaque. |
| `budgets_json` | object | Decision-time budget envelope at the moment of evaluation. Schema is policy-defined. |
| `routing` | object | Routing decision (provider, model, fallback path) chosen for the bound execution. Schema is implementation-defined. |
| `actual_input_tokens` | integer ≥ 0 | Tokens actually consumed on the input side, post-execution. |
| `actual_output_tokens` | integer ≥ 0 | Tokens actually emitted on the output side, post-execution. |
| `actual_total_tokens` | integer ≥ 0 | Total tokens consumed; typically `actual_input_tokens + actual_output_tokens`. |
| `actual_cost_usd_micros` | integer ≥ 0 | Actual cost in USD micros, post-execution. |
| `resource_operation` | string | Operation within the resource (e.g., `"messages.create"`). |
| `resource_modality` | string | Modality (e.g., `"text"`, `"image"`). |
| `max_output_tokens_requested` | integer ≥ 0 | Output token cap requested at decision time. |
| `workflow_declaration_id` | UUID | Stable identifier of the workflow declaration that governs this permit, when the permit is part of a declared workflow. |
| `workflow_id` | string | Caller-facing workflow identifier associated with `workflow_declaration_id`. |
| `workflow_state_json` | object | Decision-time workflow snapshot; see §5. |

Implementations MAY include additional descriptive fields (usage verification metadata, accounting disposition, condition evaluation, budget envelope summary). Such fields are documented in the JSON Schema in `schemas/permit-v1.schema.json` but are not part of the normative wire-format minimum.

### 2.4 Action object

```json
{
  "type": "string",
  "message": "string"
}
```

When an action object includes `type` or `message`, each value MUST be a non-empty string. Implementations MAY define additional action shapes and action `type` values; readers that do not recognize an action shape or `type` MUST preserve the action verbatim. The JSON Schema intentionally leaves `actions_json` extensible because shipped Keel action payloads are implementation-defined metadata, not verifier-critical cryptographic inputs.

### 2.5 Decision details object

```json
{
  "decision": "allow | deny | challenge",
  "code": "string",
  "reason": "string"
}
```

`decision` MUST equal the top-level `decision` field. `code` is a machine-readable enumerated value implementations MAY extend; `reason` is human-readable. Additional fields are permitted within `decision_details` and MUST be preserved by intermediaries.

## 3. Lifecycle and status

A Permit MAY carry a `status` string. The field is descriptive lifecycle metadata, not the canonical decision. Implementations MAY use additional states; the values in `status` are open-string. Keel has shipped `evaluated` as the initial post-decision status.

| State | Meaning |
|---|---|
| `evaluated` | Decision recorded; no provider/tool dispatch binding has necessarily been sealed. This is a shipped Keel status. |
| `pending` | Generic pre-binding state used by some issuers; Keel readers SHOULD treat it like an unbound evaluated permit unless issuer documentation says otherwise. |
| `bound` | A canonical provider/tool request has been bound to the permit (`binding_request_hash` set). |
| `dispatched` | The bound request was dispatched to the provider/tool. |
| `closed` | A closure record has been written linking the permit to its execution outcome. See [`closure-v2.md`](closure-v2.md). |
| `expired` | The permit's authorization window elapsed without dispatch. |
| `revoked` | The permit was revoked prior to dispatch. |

A reader MUST NOT assume a complete state machine from `status` alone. For a normal dispatched allow execution, the expected progression is `evaluated`/`pending` -> `bound` -> `dispatched` -> `closed`, but exports may observe only some states. `expired` and `revoked` are terminal alternatives reachable from non-`closed` states.

## 4. Decision shape

`decision` MUST be one of:

- `"allow"` — the policy permits the action. A non-null `binding_request_hash` MUST be produced before provider/tool dispatch (§2.2).
- `"deny"` — the policy denies the action. No binding occurs.
- `"challenge"` — the policy requires additional verification before the action may proceed. Implementations MAY define the challenge mechanism; this spec does not.

`display_decision` is a derived presentation field. When the underlying decision is `"deny"` and `decision_details.code` indicates a rate-throttle outcome, `display_decision` MAY be `"throttle"` to distinguish ephemeral throttling from policy denial. `throttle` is not a canonical Permit decision. `display_decision` MUST NOT be used for cryptographic comparisons; verifiers MUST inspect `decision`.

`shadow` is likewise not a canonical Permit decision. Shadow evaluation, shadow policy mode, or shadow routing is implementation metadata and MUST be represented, if emitted at all, outside the `decision` enum.

## 5. Composition with workflow declarations

A workflow declaration is a parent governance object for a declared multi-call run. Permits are child execution events under that declaration. One workflow declaration MAY contain many permits; a permit MAY reference at most one workflow declaration. This relationship is separate from Permit lineage (§8): `parent_permit_id` and `delegation_depth` describe per-call delegation, while `workflow_declaration_id` and `workflow_id` group permits under a declared workflow intent.

When a Permit is evaluated in a workflow context, it carries `workflow_declaration_id`, `workflow_id`, and `workflow_state_json`. `workflow_declaration_id` is the stable evidence join key for the declaration and its amendments. `workflow_id` is the caller-facing handle. `workflow_state_json` is a decision-time snapshot of the workflow state used for the Permit decision. The snapshot includes at least `effective_intent_hash`, `declaration_version_at_decision`, `actual_calls_at_decision`, and `max_calls_at_decision`.

`effective_intent_hash` is defined as `SHA-256(declaration.intent_json ‖ ordered amendments at decision time)`, using the canonical workflow declaration and amendment encodings defined by the workflow evidence schema. Amendments are ordered as applied before the Permit decision. Replay re-derives the effective intent hash from the workflow declaration plus the ordered amendments and verifies that it matches the value carried in `workflow_state_json`.

Workflow declaration and amendment records are sibling evidence artifacts to Permit evidence, not replacements for Permits. A verifier that receives a workflow-aware export verifies the Permit object, then verifies `workflow_state_json` against the corresponding `workflow_declarations` and `workflow_amendments` artifacts. If declared intent, amendment order, or decision-time counters are altered after signing, the projected workflow state becomes tamper-evident through an effective-intent-hash or counter mismatch.

The complete `workflow_intent` schema and runtime design are maintained in `/Users/cmunoz/Desktop/Business/Keel/Product/keel-api/docs/_strategy/WORKFLOW_INTENT_DESIGN_2026-05-12.md`.

## 6. Audit-export form

The Permit object defined in §2 **is** the audit-export form. There is no separate "additional fields" overlay; the canonical wire shape and the verified evidence shape are the same object. Implementations that expose alternative runtime API shapes (e.g., nested metadata envelopes) MUST translate to the §2 shape before serializing into an audit export bundle.

## 7. Identity and subject

The `subject_type` and `subject_id` fields together identify the actor. This spec does not constrain the identity model: `subject_type` is open-ended (`"user"`, `"agent"`, `"service"`, etc.) and the meaning of `subject_id` is determined by `subject_type`. Implementations MAY add issuer-specific identity context fields, but the canonical pair carried by every audit-exported Permit is `(subject_type, subject_id)`.

## 8. Lineage

Multi-step delegation is represented through the `parent_permit_id` and `delegation_depth` fields. The field shape permits at most one parent pointer per Permit.

Keel's persisted constraints enforce the implementation-level minimum: parent links are scoped to the same project and `delegation_depth` is nonnegative. Those database constraints do not by themselves prove acyclicity or that a child depth equals `parent.delegation_depth + 1`.

Spec-level conformance expects emitters and verifiers to treat delegation as an acyclic tree/chain: roots SHOULD have `delegation_depth: 0`, children SHOULD have `delegation_depth == parent.delegation_depth + 1`, and cycles SHOULD be reported as malformed lineage. These are conformance and verification expectations, not a claim that every storage backend enforces them with database constraints.

Implementations MAY enforce a maximum delegation depth. This spec recommends but does not mandate a soft limit.

## 9. Hashing of permits

A Permit object itself is not directly hashed. Hash inputs in this specification are:

- `request_fingerprint` — derived from a canonicalized form of request semantics as described in [`canonical-json.md`](canonical-json.md). Implementations MUST strip volatile observability metadata before computing this digest. This digest is useful for request identity, replay analysis, and idempotency correlation, but it is not a byte-level commitment to the final provider/tool request body.
- `binding_request_hash` — SHA-256 over the bytes produced by `canonical_provider_wire_body(payload)` at dispatch time; see [`canonical-json.md`](canonical-json.md) §3. This is the byte-level commitment to the final provider/tool wire body. It may be null until dispatch binding is sealed.

Implementations MUST NOT modify either digest after the permit is sealed. A change to `binding_request_hash` after sealing MUST be treated as tampering and MUST cause dispatch to abort with a `permit.binding_violation` chain event (issuer-defined event name).

## 10. Verification

A Permit by itself records a decision but does not by itself prove execution and is not self-authenticating as a standalone JSON object. To verify the full pre-execution-to-response-writer loop, a verifier consumes:

1. The Permit object in audit-export form.
2. The corresponding closure record (`closure_v1` or `closure_v2`); see [`closure-v2.md`](closure-v2.md).
3. The chain entries linking the permit to its lifecycle events; see [`chain-entry.md`](chain-entry.md).
4. The export bundle's signature manifest; see [`audit-export-bundle.md`](audit-export-bundle.md).

A verifier MUST emit one of the failure codes in [`failure-codes.md`](failure-codes.md) on any integrity violation.

## 11. Reserved fields

The following field names are reserved for future versions and MUST NOT be repurposed by implementations:

- `permit_format_version` (currently implicit; future revisions MAY make it explicit)
- `signature` (reserved for permit-level signatures in a future spec revision)
- `counter_signature` (reserved for customer counter-signatures in a future spec revision)

## 12. Extensions and future fields

The wire format defined in `schemas/permit-v1.schema.json` is **closed**. Conforming validators MUST reject objects that contain fields not listed in the schema. Reserved field names in §11 are reserved for future versions and MUST NOT appear in current Permit v1 objects; the current schema rejects them with `additionalProperties: false`.

Two extension paths exist:

- **Optional fields documented in `schemas/permit-v1.schema.json` but not in §2.1–§2.3 of this document** are descriptive issuer-defined fields tracked in the schema as the reference implementation evolves. They are valid in conforming Permits but are not part of the normative wire-format minimum. Future spec revisions MAY promote individual fields from schema-only to spec-required.
- **New issuer-required fields** require a new spec version (e.g., a `permit-v2.md` with `permit_format_version: "v2"`). Forking the wire format silently by adding ad-hoc fields breaks verifier conformance and is not permitted.

A reader that performs cryptographic verification MUST use only fields whose canonicalization rules are defined in this spec or a successor spec version.
