# Scope Predicate Grammar v1

This document defines the finite predicate grammar used by
`checkpoint_scope_state.v1` sidecars and `export.scope_faithfulness.v1`
export segments.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Grammar

Predicate grammar v1 is finite: AND-of-equality plus range filters only. No OR,
NOT, regex, wildcard, contains, free-text query, script expression, CEL, Rego,
JSONLogic, or policy-language expansion is in v1.

The predicate object has this shape:

```json
{
  "version": "keel.scope_predicate.v1",
  "operator": "and",
  "equals": {},
  "ranges": {}
}
```

`equals` and `ranges` MUST be present even when empty. Unsupported predicate
kind, unsupported grammar version, or unsupported range operator maps to
verdict `unverifiable_scope`, not `disproved`, because the verifier cannot
adjudicate a scope outside this grammar. Malformed v1 predicate syntax maps to
`disproved` when the pack claims v1 but violates the v1 schema.

## 3. Supported Predicate Kinds

| Kind | Predicate type | Value type | Entry field source |
|---|---|---|---|
| `project_id` | equality | UUID string | top-level entry, payload, or export record |
| `permit_id` | equality | string | top-level entry, resource id, payload, or permit record |
| `request_id` | equality | string | payload or permit/execution record |
| `event_type` | equality | string | chain entry `event_type` |
| `category` | equality | string | payload/category field |
| `severity` | equality | string | chain entry `severity` |
| `decision_type` | equality | string | permit decision or payload decision type |
| `policy_id` | equality | string | payload or permit policy id |
| `provider` | equality | string | payload/provider metadata |
| `sequence_number` | range | integer `gte`/`lte` | chain entry `sequence_number` |
| `created_at` | range | RFC 3339 `gte`/`lt` | chain entry `created_at` |
| `occurred_at` | range | RFC 3339 `gte`/`lt` | governance event occurrence time |
| `section` | equality | string | export section/export-type projection |
| `export_type` | equality | string | export type |

`section` and `export_type` are presentation/export-shaping predicate kinds.
They do not give the verifier authority to infer product entitlement.

## 4. Canonical Serialization

The predicate object is serialized with Keel canonical JSON payload rules:
sorted keys, compact separators, UTF-8 bytes, `ensure_ascii=False`, no NaN, and
no volatile-key stripping. This is equivalent canonical JSON for this purpose,
but Keel does not claim full RFC 8785/JCS compliance unless a future version
explicitly does so.

`predicate_value_hash` input is exactly the predicate object, with populated
`equals` and `ranges` maps as needed. The hash is `sha256:` plus lowercase hex
of SHA-256 over the canonical bytes.

## 5. Reserved Namespace

Future predicate kinds MUST live under a reserved namespace before they become
first-class grammar fields. Reserved namespace labels use `keel.<domain>.<name>`
strings in `predicate_basis.reserved_namespaces`. v1 verifiers MUST NOT evaluate
reserved names and MUST return `unverifiable_scope` when a declared predicate
requires one.

**`subject_id` is reserved for a future version, not supported in v1.** Subject identifiers can carry personal or customer-specific information. v1 verifiers MUST return `unverifiable_scope` with `EXPORT_SCOPE_PREDICATE_UNSUPPORTED` if a declared predicate includes `subject_id`. For avoidance: `subject_id` is a reserved first-class predicate kind name in v1; it MUST NOT appear in `predicate_basis.supported_predicate_kinds` or `declared_predicate.equals`. A future grammar version may add `subject_id` only with pinned-semantic rules requiring opaque, stable, non-PII identifiers.

**`model` and `requested_by` are reserved for a future version, not supported in v1.** Both values can be customer-controlled and may expose deployment identifiers or personal information unless normalized before signing. v1 verifiers MUST return `unverifiable_scope` with `EXPORT_SCOPE_PREDICATE_UNSUPPORTED` if a declared predicate includes `model` or `requested_by`. A future grammar version may add them only with pinned-semantic rules requiring opacity-validated model identifiers and opaque, stable, non-PII actor identifiers.

**`incident_id` is reserved for a future version, not supported in v1.** Incident references can be free-form in upstream systems and may expose ticket numbers, names, titles, descriptions, or other sensitive labels. v1 verifiers MUST return `unverifiable_scope` with `EXPORT_SCOPE_PREDICATE_UNSUPPORTED` if a declared predicate includes `incident_id`. A future grammar version may add it only with a pinned-semantic rule requiring an opaque UUID or other opacity-validated incident reference.

## 6. Presentation Policy Is Not Predicate Scope

Plan-tier filtering is NOT a predicate. It is represented by
`presentation_policy`, signed inside `declared_scope`.

Verifier rule: adjudicate "the export is faithful to the declared scope WITH
the declared presentation_policy applied." The verifier never adjudicates "the
policy itself is correct." The signed policy tells the auditor what the customer
redacted from the evidence pack. That is audit-relevant disclosure, not access
control.

## 7. Predicate Field Lookup Hierarchy

The ordered field lookup hierarchy is pinned in `keel.scope_state.merkle.v1`
because it determines which records become membership leaves for a predicate
commitment. Emitters and verifiers MUST apply the exact per-kind order below.
The first present scalar value wins; missing field at all hierarchy levels means
the predicate does not match, not that the predicate is undefined.

| Kind | Ordered lookup chain |
|---|---|
| `project_id` | 1. `entry.project_id`; 2. `entry.payload_json.project_id`; 3. `entry.payload_json.project.id`; 4. `entry.payload_json.export.project_id` |
| `permit_id` | 1. `entry.permit_id`; 2. `entry.resource_id` when `entry.resource_type == "permit"`; 3. `entry.payload_json.permit_id`; 4. `entry.payload_json.permit_uuid`; 5. `entry.payload_json.permit.id` |
| `request_id` | 1. `entry.request_id`; 2. `entry.payload_json.request_id`; 3. `entry.payload_json.execution.request_id`; 4. `entry.payload_json.permit.request_id` |
| `event_type` | 1. `entry.event_type`; 2. `entry.payload_json.event_type` |
| `category` | 1. `entry.category`; 2. `entry.payload_json.category`; 3. `entry.payload_json.classification.category`; 4. `entry.payload_json.policy.category` |
| `severity` | 1. `entry.severity`; 2. `entry.payload_json.severity`; 3. `entry.payload_json.classification.severity`; 4. `entry.payload_json.incident.severity` |
| `decision_type` | 1. `entry.decision_type`; 2. `entry.payload_json.decision_type`; 3. `entry.payload_json.decision.type`; 4. `entry.payload_json.permit.decision_type` |
| `policy_id` | 1. `entry.policy_id`; 2. `entry.payload_json.policy_id`; 3. `entry.payload_json.policy.id`; 4. `entry.payload_json.permit.policy_id` |
| `provider` | 1. `entry.provider`; 2. `entry.payload_json.provider`; 3. `entry.payload_json.model_provider`; 4. `entry.payload_json.metadata.provider`; 5. `entry.payload_json.execution.provider` |
| `sequence_number` | 1. `entry.sequence_number` |
| `created_at` | 1. `entry.created_at` |
| `occurred_at` | 1. `entry.occurred_at`; 2. `entry.payload_json.occurred_at`; 3. `entry.payload_json.event_time`; 4. `entry.payload_json.timestamp`; 5. `entry.created_at` |
| `section` | 1. `entry.section`; 2. `entry.payload_json.section`; 3. `entry.payload_json.export_section`; 4. `entry.payload_json.report.section` |
| `export_type` | 1. `entry.export_type`; 2. `entry.payload_json.export_type`; 3. `entry.payload_json.export.type` |
