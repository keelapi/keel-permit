# Changelog

All notable changes to this specification are documented here.

The spec document follows [Semantic Versioning](https://semver.org/). Wire formats (Permit `v1`, `closure_v1`, `closure_v2`, chain entry `v1`) version independently and are not bumped by spec-document revisions.

## [1.3.1] — 2026-05-20

Adds promoted scope-faithfulness negative and edge corpus fixtures for the public verifier contract. Permit wire format `v1`, closure formats, chain entry `v1`, claim registry, and semantic artifacts are unchanged.

- Add 19 `scope-faithfulness-*` verifier-claim corpus fixtures covering Step 2 negative and edge adjudication cases.
- Add the key-rotation trust root needed by the promoted scope-faithfulness corpus.
- Add deterministic generation support for the promoted scope-faithfulness negative and edge fixtures.

## [1.3.0] — 2026-05-19

Adds public-repo hardening, schema/spec consistency fixes, and conformance metadata cleanup. Permit wire format `v1`, closure formats, and chain entry `v1` are unchanged.

- Add optional Permit Chain fields to the closed Permit v1 schemas and schema export post-processing, aligning `spec/permit-chain-v1.md` with schema validation.
- Add `schemas/audit-export-manifest.schema.json` for the signed audit-export manifest sidecar.
- Align planned test-vector failure codes with `spec/failure-codes.md` and expand the taxonomy for manifest, signing-key, Permit Chain, closure-orphan, and permit dispatch-binding failures.
- Refresh README presentation with badges, a "why this exists" paragraph, current vs. planned conformance-artifact framing, newer spec links, and released artifact directories.
- Add public hygiene and repo-integrity checks, plus CI wiring.
- Add `SECURITY.md` and `CONTRIBUTING.md`.

## [1.2.0] — 2026-05-19

Adds verifier-claim and pinned-semantics artifacts for reproducible adjudication by the public verifier. Permit `v1`, closure formats, and chain entry `v1` are unchanged.

- Add `claim_registry/v0.json` as the stable verifier-claim registry artifact, including the four claim verdict statuses `supported`, `disproved`, `insufficient_evidence`, and `unverifiable_scope`.
- Add pinned semantic artifacts for verifier dispatch, including hash-addressed semantics used by the public verifier for export manifests, governance chain records, closure formats, checkpoints, workflow evidence, and permit-binding canonical requests.
- Consolidate the golden verifier-claim corpus and semantic-artifact conformance records under `test-vectors/`, including `test-vectors/verifier_claims/` and `test-vectors/semantics/`.
- Add the `permit_chain.delegation_denied_correctly.v1` claim and its permit-chain specification, covering `permit.delegated_denied` adjudication under pinned `authority-envelope.v0` comparator semantics.

## [1.1.0] — 2026-05-13

Adds Permit composition with workflow_intent. Wire format `v1` is unchanged for callers that do not declare workflows; new fields are optional.

- New optional Permit properties accepted in `audit-export-bundle.schema.json`, `audit-export-record.schema.json`, and `permit-v1.schema.json`:
  - `workflow_declaration_id` (UUID): stable identifier of the workflow declaration that governs the Permit, when the Permit is part of a declared workflow.
  - `workflow_id` (string): caller-facing workflow identifier associated with `workflow_declaration_id`.
  - `workflow_state_json` (object): decision-time workflow snapshot. Includes at least `effective_intent_hash`, `declaration_version_at_decision`, `actual_calls_at_decision`, and `max_calls_at_decision`.
- New spec section: "Composition with workflow declarations" describing the parent-workflow-to-child-permit model, `effective_intent_hash` derivation (`SHA-256(declaration.intent_json ‖ ordered amendments at decision time)`), and replay verification semantics.
- Permit lineage (`parent_permit_id`, `delegation_depth`) and workflow grouping (`workflow_declaration_id`) are distinct: lineage describes per-call delegation, workflow grouping describes membership in a declared multi-call run.

### Compatibility

- Existing valid Permits continue to validate unchanged. No required fields added. No fields removed or renamed.
- Validators that previously accepted `additionalProperties: false` schemas now accept Permits with workflow_intent fields without spec exception — the fields are defined in the schema, not ad-hoc extensions.

## [1.0.0] — 2026-05-10

Initial public release. Codifies the wire formats already shipped in the reference implementation as of 2026-05-08.

This release went through a pre-publish accuracy and safety audit. Findings folded into v1.0.0:

- The Permit object is specified as a single closed wire shape (the audit-export form). Earlier drafts described a runtime form in §2 and an additive audit-export form in §5; the two shapes used different field names and confused readers. v1.0.0 collapses them into one normative object.
- Required-field list for the Permit object now includes `id`, `actions_json`, `subject_type`/`subject_id`, `action_name`, `resource_provider`/`resource_model`, `estimated_input_tokens`/`estimated_output_tokens`, `idempotency_key`, `policy_id`/`policy_version`, `request_fingerprint`, and `created_at` — matching what the reference implementation actually emits.
- Closure record digest scoping clarified: only `dispatch_request_digest_v1` uses canonical JSON. `provider_response_digest_v1` and `client_response_digest_v1` hash raw response bytes.
- Permit binding timing clarified: `binding_request_hash` may be null before dispatch and for historical rows, but must be non-null before dispatched/closed allow executions where provider/tool dispatch occurred.
- Lifecycle wording now includes Keel's shipped `evaluated` status and treats `status` as descriptive metadata rather than a complete state machine.
- Delegation lineage wording distinguishes Keel's database-enforced minimums from spec-level verifier expectations for acyclicity and depth.
- Throttle and shadow clarified: neither is a canonical Permit decision; throttle is represented through deny/display metadata and shadow is implementation metadata.
- Chain-entry timestamps MUST be UTC. Non-UTC inputs are explicitly non-conforming.
- Chain-entry continuity rule clarified: no-gap is enforced via `prev_hash` continuity, not via consecutive numbering.
- Chain-entry tamper-evidence claims are scoped to signed bundles, verified manifests, or anchored checkpoints.
- Chain-entry schema tightened: `record_hash`, `prev_hash`, `sequence_number`, and `chain_scope` are non-nullable in audit-export form. `chain_format_version` is required.
- Audit-export-bundle schema tightened: `schema_version` is constrained to `[1, 2]`. A conditional asserts `schema_version == 2` requires `include_chain_entries: true`.
- Closure schema (`schemas/closure-v2.schema.json`) added (hand-maintained, since the closure envelope is built dynamically in the reference implementation rather than from a Pydantic model).
- Closure schema now allows abnormal closure states to omit or null `dispatch_request_digest_v1` while keeping `closure_status: "closed"` strict.
- Canonical JSON wording now describes Keel's canonicalization profile without claiming full RFC 8785/JCS compliance.
- Plan-tier and pricing-redaction developer comments stripped from public schemas.
- Wire format declared closed: `additionalProperties: false` in schemas. Extensions require a new spec version, not ad-hoc fields.

### Wire formats included

- **Permit v1** — pre-execution decision record. Fields, lifecycle, and required vs. optional split per `spec/permit-v1.md`.
- **closure_v1** — execution closure record without `dispatch_request_digest_v1`. Backwards-compatibility format. Verifiers MUST continue to accept indefinitely.
- **closure_v2** — execution closure record with `dispatch_request_digest_v1` cross-referenced to the permit's `binding_request_hash`. Default for new closures.
- **Chain entry v1** — `SHA-256(event_id|event_type|resource_type|resource_id|outcome|severity|created_at|prev_hash|sequence_number)` with pipe separators and microsecond UTC timestamp normalization.
- **Audit export bundle** — `bundle_type: "audit_export_bundle"` with `schema_version: 1` (records only) or `schema_version: 2` (records + chain entries). Both versions remain valid.

### Verification

- Failure code taxonomy: `WALK_RECORD_HASH_MISMATCH`, `WALK_PREV_HASH_DISCONTINUITY`, `WALK_SEQUENCE_INVERSION`, `WALK_UNKNOWN_CHAIN_FORMAT`, `WALK_CLOSURE_SIGNATURE_INVALID`, `WALK_CLOSURE_DIGEST_MISMATCH`, `WALK_CLOSURE_DIGEST_MISSING`, `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH`, `WALK_UNKNOWN_CLOSURE_FORMAT`.
- Canonicalization rules for hashing (Keel canonicalization profile: sorted keys, no insignificant whitespace, `ensure_ascii=False`; not a full RFC 8785/JCS conformance claim).

### Out of scope for v1.0.0

- Per-chunk Merkle stream digests (reserved for a future format version).
- Multi-witness anchoring (see Keel reference implementation roadmap; orthogonal to this spec).
- TEE/HSM signing models (orthogonal to wire format).
- Customer counter-signatures (a future spec revision may introduce dual-signer envelopes).
