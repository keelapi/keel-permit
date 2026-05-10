# Changelog

All notable changes to this specification are documented here.

The spec document follows [Semantic Versioning](https://semver.org/). Wire formats (Permit `v1`, `closure_v1`, `closure_v2`, chain entry `v1`) version independently and are not bumped by spec-document revisions.

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
