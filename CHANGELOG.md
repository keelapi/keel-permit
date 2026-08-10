# Changelog

All notable changes to this specification are documented here.

The spec document follows [Semantic Versioning](https://semver.org/). Wire formats (Permit `v1`, `closure_v1`, `closure_v2`, chain entry `v1`) version independently and are not bumped by spec-document revisions.

## Unreleased

- Define the human-first AI Permit-to-X artifact and `.keelpermit` package
  inventory without creating a new authorization lifecycle or trust root.
- Require verifier-derived titles, lifecycle fields, evidence boundaries, and
  an end-positioned plain-language summary from verified structured fields.
- Keep denial and pending-review records distinct from issued Permits and keep
  raw canonical bytes, hex, Base64, signatures, and digests in an advanced
  representation layer.

## [1.10.0] — 2026-07-30

- Add `verifier-claims.v2` as a composable, digest-pinned extension of the
  immutable v1 registry.
- Define structured claims for specific Permit type, exact target, material
  request, execution-time validity, revocation, certified enforcement,
  bounded/single use, replay, idempotency, and provider receipt states.
- Add consequence-neutral semantic binding v2 and strict
  `keel.permit_exact/v2` evidence-pack body with exact embedded contract bytes.
- Add fact-profile registry v2 with operative disclosure audiences, retention,
  erasure behavior, and low-entropy privacy safeguards.
- Add signed adapter-certification, deployment-assurance, runtime-enforcement,
  and bounded-use schemas with digest binding, expiry, and revocation.
- Separate provider rejection, acceptance, completion, and external-outcome
  ceilings through a reusable provider-receipt state machine.
- Add the minimum cross-repository behavioral corpus and fail-loud integrity
  checks for every new contract surface.
- Preserve all version-pinned v0/v1 claim, fact-profile, semantic, and evidence
  behavior without silent reinterpretation.

## [1.9.1] — 2026-07-30

- Carry every verifier claim and pinned semantic recipe already implemented by
  keel-verifier into `verifier-claims.v1`, closing release-source parity for
  TSA-chain, temporal authority, edge-revocation, and settlement adjudication.
- Publish the `permit.co_signature.v1` offline target-source limitation and add
  target-bound `permit.co_signature.v2` plus
  `permit.co_signature.quorum.v1`.
- Add `verifier-claims.v1` without reinterpreting frozen v0 evidence packs.
- Define `permit.exact_action.v1` so exact semantic and fact evidence must be
  covered by a separately supported signed Permit decision.
- Add executable v2 WebAuthn vectors, including a valid-assertion false-target
  case, and fail-loud CI validation.
- Add semantic selector registry v3 with an optional, trusted
  `fact_profile_id` association.
- Add `keel.fact_profile_registry.v1` and the first eligible profile,
  `keel.facts.payment_exact.v1`.
- Define privacy-aware per-field disclosure, retention, commitment, and erasure
  posture for bulk exports and exact-permit evidence packs.
- Add the exact payment fact schema and conformance vectors for integer amount
  in minor units, currency, recipient commitments, payment rail, and exact
  request digest.
- Extend the semantic-binding schema additively so a signed Permit can pin the
  fact registry, profile, schema, canonicalization rule, and exact fact digest.
- Define `permit.review_transition.v1` and its signed transition semantics so a
  verifier can link an issuance-time challenge to a later approved or denied
  review outcome without re-issuing the original Permit.

## [1.9.0] — 2026-07-30

- Publish the initial corrected co-signature and exact-action contract set.
- Superseded before downstream consumption by v1.9.1 because the v1 claim
  registry did not yet preserve the full released verifier-claim superset.

## [1.8.0] — 2026-07-21

Adds the contract-first foundation for bounded Work authority and honest
Permit-to-X presentation. Permit wire format `v1`, existing binding versions,
closure formats, default evidence bundles, and cost-permit vocabulary are
unchanged.

- Add strict payment-only Work request, WorkPackage, Work authority,
  payment-value event, semantic-binding, and `work-chain.v1` schemas.
- Add four contract-only Work claim definitions and pinned semantic recipes:
  authority-manifest integrity, exact child containment, execution-boundary
  authorization, and payment-value conservation.
- Add a fail-closed semantic selector registry based on server-owned
  provenance and a separate non-authorizing presentation registry.
- Add admitted Work, Pay, and Generate Text presentations; keep realtime
  generic-qualified as `AI Permit — Realtime session`.
- Preserve generic, unclassified, historical-title-unavailable, and
  cost-permit fallbacks.
- Add positive, spoofing, carve-out, historical-rendering, non-interference,
  schema, population-commitment, and negative Work contract vectors.
- Do not claim runtime producer or public-verifier support from this contract
  alone; those ship in coordinated downstream releases.

## [1.7.0] — 2026-06-24

Adds the R4 budget-ledger verifier-claim contract. Permit wire format `v1`,
Permit binding versions, closure formats, and chain entry `v1` are unchanged.

- Add `quota.reservation_linkage.v1` and `budget.partition_ledger.v1` to
  `claim_registry/v0.json`.
- Add pinned semantic artifacts for quota reservation linkage and budget
  partition ledger replay.
- Define the attestation-grade enum and ordering:
  `keel_self_signed_unanchored < keel_attested_unsigned < signed_identity`.
- Clarify that `keel_attested_unsigned` is anchor-contingent; unanchored
  self-attesting bundles must use `keel_self_signed_unanchored` or withhold the
  quota linkage claim.

## [1.6.0] — 2026-06-17

Documents additive Permit binding v7/c7 support while keeping v6 frozen.

- Add the public v7 canonicalization contract: v7 uses the RFC 8785 substrate and signs the frozen v6 field set plus `authority_chain_digest`, `quota_reservation_id`, `subject_id`, `subject_type`, `account_id`, and `org_id`.
- Preserve v6 as byte-stable/frozen. v7 is additive; historical v6 artifacts continue to verify under the v6 rules.
- Update the Permit v2 schema to admit the v7/c7 signed fields, including `binding_version`, `account_id`, `org_id`, authority-chain digest, quota reservation, and subject fields.
- Clarify that for v7+ Permit v2 slot key lookup, account and registry-partition selection comes from signed permit bytes, never a caller manifest or other unsigned metadata.
- Record v7/c7 support in the public capability inventory and test-vector manifest. These public artifacts ship with the verifier release train and remain gated on ratification before publication.

## [1.5.0] — 2026-06-02

Added `custom_metadata` as designated extension carrier on `AuditExportPermitSource`.

- Added `custom_metadata` as an optional property on `AuditExportPermitSource` in all three schemas (`permit-v1.schema.json`, `audit-export-bundle.schema.json`, `audit-export-record.schema.json`). The outer `AuditExportPermitSource` remains closed (`additionalProperties: false`); `custom_metadata` itself uses `additionalProperties: true` as the escape hatch for additive issuer extensions.
- Reserved key: `shadow_override` under `custom_metadata`, introduced for audit annotation of shadow-overridden dispatches (carries `outcome`, `seam_id`, `rule_action`, `param_signature`, `shadow_decision`, `legacy_decision`, `shadow_reason_code`).
- Updated §2.3 optional fields table and §12 (closed-semantics prose) in `spec/permit-v1.md` to document the closed-with-escape-valve pattern and the `shadow_override` reserved key.
- Backward compatible: validators accepting v1.4.x records remain valid; `custom_metadata` is optional and absent from all existing permits.

## [1.4.1] — 2026-05-22

Promotes the Step 4 verifier adjudication corpus into the canonical public
verifier-claims corpus. Permit wire format `v1`, closure formats, chain entry
`v1`, claim registry `v0`, and pinned semantic artifacts are unchanged.

- Add 17 Step 4 permit-claim corpus fixtures covering signed permit-decision negatives, signed permit-revocation negatives, and scope-faithful absence adjudication negatives/edges for post-revocation dispatch initiation.
- Record dependency verdicts for bridge-record and missing-artifact absence cases so the public corpus captures both the target permit claim result and the supporting scope-state/export-scope adjudication result.
- Keep doctrine language on scope-faithful absence adjudication and avoid native non-membership overclaims.

## [1.4.0] — 2026-05-21

Adds Step 4 claim contracts for signed permit decisions, signed permit
revocations, and scope-faithful absence adjudication for post-revocation
dispatch initiation. Permit wire format `v1`, closure formats, and chain entry
`v1` are unchanged.

- Add Step 4 claim contracts (`permit.decision.v1`, `permit.revoked.v1`, `permit.dispatch_absence_after_revocation.v1`) per multi-model design pass 2026-05-21. Scope-faithful absence adjudication, falsifiability-oriented trust model. Reserved `non_membership_profile` namespace for future SMT/NMT native non-membership. PR 1 of Step 4; emission + adjudication land in PR 2 + PR 3.

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
- Multi-witness anchoring (orthogonal to this spec).
- TEE/HSM signing models (orthogonal to wire format).
- Customer counter-signatures (a future spec revision may introduce dual-signer envelopes).
