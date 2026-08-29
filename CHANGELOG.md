# Changelog

All notable changes to this specification are documented here.

The spec document follows [Semantic Versioning](https://semver.org/). Wire formats (Permit `v1`, `closure_v1`, `closure_v2`, chain entry `v1`) version independently and are not bumped by spec-document revisions.

## Unreleased

- No unreleased changes.

## [1.23.0] — 2026-08-28

### Added

- Publish claim registry `verifier-claims.v7` with four managed-MCP Action
  Mapping evidence claims: `permit.mcp_action_mapping_binding.v1`,
  `permit.mcp_governance_interpretation.v1`,
  `permit.mcp_structural_hold_evidence.v1`, and
  `permit.mcp_dispatch_eligibility.v1`.
- Separate the three artifact classes that carry different authority:
  `execution` is signed into the Permit before either relational claim exists,
  `structural_decision` is non-approvable evidence with no Permit and no resume
  or dispatch semantics, and `post_claim_execution` is durable standalone
  evidence emitted after both relational claims commit. Only
  `post_claim_execution` may name a dispatch claim.
- Publish the `keel.permit.universal_verification.v6` recipe extension, which
  pins `verifier-claims.v7` and requests the claims for the
  `managed_mcp:action_mapping` enforcement surface only.
- Add [`spec/verifier-claims-v7.md`](spec/verifier-claims-v7.md) declaring the
  new claim, verdict, artifact-class, and pack-pinning semantics, as
  [`claim_registry/README.md`](claim_registry/README.md) requires of a new
  registry version.
- Hash-address both new artifacts in the Permit-to-X artifact manifest and
  validate the v6→v7 registry and v5→v6 recipe chains in
  `tools/check_permit_to_x_artifacts.py`.
- Add the `keel.claim_registry_chain_vectors.v1` conformance corpus and its
  offline reference executor, covering both extension chains: a positive
  resolution of each, and refusals for a missing or altered inherited digest, a
  changed predecessor, claim redefinition or duplication, a missing or extra
  Action Mapping claim, a registry/recipe version mismatch, a mutated
  artifact-class mapping, and semantic substitution through `mcp.tool.call` or
  `payment.refund`.
- Correct the README's release-manifest artifact count, which had stayed at the
  v1.20.1 figure across three releases, and recompute it in
  `tools/check_repo_integrity.py` so it cannot drift again.

### Compatibility

- Additive only. No released artifact is rewritten: `claim_registry/v6.json`
  and `semantics/permit/universal_verification_v5.json` are byte-unchanged, and
  v7 extends v6 by pinned SHA-256 digest without redefining any inherited
  claim. The four stable verdict values are unchanged.
- Both new artifacts are byte-identical to the keel-verifier copies they were
  published from, so the specification and the reference verifier resolve the
  same bytes.
- No Permit schema, binding version, semantic registry, fact profile,
  consequence registry, or presentation registry changes. The target
  `governance_action_id` is deliberately not a semantic-registry selector, and
  `permit_action_name` remains `mcp.tool.call`.
- The claims establish what an artifact binds. They do not establish that
  upstream dispatch occurred, provider acceptance, downstream effect, or
  independent verification of the WebAuthn activation ceremony.
- `verifier-claims.v7` is a candidate registry version. The conformance-vector
  requirement in [`claim_registry/README.md`](claim_registry/README.md) is met
  by the new corpus, which covers each added claim's identity, verdict enum,
  evidence ceiling, and artifact-class binding, and the refusals that keep the
  chain failing closed.
- Those vectors are registry- and recipe-composition vectors. Adjudicating a
  `keel.mcp_action_mapping_evidence.v1` artifact is deliberately not vectored
  here: that artifact and its schema are producer-owned, and this repository
  does not vendor them.

## [1.22.0] — 2026-08-21

### Added

- Add provider-neutral, server-controlled exact-fact contracts for
  `call.outbound` and `call.respond` through a Keel action gateway.
- Bind each telephony fact to the authenticated principal, Work root,
  authority lane, exact provider wire body, and exact idempotency request.
- Add a narrowly scoped `AI Permit-to-Respond-to-Voice-Turn` presentation;
  transfer, DTMF, SMS, hangup, consent, and broader conversation governance
  remain explicitly outside that title.

### Compatibility

- Preserve the historical direct Vocal Bridge outbound-call schema and title
  byte-for-byte. The new contracts use additive v22/v19/v21 registries and a
  distinct trusted source kind.

## [1.21.1] — 2026-08-20

- Allow Work value-event v2 evidence to reference either historical
  `keel.provider_value_fact.v1` or the newly published
  `keel.provider_value_fact.v2`. Version 1.21.0 defined the v2 fact but left the
  value-event reference fixed to v1, making genuine v2 evidence structurally
  impossible. All other 1.21.0 contracts and bytes remain unchanged.

Supersedes 1.21.0 for new provider-verified Work evidence. Version 1.21.0
remains published so the correction trail is explicit.

## [1.21.0] — 2026-08-20

### Heterogeneous multi-principal Work

- Define `keel.work_authority.v2` and `work-action-authority.v2` for exact
  action, resource, identity, credential, delegation, time, use-count, and
  value-mode containment across heterogeneous Work lanes.
- Define one finite root customer-economic-value pool shared by every monetary
  lane while keeping AI/model compute authority in a separate, non-fungible
  policy domain.
- Add signed delegation and scoped root, authority, delegation, principal, and
  credential revocation evidence so liveness can be re-evaluated at the final
  pre-effect dispatch boundary.
- Define `none`, `declared_bounded`, and `provider_verified` value binding;
  provider-verified value requires signed, exact provider facts and cannot be
  self-certified by the caller.
- Add the backward-compatible provider-value-fact v2 contract for new
  provider-verified issuance. It binds a code-pinned provider parser and exact
  object commitment to a signed validity window capped at 900 seconds, while
  retaining v1 verification for historical evidence.

### Exact review and independently verifiable evidence

- Bind a frozen request and human review outcome separately from the final
  authorization decision, including approval followed by denial after current
  root authority is re-evaluated.
- Require the exact signed Work request preimage, complete issued/excluded
  partition, root-wide hash-linked value ledger, pre-effect dispatch records,
  and a derived non-authorizing `AI Permit-to-Work` summary.
- Add conformance and mutation vectors for action, principal, delegation,
  value mode, root cap, amount, request, review, dispatch, and summary changes.

### Outbound-call semantic profile

- Register `AI Permit-to-Place-Outbound-Call` for server-controlled telephony
  origination only, with normalized destination commitment and provider wire
  body binding. Raw phone numbers are forbidden from verifier-safe facts.
- Add schemas and registry revisions for the Work v2 and telephony contracts.

### Reusable Keel-controlled action gateways

- Define exact, server-sourced semantic and fact contracts for customer-hosted
  message and calendar gateways behind Keel's credential and dispatch boundary.
- Admit `payment.execute` through the same server-owned gateway boundary by an
  append-only selector registry revision. Historical registry bytes remain
  immutable, the existing payment title and fact profile are unchanged, and
  legacy `action_verb_execute` admission remains supported.

## [1.20.1] — 2026-08-18

- Record the source commit correctly in `release-manifest.json`. `git rev-parse`
  on an annotated tag returns the tag object rather than the commit it points
  at, so the v1.20.0 manifest published `commit` as a tag-object SHA that names
  no commit. The builder now peels with `^{commit}` and rejects anything that
  does not resolve to a commit object.
- Gate the manifest's commit identity in the release workflow, so a manifest
  whose recorded commit disagrees with the tag fails the release rather than
  shipping.

Supersedes 1.20.0, whose bundle and attestation are sound but whose manifest
carries an incorrect `commit` value. 1.20.0 remains published; the correction
trail is more useful than a deleted release.

## [1.20.0] — 2026-08-18

### Release integrity

- Publish deterministic release bundles. Each tag produces
  `keel-permit-<version>.tar.gz` containing the published specification
  distribution, a `release-manifest.json` carrying per-file digests and the
  command to reproduce the bundle, and `SHA256SUMS`. Development tooling is
  excluded through `export-ignore`, so the bundle holds only what a consumer
  needs.
- Build with `git archive`, which is byte-deterministic for a given tree.
  Anyone can rebuild a published release from its tag and compare digests
  without trusting the publisher. A signature attests who built an artifact;
  rebuilding attests what is in it.
- Attest release provenance with Sigstore-backed GitHub artifact attestations
  over the bundle, the manifest, and `SHA256SUMS`, verifiable with
  `gh attestation verify`.
- Verify in CI that a release reproduces from its own published instruction, so
  a release cannot ship an instruction that does not work.
- Classify every distribution member rather than calling all of it normative.
  `release-manifest.json` records `content_classes`: normative specification
  material, conformance artifacts, illustrative examples, draft
  evidence-support mappings, and project documentation.
- Record signing state explicitly. The manifest carries no embedded signature
  and says so, alongside the provenance path that does cover it and the exact
  command to verify.

### Specification

- Document, non-normatively, that `permit-fact-profiles-v1` does not constrain
  salt generation: it requires a salt for low-entropy values but sets no minimum
  length and does not require a CSPRNG, so a conforming v1 issuer may produce a
  commitment that is recoverable by enumeration. The limitation is recorded
  rather than repaired, because `keel.fact_profile_registry.v1` is frozen and
  changing what v1 requires would change the meaning of evidence already issued
  under it. New issuance should use fact-profile v2, where the low-entropy
  disclosure contract is operative and the 128-bit requirement is normative.
- Document in `permit-co-signature-v1` §4.1 that the deterministic Permit-bound
  challenge is a deliberate deviation from typical WebAuthn practice, and that
  the contract therefore does not establish assertion freshness or single use.
- State in `permit-universal-verification-v1` §6 that "certification" names a
  Keel-issued signed artifact and is not a third-party accreditation.

### Repository integrity

- Add `tools/check_pack_integrity.py`, which recomputes all 82 declared
  verifier-claim pack `content_hash` values, extracts every archive, verifies
  the declared member set, and parses every JSON and JSONL member. These
  integrity declarations were previously unenforced.
- Add `tools/check_fact_profile_freeze.py`, which asserts that the v1 registry
  stays free of the v2 low-entropy disclosure contract and that v2 continues to
  carry it, so neither the freeze nor the successor's stronger rule can drift
  unnoticed.
- Declare intentional absence in the conformance corpus through an explicit
  `expected_missing_paths` field rather than inferring it from failure-code
  spelling.

## [1.19.0] — 2026-08-13

- Add compact exact evidence profile `keel.permit_exact/v4`. It preserves v3
  verification semantics while allowing contract pins to omit duplicated
  bytes and resolve strictly by identity, version, and SHA-256 digest against
  an offline verifier's allowlisted historical contracts.
- Make compact, consequence-titled JSON the default downloadable AI
  Permit-to-X artifact; retain `.keelpermit` ZIP packages as legacy-compatible
  verifier inputs.
- Add the edition-pinned `aiuc_1_q3_2026` evidence-support entry to the control
  framework mapping, with the same framing and do-not-claim guardrails already
  used for FedRAMP and PCI DSS, and an explicit guard against transitive
  compliance claims.
- Record AIUC-1 `D004` as an explicit non-mapping: it requires qualified
  third-party assessors at least quarterly, which the project's own conformance
  tests do not satisfy.

## [1.18.0] — 2026-08-13

- Add five provider-exact Transactional CX consequences: Stripe payment
  refund, account credit, period-end cancellation scheduling, pending
  cancellation withdrawal, and HubSpot support-case resolution.
- Publish additive consequence registry v3, semantic registry v8, fact-profile
  registry v6, and presentation registry v7 while preserving every earlier
  registry entry byte-for-value.
- Bind provider environment and API version, short-lived authenticated
  preflight state, exact mutation arguments, and one-use idempotency into each
  CX action's signed authorization facts.
- Distinguish withdrawing a pending cancellation from falsely claiming to
  reinstate an already canceled subscription, and require provider-declared
  `ticketState=CLOSED` metadata rather than trusting a ticket-stage label.
- Close the portfolio contract layer across identity and security, merge and
  deployment, coding workspace, collections, insurance claims, ERP/CRM,
  procurement and accounts payable, commerce and regulated, and Wave 5 breadth
  consequences, covering all 96 portfolio Permit-to-X contracts.

## [1.17.0] — 2026-08-10

- Add three exact Payment & Ledger consequences: paying one provider-verified
  open invoice, posting one version-checked double-entry ledger record, and
  recording one matched payment reconciliation.
- Publish additive consequence registry v2, semantic registry v7, fact-profile
  registry v5, and presentation registry v6 without rewriting the released
  database registry history.
- Require invoice-state preflight, one-use idempotency, distinct balanced
  ledger accounts, provider/ledger observation digests, matched amount and
  currency, and expected-current reconciliation state before a specific
  Payment & Ledger Permit is eligible.
- Bind each exact action to a short-lived gateway-signed preflight snapshot;
  caller-supplied state and expired or argument-mismatched snapshots are not
  trusted authorization facts.

## [1.16.0] — 2026-08-09

- Add schema-validated exact authorization facts for insert, update, delete,
  migration, and dataset-export database consequences.
- Bind each database action to its own fact-profile ID in additive semantic
  registry v6 and presentation registry v5 without rewriting v5/v4 history.
- Reject cross-action fact-profile substitution and require connector,
  tool-contract, exact-target, material-request, and enforced-path facts before
  a database-specific Permit title is eligible for exact evidence.

## [1.15.0] — 2026-08-09

- Add the versioned `keel.consequence_registry.v1` source contract with five
  exact database consequences: insert rows, update rows, delete rows, apply
  migration, and export dataset.
- Record material-field, trusted-fact, canonicalizer, provider-operation, risk,
  and claim-boundary metadata for each consequence.
- Add a deterministic generator that composes those entries onto immutable
  semantic registry v4 and presentation registry v3, producing v5/v4 without
  rewriting released history.
- Require `connector_identity` and `tool_contract` plus action-specific trusted
  facts for every consequence; unknown, overlapping, or untrusted actions stay
  generic and presentation never establishes dispatch or provider success.
- Add `spec/consequence-registry-v1.md`, the registry schema, exact-byte
  artifact-manifest pins, and one published selector/title conformance vector
  per consequence.

## [1.14.0] — 2026-08-09

- Define the human-first AI Permit-to-X artifact and `.keelpermit` package
  inventory without creating a new authorization lifecycle or trust root.
- Require verifier-derived titles, lifecycle fields, evidence boundaries, and
  an end-positioned plain-language summary from verified structured fields.
- Keep denial and pending-review records distinct from issued Permits and keep
  raw canonical bytes, hex, Base64, signatures, and digests in an advanced
  representation layer.

## [1.13.0] — 2026-08-02

- Define conditional issuance-time and dispatch-time Work enforcement regime
  claims, and pin them in universal verification v4 without applying them to
  unrelated Permit types.
- Add historical, tamper, impossible-tuple, off/deny, root/child, and
  current-config exclusion vectors, and make the vectors and new artifacts
  mandatory repository-integrity checks.
- Scope the claim ceiling explicitly: these claims establish the signed
  historical regime record only. They do not establish current project
  configuration, universal implementation correctness, absence outside the
  governed boundary, or external outcome.

## [1.12.0] — 2026-08-02

- Add `permit-enforcement-state-v1`, the issuance-time enforcement snapshot
  carried in `resource_attributes` and therefore already covered by
  `resource_attributes_canonical_hash`. No binding-version bump: `v6` and `v7`
  stay frozen.
- Extend the existing pre-effect dispatch record as
  `runtime-enforcement-proof-v2` rather than introducing a competing contract,
  so one dispatch cannot produce two records that disagree.
- Add `permit-exact-pack-v3`, which accepts either proof version so packs
  spanning the change stay verifiable. Pack v2 stays frozen.
- Keep "issued under", "executed under", and "current availability" as three
  separate facts that are never derived from one another.

## [1.11.0] — 2026-08-01

- Admit `keel.action.generate_text.v1`, `keel.action.payment_refund.v1`, and
  `keel.action.agent_delegate.v1` as `exact_action` semantics in semantic
  registry v4, keeping existing admitted semantics and
  `exactly_one_match_else_fallback` selection unchanged.
- Add fact-profile registry v3 with exact fact profiles for Generate Text,
  Refund, and Delegate, including per-field classification, disclosure tiers,
  retention, and commitment methods.
- Add claim registry v3/v4 with `permit.delegate_child_linkage.v1`,
  `permit.generate_text_exact_request.v1`, and
  `permit.refund_original_payment_bound.v1`, each pinning its predecessor
  registry by SHA-256.
- Add closed schemas for delegate child-linkage and the three exact fact
  profiles, plus consequence-claim and delegate-linkage test vectors.
- Add `tools/check_permit_to_x_artifacts.py` and wire it into the
  `repo-integrity` check.
- Give every new claim an explicit `does_not_establish` list. None of them
  assert provider completion, settlement, funds returned, real-world outcome,
  correctness of generated content, or independent real-world identity behind
  a commitment.

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
