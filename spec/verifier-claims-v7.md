# Verifier Claims v7

`verifier-claims.v7` adds four managed-MCP Action Mapping evidence claims to
the immutable v6 registry. Its canonical artifact is
[`claim_registry/v7.json`](../claim_registry/v7.json), and its adjudication
recipe is
[`semantics/permit/universal_verification_v7.json`](../semantics/permit/universal_verification_v7.json).

The released v7 recipe is an additive promotion wrapper over the immutable
candidate
[`universal_verification_v6.json`](../semantics/permit/universal_verification_v6.json).
It pins the exact v6 bytes and preserves the complete v6 `body` byte-for-value
after JSON parsing. The predecessor remains available under its original
identity and candidate status; promotion never rewrites a historical pin.

A verifier that supports recipe v6 does not thereby support recipe v7. It MUST
explicitly allowlist the v7 identity and exact bytes. Until a coordinated public
verifier release does so, evidence packs MUST continue to pin v6 and this
promotion MUST NOT be described as externally supported.

The artifact pins and extends the complete immutable v6 registry rather than
copying it, under the composition rules stated in
[`verifier-claims-v2.md`](verifier-claims-v2.md). Failure to resolve the pinned
base is fatal.

These claims report what a signed artifact binds. They never convert a bound
reference into a verified ceremony, an eligibility into a dispatch, single
consumption into approval-set satisfaction, or an arbitrary mapping into a
certified action contract.

## Applicability

All four claims are conditional on
`enforcement_surface_key: managed_mcp:action_mapping`. They are requested only
for one schema-valid `keel.mcp_action_mapping_evidence.v1` artifact whose
`permit_action_name` is `mcp.tool.call`. The binding claim is always requested;
the remaining three follow from the artifact class.

The target `governance_action_id` MUST NOT appear as the Permit action on any
surface — the evidence block, the signed semantic binding's action name or
operation, or the resolved fact profile's authorized action. The governance
action is what the mapping targets, not what the Permit authorized.

## Artifact classes

Three artifact classes are established at different moments and carry different
authority. The class determines which claims are requested and which relational
material may be present at all.

| Class | Established | Permit evidence | May name a dispatch claim |
|---|---|---|---|
| `execution` | signed into the Permit before either relational claim exists | yes | no |
| `structural_decision` | at a non-approvable hold | no | no |
| `post_claim_execution` | after both relational claims commit | no | yes |

Only `execution` may be adjudicated through a Permit, and for that class the
artifact MUST be covered by the supported signed Permit resource-attributes
commitment. Its approval group MUST name that Permit as the execution Permit,
with a distinct reviewed Permit.

`structural_decision` is a non-approvable hold. It has no Permit, no approval
group, and no resume or dispatch semantics of any kind. It is supplied as
standalone evidence, and a bundle carrying dispatch, bounded-use,
provider-receipt, or allow-decision material alongside it is not a structural
hold.

`post_claim_execution` is separate durable evidence emitted only after both
relational claims commit. It is the only class that may name a dispatch claim.

## Claims

`permit.mcp_action_mapping_binding.v1` establishes the exact source identity,
mapping ID, mapping revision, canonical manifest hash, lifecycle epoch and
state, mapping assurance, target governance-action identity, versioned
challenge basis, and the activation record Keel's decision used. Every other
v7 claim requires it supported.

`permit.mcp_governance_interpretation.v1` establishes that Keel evaluated this
exact request under the named human-approved governance interpretation and
exact review, with the consequence-critical facts bound in the review material.
It requires `challenge_class=action_review` and a complete approval group.

`permit.mcp_structural_hold_evidence.v1` establishes that a
`challenge_class=structural_hold` decision created no approval action, no
execution Permit, and no dispatch claim, and binds the typed absence and
derivation-diagnostic commitments. It does not establish that the unavailable
consequence-critical facts are false rather than unestablished, and carries no
payment, refund, amount, or business-effect interpretation of the held request.

`permit.mcp_dispatch_eligibility.v1` establishes that the request became
*eligible* for dispatch only after the bound action approval was satisfied. It
requires a recorded consumption claim and a dispatch claim acquired for the
same governed request, at the mapping's own lifecycle epoch, on a revision
active at that epoch.

## Individually required bindings

The recipe names each required field individually rather than accepting a
composite. A present composite hash never substitutes for a missing scalar:
`mapping_revision` is a positive integer required in its own right, because the
canonical manifest hash is invariant across a lifecycle transition that moves
the epoch.

`challenge_basis_version` MUST equal `mcp_challenge_basis.v4`. A basis hash is
comparable only within an identical basis version. A superseded version is
`disproved` and an unrecognised one is `unverifiable_scope`, with no fallback,
reconstruction, or cross-version comparison.

`assurance=human_mapped_review_only` requires
`certified_action_contract.state=absent` and
`classification_provenance=human_approved_action_mapping`. A present certified
contract on an arbitrary human mapping is forged evidence and is `disproved` —
never ignored, downgraded, or silently dropped.

## Claim ceiling

`activation.independently_verified` MUST be false. The activation reference is
a binding, not a ceremony verification: independent verification of the
WebAuthn assertion would require a bundle carrying the canonical activation
record and sufficient supporting evidence, and no such bundle reaches the
verifier.

`approval_set_independently_established` MUST be false. The unique consumption
claim establishes single consumption, not which approvals satisfied the frozen
requirement.

No claim in this version establishes that upstream dispatch occurred, occurred
at most once, or did not occur before approval; provider acceptance; downstream
completion or effect; handler semantics; certified action facts or certified
adapter semantics; deployment of the mapped source revision; or absence of
bypass. Current mapping, catalog, or policy configuration is excluded and MUST
NOT be inferred from, or used to rewrite, historical signed evidence.

## Presentation

Derived summaries, Permit-to-X titles, and disclaimer text are non-authorizing
projections. A disclaimer never licenses a positive claim, and a positive claim
is emitted only when the exact supporting artifacts are present.

The interpretation sentence ends at "under exact review, with the
consequence-critical facts bound in the review material". The truncated "under
mandatory review" form is forbidden, because it would be emittable in exactly
the case the specification withholds it.

## Verdicts

The four stable verdict values are unchanged. Missing state is
`insufficient_evidence`; a mismatch is `disproved`; an unsupported contract is
`unverifiable_scope`.
