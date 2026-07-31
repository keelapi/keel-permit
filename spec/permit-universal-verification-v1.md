# Permit Universal Verification v1

## 1. Purpose

This contract defines the reusable evidence and claim vocabulary for exact
AI Permit-to-X products. It separates five questions that MUST NOT be collapsed:

1. what consequence and exact facts were authorized;
2. whether the Permit was valid and live at the dispatch boundary;
3. whether a certified enforcement boundary actually governed the request;
4. what the provider reported after dispatch; and
5. what external outcome, if any, the evidence establishes.

An implementation MUST preserve historical claim and fact-profile behavior.
New profiles MUST NOT reinterpret version-pinned evidence issued under older
registries.

## 2. Canonical artifacts

- `claim_registry/v2.json`
- `fact_profiles/v2.json`
- `fact_profiles/v2.schema.json`
- `schemas/permit-semantic-binding-v2.schema.json`
- `schemas/permit-exact-pack-v2.schema.json`
- `schemas/adapter-certification-v1.schema.json`
- `schemas/deployment-assurance-v1.schema.json`
- `schemas/runtime-enforcement-proof-v1.schema.json`
- `schemas/permit-bounded-use-v1.schema.json`
- `schemas/permit-selective-disclosure-v1.schema.json`
- `schemas/provider-receipt-v1.schema.json`
- `semantics/permit/provider_receipt_state_v1.json`

All signed hashes use RFC 8785 canonical JSON and lowercase
`sha256:<64 lowercase hex>` digests.

## 3. Exact-action adjudication

A verifier MUST resolve the semantic selector, fact profile, fact schema, and
claim definitions from the versions and digests pinned by the evidence pack.
It MUST NOT branch on a presentation title.

For an exact-action Permit, the verifier:

1. supports the signed `permit.decision.v1` claim;
2. recomputes the signed resource-attribute commitment;
3. resolves exactly one admitted semantic selector;
4. resolves exactly one fact profile for that semantic;
5. validates the complete facts object against the pinned schema;
6. checks the semantic and fact digests covered by the signed attributes; and
7. emits each required structured claim, including failures.

Adding a fact profile MUST NOT require a change to the generic verifier
dispatch loop. A consequence-specific comparator MAY be registered when the
profile explicitly pins its identifier and digest.

The v2 semantic binding removes v1's closed registry-version and surface
enums. It binds the exact claim registry and universal semantic recipe as well
as the selector and fact contracts. A server-owned issuance adapter remains
responsible for choosing `trusted_source_kind`; accepting that field from the
request would violate admission even if the resulting object passed schema
validation.

## 4. Exact evidence-pack body

`keel.permit_exact/v2` is the strict, consequence-neutral evidence-pack body.
It declares every requested claim and embeds every pinned replay input.
`contract_pins.*.content_base64` carries the exact artifact bytes and
`contract_pins.*.sha256` hashes those decoded bytes; a verifier recomputes the
digest before parsing or using the object.

The signed Permit decision and its committed `resource_attributes_json` remain
the authority source. `permit_receipt` is a comparison projection and MUST NOT
supply a missing type, target, request, or fact. Optional evidence arrays are
present even when empty so missing evidence cannot be confused with a producer
that silently omitted the field.

## 5. Claim separation

The universal claim set distinguishes:

- `permit.type.v1`
- `permit.exact_target.v1`
- `permit.material_request.v1`
- `permit.valid_at_dispatch.v1`
- `permit.revocation_at_dispatch.v1`
- `permit.enforced_at_certified_boundary.v1`
- `permit.bounded_use.v1`
- `permit.single_use.v1`
- `permit.replay_prevented.v1`
- `permit.idempotency_bound.v1`
- `provider.receipt_state.v1`
- `provider.rejected.v1`
- `provider.accepted.v1`
- `provider.completed.v1`

A pack MAY omit evidence for an optional claim, but a verifier MUST still emit
an `insufficient_evidence` or `unverifiable_scope` result when the pack declares
that claim. It MUST NOT silently omit a failed declared claim.

## 6. Certified enforcement

An adapter certification establishes conformance for an exact adapter version
and consequence set. A deployment assurance establishes that a customer
deployment uses that adapter without a known side route around the named
boundary. A runtime enforcement proof binds one Permit and one exact dispatch
to both artifacts.

`permit.enforced_at_certified_boundary.v1` is supportable only when:

- certification and deployment assurance were active at dispatch;
- neither had expired or been revoked;
- their adapter, version, surface, project, and consequence match;
- the runtime proof names the same Permit and exact request digest; and
- the recorded gate result proves the boundary ran before the effect.

A connector MUST NOT self-declare this claim merely by writing
`enforced_by_keel`.

The adapter certification, deployment assurance, runtime enforcement proof,
and bounded-use transition use
`keel.ed25519.sha256_rfc8785.v1`. The signer removes `canonical_hash` and
`signature`, computes `sha256:` plus the lowercase SHA-256 hexadecimal digest
of the remaining RFC 8785 bytes, writes that value as `canonical_hash`, and
signs the UTF-8 bytes of the complete `canonical_hash` string. A verifier
resolves an active trusted key for the artifact-specific purpose at the
artifact time before accepting the signature.

IDs are locators, not bindings. Deployment assurance MUST bind the digest of
the exact adapter certification. Runtime enforcement proof MUST bind the
digests of both the exact adapter certification and deployment assurance.

## 7. Bounded use, replay, and idempotency

The bounded-use record is a monotonic transition from `consumed_before` to
`consumed_after`, with `consumed_after = consumed_before + 1` and
`consumed_after <= maximum_uses`. It binds the Permit, exact request digest,
dispatch identifier, and idempotency-key commitment.

The first transition has `counter_sequence=1`, `consumed_before=0`,
`consumed_after=1`, and no previous-transition digest. Every later transition
increments the sequence and binds the immediately preceding signed transition.
The runtime update MUST be atomic against `(project_id, permit_id)`; a
schema-valid transition alone does not establish that atomicity.

Single-use, replay prevention, idempotency binding, and general bounded use are
distinct claims. Evidence for one MUST NOT be promoted into another.

## 8. Privacy and disclosure

Fact-profile v2 makes disclosure rules operative. Every exact fact declares:

- classification;
- disclosure disposition for `verifier_safe`, `authorized`, and `private`;
- retention class and retention limit;
- erasure behavior; and
- a commitment method.

Low-entropy values such as filenames, paths, names, account references, record
IDs, or email addresses MUST NOT use an unsalted plain hash. They use a
randomized commitment, a keyed commitment, or a tenant-scoped opaque reference
with at least 128 bits of entropy. Cleartext openings are separate,
audience-scoped evidence with an audit reason; they do not change signed
authorization bytes. An exact profile that signs a cleartext value cannot
later describe that value as erased; only a separately stored opening may be
erased while its signed commitment remains.

Erasure MUST NOT rewrite signed evidence. It records an erasure transition and
leaves the original commitment verifiable while the opening becomes
intentionally unavailable.

## 9. Provider receipt states

The universal provider-receipt states are:

- `rejected`
- `accepted`
- `running`
- `completed`
- `failed`
- `rolled_back`
- `outcome_unknown`

`rejected` is terminal for that dispatch attempt. `accepted` and `running` do
not establish completion. `completed` is a provider assertion unless an
independent outcome source is separately verified. A network error or provider
HTTP error MUST NOT establish acceptance; absent authoritative evidence it
produces `outcome_unknown`.

Every provider-receipt claim carries claim-level `does_not_establish`. The
verifier MUST report the strongest supported state and MUST NOT promote
provider acceptance, completion, settlement, deletion, deployment health, or
other external outcomes beyond the supplied evidence.

`provider.receipt_state.v1` validates the receipt and transition. It does not
stand in for the consequence claims. `provider.rejected.v1`,
`provider.accepted.v1`, and `provider.completed.v1` are independently emitted
when declared. A Keel transport observation may establish rejection or
`outcome_unknown`; it MUST NOT establish provider acceptance or completion.

## 10. Compatibility

`verifier-claims.v0`, `verifier-claims.v1`, and
`keel.fact_profile_registry.v1` remain frozen and resolvable. Release gates
MUST run positive and negative historical corpora and fail when a required
artifact or vector is absent.
