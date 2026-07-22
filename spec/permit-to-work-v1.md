# Bounded Work Permits v1

**Status:** additive contract; runtime support is implementation- and
release-gated.

This document defines the public evidence contract for an AI Permit-to-Work:
one non-executable signed Permit that carries the maximum authority for one
identified, bounded job. It does not define a workflow engine, task plan,
schedule, retry graph, progress model, or completion assertion.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in RFC 2119.

## 1. Objects and roles

A bounded Work chain contains:

1. one root Permit with role `work_root` and server-derived action
   `work.authorize`;
2. one signed `work_package_v1` embedded in material covered by the Permit's
   released binding profile;
3. zero or more relational `work_authority_v1` objects whose canonical hashes
   are named by the signed root manifest;
4. zero or more ordinary exact Permits with role `action_child`, each linked to
   exactly one Work authority by `work_binding_v1`;
5. append-only payment-value events for payment authority; and
6. a separately requested `work-chain.v1` evidence pack.

`work_root` is non-executable. An implementation MUST reject provider or tool
dispatch against that role. Only a contained exact child can become executable.

The public strict schemas are:

- [`work-request-v1.schema.json`](../schemas/work-request-v1.schema.json)
- [`work-package-v1.schema.json`](../schemas/work-package-v1.schema.json)
- [`work-authority-v1.schema.json`](../schemas/work-authority-v1.schema.json)
- [`work-value-event-v1.schema.json`](../schemas/work-value-event-v1.schema.json)
- [`work-chain-pack-v1.schema.json`](../schemas/work-chain-pack-v1.schema.json)

## 2. Request and server reconciliation

The caller MAY request bounded payment authority using `work_request_v1`. The
caller does not choose the root role, root action, trusted semantic identity,
customer title, Policy result, or verifier claim.

Before root issuance, the issuer MUST:

- reconcile the authenticated request to a verified principal;
- evaluate current issuance Policy and non-bypassable safety controls;
- intersect requested authority field by field;
- record requested, issued, and excluded authority identifiers;
- deny rather than issue an unusable root when any required authority is
  excluded;
- derive `work.authorize` and `work_root` server-side; and
- bind the exact issued authority-set hash and exact root-review hash.

The beta v1 request schema is deliberately payment-only. Adding a new authority
kind requires its own typed scope/comparator and evidence contract. A generic
JSON authority object is not a conforming extension.

## 3. Signed WorkPackage

The WorkPackage freezes issuance-time facts:

- verified principal;
- Declared purpose and optional job reference;
- exact resource type, identifier, and digest;
- requested-authority-set hash;
- required authority identifiers;
- issued authority identifiers and canonical hashes;
- excluded authority identifiers and reason codes;
- Policy identifier, version, and snapshot hash;
- exact root-review hash; and
- not-before and expiry instants.

Declared purpose is customer-supplied context. It MUST NOT determine the
trusted Permit semantic identity or title.

Implementations compute an authority canonical hash as lowercase SHA-256 over
RFC 8785/JCS bytes of the strict `work_authority_v1` object with
`authority_canonical_hash` omitted. The issued-authority-set hash is lowercase
SHA-256 over RFC 8785/JCS bytes of the array of
`{authority_id, authority_canonical_hash}` records sorted lexicographically by
`authority_id`.

The root manifest hash referenced by `work_binding_v1` is lowercase SHA-256
over the complete strict `work_package_v1` RFC 8785/JCS bytes.

## 4. Work authority and child containment

`work_authority_v1` is authorization, not an expected step. It contains no
ordering, dependency, retry, progress, or completion field.

The initial comparator is
[`work-payment-authority-v1.json`](../comparator_registry/work-payment-authority-v1.json).
Unknown comparator versions or consequential fields are not guessed; the
verifier returns `unverifiable_scope`.

Every linked child MUST remain an ordinary exact `action_child` Permit. Its
signed `work_binding_v1` names:

- the root Permit;
- the authority identifier;
- the authority canonical hash; and
- the signed root manifest hash.

The issuer and verifier MUST fail when signed and relational values differ.
The child request MUST match the authority resource, currency, recipient and
purpose restrictions, time window, use availability, and value availability.

## 5. Policy timing and review

The signed root and issuance snapshot do not mutate when Policy changes.

- New child requests use current issuance Policy and cannot exceed the frozen
  root.
- Final dispatch uses current execution Policy, non-bypassable safety,
  identity/authority liveness, Work-root liveness, authority liveness, approval
  state, and reservation state.
- Tightening MAY block a future child or dispatch without rewriting history.
- Widening MUST NOT expand an issued root.
- Revocation, expiry, authority ending, replacement, and current
  identity/authority state remain live execution gates.

Root approval authorizes the bounded job authority. It does not execute an
action. Exact child requests above their no-additional-review threshold require
their own approval before executable authorization.

## 6. Atomic execution boundary

All operations that can race MUST use one compatible lock order:

1. root Permit;
2. Work authority;
3. child Permit;
4. governed request/reservation.

Inside dispatch ownership, the implementation locks and rechecks those objects,
approval, current execution Policy, non-bypassable safety, and ancestor
liveness, then commits the dispatch-start/boundary record before network
egress. It MUST NOT hold the database transaction open across the provider
call.

If close or revoke commits first, dispatch is denied. If dispatch-start commits
first, a later revoke is recorded after dispatch and MUST NOT be described as
having prevented it.

## 7. Payment-value conservation

`work_value_event_v1` records positive amount magnitudes and an explicit event
type. Events are append-only and strictly ordered per authority. A deterministic
transition identity prevents duplicate reserve, release, dispatch, acceptance,
settlement, unknown-outcome, and reconciliation application.

Authorization, reservation, dispatch, and provider acceptance are different
facts. A `settled` event is valid only with supported settlement evidence. When
settlement cannot be established, the report says `not established` rather
than deriving settlement from an earlier state.

## 8. End authority

Ending Work authority blocks new linked Permits and not-yet-dispatched children
and releases only reservations that are safe to release. It does not assert
that the business job completed, an external action succeeded, or a payment
settled.

## 9. Evidence profile and claims

The default Permit bundle remains unchanged. Work evidence is requested with
the separate `work-chain.v1` profile.

The pack declares its Keel-recorded source, cutoff, checkpoint, and exact
authority/child/value/lifecycle populations. It claims only a scope-faithful
slice of Keel-recorded evidence through that boundary. It does not assert
comprehensive runtime instrumentation or exhaustive real-world activity.

The pack is self-contained: every root Permit, child Permit, lifecycle event,
provider receipt, or settlement reference used by a requested claim MUST
resolve exactly once in the top-level `artifacts` array. The referenced digest
MUST equal the RFC 8785/JCS SHA-256 digest of the embedded artifact payload.
An artifact identifier or digest is not a substitute for the artifact bytes.

The profile registers four claims:

- `permit.work_authority_manifest.v1`
- `permit.work_child_containment.v1`
- `permit_chain.execution_authorized_at_boundary.v1`
- `permit.work_value_conservation.v1`

Those claims are narrower than Policy correctness, provider outcome, job
completion, and settlement. Each external claim requires support in the
released public verifier before a producer may describe it as independently
verified.

## 10. Compatibility

- Existing Permit v1 objects and binding v1-v7 bytes remain unchanged.
- Existing default evidence-bundle bytes remain unchanged.
- Legacy Permits receive no semantic backfill and render generically.
- Cost permits keep their existing vocabulary, routes, and reports.
- Missing historical presentation material affects rendering only; it cannot
  invalidate authorization evidence or change a verifier verdict.
