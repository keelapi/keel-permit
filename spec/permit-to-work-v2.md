# Heterogeneous Multi-Principal Work Permits v2

**Status:** additive contract; runtime support and public verifier support are
release-gated. This contract does not change the payment-only v1 contract.

This document defines a public evidence contract for one bounded job whose
authority may be exercised by multiple verified principals across different
consequential actions. The Work root is an authority container, not an
executable action, payment container, task planner, or proof of real-world
completion.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in RFC 2119.

## 1. Version and compatibility boundary

The following v1 objects remain payment-only and byte-compatible:

- `keel.work_request.v1`;
- `keel.work_package.v1`;
- `keel.work_authority.v1`;
- `keel.work_binding.v1`;
- `keel.work_value_event.v1`; and
- `keel.work_chain_pack.v1` / `work-chain.v1`.

Heterogeneous or delegated Work MUST use the corresponding v2 request,
package, authority, child binding, value event, and evidence-pack contracts.
An implementation MUST NOT add optional v2 fields to a strict v1 object or
select a v2 comparator while labeling the object v1.

Unsupported future versions fail closed as `unverifiable_scope`. A version or
comparator mismatch is disproved.

## 2. One Work, multiple exact lanes

One v2 root MAY carry lanes such as:

- `call.outbound` with `value_binding=none`;
- `calendar.event.create` with `value_binding=none`;
- `payment.execute` with `value_binding=declared_bounded`; and
- `travel.lodging.book` with `value_binding=provider_verified`.

Every lane binds exactly one server-derived `trusted_action`, semantic
identity, resource scope, use limit, time window, value-binding mode, and
optional recipient or purpose commitments. The exact child request MUST match
that lane. A call cannot use a payment lane, one worker cannot use another
worker's lane, and a caller-provided action label cannot select a semantic
profile.

`keel.work_authority.v2` and `work-action-authority.v2` define three modes:

- `none`: the lane MUST NOT reserve or consume customer economic value;
- `declared_bounded`: the exact signed request supplies an amount that MUST fit
  the lane and root limits; and
- `provider_verified`: the amount MUST come from a supported trusted provider
  fact bound to the exact request and exact provider body.

The string `provider_verified` is not evidence. Without a signature-valid,
supported provider fact, the public verdict is `unverifiable_scope` and the
runtime MUST NOT dispatch an action that depends on that amount.

## 3. Customer value is not AI compute spend

`customer_value_pool` is the single finite pool for external economic value
authorized by the job: purchases, deposits, lodging, tickets, and similar
customer-facing monetary effects. It is denominated in one currency because
this contract grants no exchange-rate authority.

Model tokens, inference charges, embeddings, and other AI-compute spend are a
separate Keel authority and ledger domain. They MUST NOT draw down or replenish
`customer_value_pool`. Conversely, customer economic events MUST NOT be booked
to an AI-compute budget. The Work summary explicitly reports this boundary.

When a v2 Work includes any monetary lane, the signed package MUST contain a
finite `customer_value_pool`. Each monetary lane uses the pool currency. New
lanes, delegates, credentials, retries, providers, or child Permits cannot
increase that signed root limit.

Under the root lock, the runtime computes:

```text
remaining = root limit - active reservations - consumed value
```

Reservation and use admission MUST commit atomically. Every root value event
has one monotonic `root_sequence`, previous-event hash, and canonical event
hash so the public verifier can reconstruct one root-wide ledger across lanes.

## 4. Multi-principal delegation

The signed v2 package names the verified root principal and the complete set of
lane delegations. Each delegation binds one authority identifier to one
verified principal and one stable delegation identifier. Absence of a
delegation means only the root principal may exercise the lane.

Each child carries a signed `work_binding.v2` with:

- root Permit identifier and signed package hash;
- authority identifier and canonical authority hash;
- verified exercising principal;
- delegated principal and delegation identifier when applicable; and
- a non-secret digest identifying the authenticated credential used at
  issuance.

The runtime derives identity from the authenticated credential. Payload
`principal_id` values are never authoritative. Database delegation state must
agree with the signed package; disagreement fails closed.

Final dispatch MUST lock and recheck, in this order:

1. root Permit;
2. Work authority;
3. child Permit;
4. delegation and principal;
5. authenticated credential; and
6. governed reservation/request.

It then rechecks root, lane, child, delegation, principal, credential, review,
current Policy, reservation, revocation, expiry, idempotency, and exact
provider-body binding before committing dispatch ownership. Revoking one
delegate blocks that delegate's undispatched children without revoking an
unrelated delegate; root revocation blocks every lane.

## 5. Exact human review

A review freezes the exact request digest, request-review hash, root, lane,
principal, material parameters, and provider-body digest. Approval authorizes
re-evaluation of that frozen request; it is not an allow decision and is not
authority expansion.

Resume MUST NOT call a model to regenerate the request. It MUST compare the
frozen hashes, re-evaluate current Work authority and current Policy, and fail
closed on any mutation or missing material. A human approval cannot bypass
current root value, use, identity, revocation, expiry, or provider-binding
constraints.

`keel.work_review_transition.v1` records both the human outcome and the
post-review authorization result. Therefore an authentic sequence may be:

```text
challenge -> human outcome approve -> re-evaluation deny -> no dispatch
```

The public report MUST distinguish "the human approved this exact request"
from "Keel authorized the action." A final denial after approval is valid
evidence of a denied authorization decision, not a valid Permit to execute.

## 6. Trusted provider facts and effect boundary

`keel.provider_value_fact.v1` is a connector-produced, signed observation. It
binds the project, Work root, lane, child request digest, connector identity,
provider environment, exact provider-body digest, amount, currency, response
digest, observation time, and signing key.

The provider fact establishes only what the supported connector observed. It
does not by itself establish dispatch, acceptance, completion, settlement, or
conversation governance. Provider-specific semantic titles require their own
supported fact profile and presentation profile in addition to Work
containment.

## 7. Evidence completeness and derived summary

`work-chain.v2` is a self-contained root-scoped pack. Its signed scope
commitment covers exact populations for authorities, children, root value
events, lifecycle events, review transitions, and authorization/provider fact
references through one declared checkpoint.

The evidence root carries the exact signed `work_request_v2` preimage as well
as `work_package_v2`. Verifiers recompute the requested authority-set hash and
the complete issued/excluded partition; an opaque request digest is not enough.

All references used by a claim MUST resolve exactly once to embedded bytes and
the referenced digest MUST match the canonical payload. The verifier
reconstructs authority hashes, root-package hash, child containment,
delegation, root value, review transitions, trusted provider facts, and the
scope commitment independently.

The exported JSON contains `summary`, but that summary is non-authorizing. Its
title, text, state, root customer-value totals, lane actions, worker
identifiers, and evidence boundaries are deterministically recomputed by the
public verifier from fields that already passed verification. Caller-supplied
titles or summaries are forbidden. A changed summary makes the artifact
invalid even when the underlying evidence remains intact.

The summary MUST state that AI/model compute spend is governed separately and
MUST NOT imply provider success, completed travel, financial settlement,
calendar attendance, call answer, conversation content, or agreement.

## 8. What a valid report means

`VALID` means the evidence and requested claims verified under the selected
trust mode. It does not mean every child was allowed or dispatched. A valid
pack may contain denials, including a human-approved request that Keel denied
on re-evaluation.

The semantic title `AI Permit-to-Work` describes the bounded root. Verified
child titles describe only the exact authorization each supported semantic
profile earns. Neither title proves real-world execution or outcome.
