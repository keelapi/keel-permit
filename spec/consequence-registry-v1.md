# Consequence Registry v1

## Status

Public contract artifact. This document defines the additive source registry
used to generate exact Permit semantic selectors and human presentation
profiles. It does not define a policy language or authorize an action.

## Purpose

`consequence_registry/v1.json` records the externally meaningful result that a
specific certified tool can cause. One entry binds:

- an exact `consequence_type` and `semantic_id`;
- one or more exact tool names;
- material request fields and trusted fact requirements;
- a canonicalization profile and provider-operation mapping; and
- a non-authorizing `AI Permit-to-X` presentation profile.

The generated semantic registry still applies
`exactly_one_match_else_fallback`. A request that does not match exactly one
eligible entry remains the generic AI Permit. A presentation title cannot make
an unclassified action eligible.

## Trust boundary

Tool names are admissible only when the runtime derives them from a verified
MCP tool contract and an enrolled connector identity. An agent-supplied label,
consequence type, title, provider mapping, risk tag, or trusted fact is never a
selector input.

Every v1 entry therefore requires both `connector_identity` and
`tool_contract`. Runtime producers must also enforce each entry's additional
`trusted_fact_requirements` before issuing the specific semantic binding.

## Generated artifacts

`tools/build_consequence_registries.py` composes the v1 consequences onto the
last immutable semantic and presentation registries. It produces:

- `semantic_registry/v5.json`; and
- `presentation_registry/v4.json`.

The first exact-facts extension preserves those historical bytes and adds:

- `fact_profiles/v4.json`, with one action-specific fact profile per database
  consequence;
- `semantic_registry/v6.json`, which binds those profiles to the existing
  semantic IDs; and
- `presentation_registry/v5.json`, which carries the same human titles against
  the v6 selector bytes.

All five profiles use `schemas/database-exact-facts-v1.schema.json`. Its
conditional branches bind each action to exactly one fact-profile ID and exact
material fields. Cross-action profile substitution is invalid. A runtime may
emit the specific database semantic only after it derives those facts from a
schema-verified, Keel-traced MCP call on the enforced dispatch path.

Historical registry bytes are not rewritten. The generated artifacts and this
source registry are independently schema-validated and pinned by
`artifact-manifests/permit-to-x-v1.json`.
`consequence_registry/test-vectors/v1.json` publishes one exact selection and
title vector for every v1 consequence. Version 2 of those vectors adds valid
authorization facts plus negative action/profile-substitution coverage.

## Additive Payment & Ledger extension

`consequence_registry/v2.json` preserves every v1 consequence byte-for-value
and adds three distinct consequences:

- `payment.invoice.pay.v1` → **AI Permit-to-Pay-Invoice**;
- `ledger.entry.record.v1` → **AI Permit-to-Record-Ledger-Entry**; and
- `payment.reconciliation.record.v1` → **AI Permit-to-Reconcile-Payment**.

The extension generates `fact_profiles/v5.json`,
`semantic_registry/v7.json`, and `presentation_registry/v6.json`. The exact
fact objects validate against
`schemas/payment-ledger-exact-facts-v1.schema.json`, whose mutually exclusive
branches prevent cross-action fields and fact-profile IDs from validating.

An invoice payment requires provider-derived open-invoice state and amount. A
ledger entry requires a version precondition, distinct debit and credit
accounts, and a trusted value-conservation result. A reconciliation requires
bound provider and ledger observations, matching amount and currency, posted
and completed states, and an expected current status of `unreconciled`.
Caller assertions do not satisfy those requirements. Runtime producers must
derive them at the enforced connector or workflow boundary.

Each Payment & Ledger fact object also binds the observation time, expiry, and
digest of a short-lived gateway-signed preflight snapshot. Runtime producers
must verify that snapshot under a credential unavailable to the agent and must
reject it after expiry or when it does not bind the exact action arguments.

`consequence_registry/test-vectors/v3.json` covers both historical database
consequences and the new Payment & Ledger consequences under the latest
registries, including adversarial profile, state, connector, and cross-action
mutations.

## Additive Transactional CX extension

`consequence_registry/v3.json` preserves every v2 consequence byte-for-value
and adds five exact Stripe and HubSpot mutations. It generates fact-profile
registry v6, semantic registry v8, presentation registry v7, and v4 exact
vectors. The action-specific provider mappings, state transitions, factual
limits, and evidence ceilings are normative in
[`transactional-cx-exact-action-contract-v1.md`](transactional-cx-exact-action-contract-v1.md).

The new refund semantic is v2 and matches `operation=call.tools`; the historical
refund v1 semantic continues to match `operation=payment.refund`. This prevents
selector ambiguity and leaves historical pinned artifacts unchanged.

## Claim boundary

A consequence entry and its title establish only the exact authorization
semantic carried by valid signed Permit evidence. They do not by themselves
establish dispatch, provider acceptance, durable provider state, business
correctness, settlement, or effects outside the exact bound target. Each entry
lists its additional `does_not_establish` boundaries.
