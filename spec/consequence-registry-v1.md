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

## Claim boundary

A consequence entry and its title establish only the exact authorization
semantic carried by valid signed Permit evidence. They do not by themselves
establish dispatch, provider acceptance, durable provider state, business
correctness, settlement, or effects outside the exact bound target. Each entry
lists its additional `does_not_establish` boundaries.
