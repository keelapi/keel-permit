# Verifier Claims v0

This document defines the durability invariant and verdict semantics for
`verifier-claims.v0`, published in [`../claim_registry/v0.json`](../claim_registry/v0.json).

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 1. Verdict-durability invariant

> A v0 evidence pack must verify to the same claim verdict on every future public verifier, forever. The verifier must pin comparator, serialization, canonicalization, digest, and claim semantics from the pack itself, never from the verifier build that happens to run later.

## 2. Verdict values

The only verdict values for `verifier-claims.v0` are:

- Missing pack-pinned semantics -> `insufficient_evidence`.
- Unknown pack-pinned semantics -> `unverifiable_scope`.
- Known pack-pinned semantics with invalid evidence -> `disproved`.
- Known pack-pinned semantics with sufficient valid evidence -> `supported`.

## 3. Registry relationship

The claim registry defines stable claim names, assertions, required evidence,
and the allowed verdict enum. It is the source of truth for claim definitions,
not a record of current verifier implementation coverage.

A released claim registry version is immutable. Any change to a claim's
assertion, required evidence, or verdict semantics requires a new registry
version. Historical evidence packs MUST continue to resolve the claim
definitions they pinned when they were produced.

## 4. Pack-pinned semantics

Evidence packs that assert `verifier-claims.v0` claims MUST either inline the
claim registry artifact or hash-address it in the bundle manifest. The same
rule applies to comparator, serialization, canonicalization, and digest
semantics required by a claim. A verifier MUST evaluate the claim against the
semantics pinned by the pack, not against mutable defaults from the verifier
build.

## 5. Pre-publication claim clarifications

For `closure.digest_consistency.v1`, catalog-approved provider/client digest
evidence is either the specific `provider.response.received` and
`client.response.delivered` events, or an `execution.completed` event carrying
the corresponding `provider_response_digest_v1` and
`client_response_digest_v1` fields. This clarification is part of local v0
finalization before publication; after publication, semantic changes require a
new registry version.
