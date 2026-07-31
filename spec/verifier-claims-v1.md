# Verifier Claims v1

This document defines `verifier-claims.v1`, published in
[`../claim_registry/v1.json`](../claim_registry/v1.json).

The durability, verdict, hash-addressing, semantic-pinning, and no-partial-
fallback rules in [`verifier-claims-v0.md`](verifier-claims-v0.md) continue to
apply with these substitutions:

- `claim_set.version` is `verifier-claims.v1`;
- the registry artifact ID is `keel.verifier_claim_registry.v1`; and
- the registry bytes are `claim_registry/v1.json`.

`verifier-claims.v0` remains frozen and resolvable. A verifier MUST NOT
reinterpret a v0 pack under v1 definitions.

## New and corrected claims

v1 publishes:

- a narrowed `permit.co_signature.v1` definition that makes its shipped
  target-source limitation explicit;
- `permit.co_signature.v2`, bound to a separately supported signed Permit
  decision;
- `permit.co_signature.quorum.v1`; and
- `permit.exact_action.v1`, which cross-binds exact semantic and fact evidence
  to a separately supported signed Permit decision's resource-attribute
  commitment.

Every claim may carry `does_not_establish` vocabulary. Those statements are
part of the claim definition and constrain interpretation; they do not change
the four verdict values.
