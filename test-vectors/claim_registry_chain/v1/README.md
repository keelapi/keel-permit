# Claim Registry Chain Conformance Corpus v1

Conformance vectors for resolving two extension chains:

- `verifier-claims.v6` → `verifier-claims.v7` in [`claim_registry/v7.json`](../../../claim_registry/v7.json)
- `keel.permit.universal_verification.v5` → `.v6` in
  [`semantics/permit/universal_verification_v6.json`](../../../semantics/permit/universal_verification_v6.json)

The expected outcomes are derived from
[`spec/verifier-claims-v2.md`](../../../spec/verifier-claims-v2.md), which
states the resolver rules, and
[`spec/verifier-claims-v7.md`](../../../spec/verifier-claims-v7.md), which
narrows them for v7. They are not copied from any verifier's current output.

These are registry- and recipe-composition vectors. They establish that a
resolver reaches the same accept/refuse outcome on the published artifacts.
They are not Action Mapping evidence vectors: no
`keel.mcp_action_mapping_evidence.v1` artifact, schema, or adjudication result
appears here, because that contract is owned by the producer, not by this
repository.

## Running

```sh
python3 test-vectors/claim_registry_chain/v1/reference_executor.py
```

The executor is also run by `make test` and by the repository-integrity job.
Separately, `tools/check_permit_to_x_artifacts.py` checks that this corpus
still describes the artifacts the repository ships, so the corpus cannot drift
into passing its own executor while asserting nothing about the registry.

## Vector model

Every negative is a documented single-delta mutation of a valid parent, in the
style of the `verifier_claims/v0` corpus. A vector names:

- `chain` — which extension chain to resolve;
- `covers` — the refusal category the vector exists to hold;
- `mutation` — `null` for the positive, otherwise one `op` applied to a parsed
  copy of either the `extension` or the `base` artifact;
- `expected` — the `outcome` (`resolved` or `refused`) and its `reason`.

A mutation whose `target` is `base` changes the base bytes, so the extension's
pinned digest is expected to stop matching. That is how "the predecessor
changed underneath a published pin" is expressed without editing the pin.

## Reason ordering

Reasons are ordered so each refusal category is reachable on its own. A claim
renamed onto an inherited name reports `CHAIN_CLAIM_REDEFINED` rather than a
generic set mismatch, and a claim moved between artifact classes reports
`RECIPE_ARTIFACT_CLASS_BINDING_MISMATCH` rather than a claim-set mismatch,
because the class is what decides whether a dispatch claim may be named at all.

## What these vectors do not establish

They do not establish that any Action Mapping evidence artifact is valid, that
upstream dispatch occurred, that a WebAuthn activation ceremony was
independently verified, or that a verifier implements the claims. They
establish only that the published extension chain resolves, and that the
specific corruptions listed in the corpus are refused.
