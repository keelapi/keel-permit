# Verifier Claims v5

`verifier-claims.v5` adds two conditional Work enforcement-regime claims to
the immutable v4 registry. Its canonical artifact is
[`claim_registry/v5.json`](../claim_registry/v5.json), and its adjudication
recipe is [`semantics/permit/universal_verification_v4.json`](../semantics/permit/universal_verification_v4.json).

These claims are historical evidence claims. They report the server-derived
regime recorded in signed Permit bytes at issuance and in a signed pre-effect
runtime proof at dispatch. They never infer the project's current setting.

## Applicability

Both claims are conditional on `enforcement_surface_key: program:work`.
Unrelated exact Permit types do not request either claim. A Work root and each
executable Work child are evaluated independently; a root's issuance state
does not establish a child's issuance or dispatch regime.

## Issuance

`permit.enforcement_regime_at_issuance.v1` requires a schema-valid
`keel.permit_enforcement_state.v1` block covered by the supported signed
resource-attributes commitment. Missing state on a historical Permit is
`insufficient_evidence`, not `disproved`. A signature, commitment, identity, or
closed-tuple mismatch is `disproved`.

## Dispatch

`permit.enforcement_regime_at_dispatch.v1` requires a signature-valid,
identity-matched `keel.runtime_enforcement_proof.v2` persisted from the
pre-effect boundary. A historical v1 proof remains valid evidence for the
claims it originally supported, but the enforcement regime is not recorded;
this new claim therefore returns `insufficient_evidence`. A signature,
identity, schema, or tuple mismatch is `disproved`.

## Claim ceiling

Neither claim establishes that an enforcement implementation was correctly
implemented, that every path to the effect crossed the boundary, or that an
external outcome occurred. Current project configuration is deliberately
excluded from both claims.
