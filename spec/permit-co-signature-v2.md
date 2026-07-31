# Permit Co-Signature v2

`permit.co_signature.v2` is the target-bound successor to
`permit.co_signature.v1`. It records a WebAuthn assertion whose challenge is
the canonical hash of a separately verified signed Permit decision.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in RFC 2119.

## 1. Target contract

The target is a `permit.decision.v1` artifact whose `binding_canonical_hash`
and Ed25519 signature have already produced a `supported`
`permit.decision.v1` verifier claim. The target decision MUST also have passed
all binding-version-specific sub-hash checks, including
`resource_attributes_canonical_hash` where the binding version requires it.

The v2 co-signature claim carries only:

- `permit_id`;
- `permit_decision_canonical_hash`;
- co-signer, role, key, custody, and recorded acceptance time; and
- the WebAuthn assertion envelope.

It does not repeat action, resource, modality, or other target fields. Those
facts derive from the separately verified signed decision and its verified
resource-attribute commitment. This removes the unsigned projection seam in
v1.

## 2. Challenge construction

The ceremony challenge is the raw 32-byte value represented by the target
decision's lowercase hexadecimal `binding_canonical_hash`:

```text
base64url_decode(clientDataJSON.challenge)
  == hex_decode(permit.co_signature.v2.permit_decision_canonical_hash)
```

The verifier MUST NOT accept a hash copied only from the co-signature claim or
from an unsigned Permit projection. It MUST compare the field with the
canonical hash of a separately supported `permit.decision.v1` claim for the
same `permit_id`.

## 3. Verification

A conforming verifier:

1. verifies enclosing pack integrity;
2. independently adjudicates the target `permit.decision.v1` claim;
3. requires that decision claim to be `supported`;
4. compares the v2 `permit_id` and `permit_decision_canonical_hash` with the
   supported decision evidence;
5. resolves a trusted co-signer key valid at `signed_at`;
6. applies the v1 WebAuthn byte, type, origin, RP-ID-hash, UP, UV, algorithm,
   and signature checks; and
7. emits `supported` only when every preceding check succeeds.

A valid assertion for a different, also well-formed target is `disproved` with
`CO_SIGNATURE_PERMIT_BINDING_MISMATCH`. Missing or unsupported target-decision
verification is `insufficient_evidence` or `unverifiable_scope` according to
the target claim.

`supported` proves that the registered credential approved or witnessed the
specific signed Permit decision under the verified ceremony constraints. It
does not establish hardware backing, a physical-only credential, independent
identity, notarization, witnessing authority, the correctness of the
underlying decision, execution, or outcome.

## 4. Quorum claim

`permit.co_signature.quorum.v1` composes individually supported v2 claims
against one `require_co_signature` requirement. Its evidence shape is
[`permit-co-signature-quorum-v1.schema.json`](../schemas/permit-co-signature-quorum-v1.schema.json).

Before counting signers, a verifier MUST:

1. require a supported target `permit.decision.v1`;
2. require that the RFC 8785 digest of `requirement` equals
   `requirement_digest`;
3. require evidence that the same requirement digest is covered by the signed
   target decision's resource-attribute commitment;
4. expand `signer_set` from trusted project identity/group evidence;
5. require the expansion to equal `eligible_co_signer_ids`;
6. apply separation of duties and timeout;
7. count each eligible `co_signer_id` at most once; and
8. count only a `supported permit.co_signature.v2` claim for the same Permit,
   decision hash, and required role.

`supported` means the threshold was satisfied. `disproved` means present
evidence contradicts the signed requirement or contains an invalid counted
signature. Missing signed requirement coverage, trusted group expansion,
target decision, or enough signatures is `insufficient_evidence`.
Unsupported requirement or identity semantics are `unverifiable_scope`.

Approver quorum is pre-execution and may gate executability. Witness quorum is
post-execution and never grants or changes authority.
