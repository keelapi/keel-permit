# Verifier Claims v2

`verifier-claims.v2` is the first composable claim registry. Its canonical
artifact is [`claim_registry/v2.json`](../claim_registry/v2.json).

The artifact pins and extends the complete immutable v1 registry rather than
copying it. A resolver MUST:

1. load the exact base registry named by `extends`;
2. verify its version and SHA-256 digest;
3. reject duplicate claim names across the base and extension;
4. expose the ordered union of base claims followed by v2 additions; and
5. preserve the original defining registry version for each claim.

Failure to resolve the pinned base is fatal. Falling back to a different
registry version or silently dropping an extension claim is forbidden.

The v2 additions implement the universal verification contract in
[`permit-universal-verification-v1.md`](permit-universal-verification-v1.md).
They separate Permit type, target, request, validity, revocation, certified
enforcement, bounded use, single use, replay, idempotency, and provider receipt
state. Provider rejection, acceptance, and completion are separate claims over
that receipt-state foundation. No one claim implies another unless its
`required_evidence` explicitly names the supported prerequisite claim.
