# `permit.co_signature.v1` golden vectors

This corpus contains deterministic, offline WebAuthn assertion vectors for the
[`permit.co_signature.v1`](../../../spec/permit-co-signature-v1.md) contract.
It includes two supported cases (ES256 and EdDSA) and seven disproved cases with
distinct primary reasons:

- wrong challenge;
- wrong origin;
- wrong RP ID hash;
- UV clear while user verification is required;
- authenticator data changed after signing;
- malformed/tampered signature; and
- replay against a different target Permit.

Every vector carries the co-signature claim and assertion envelope, the
registered COSE public-key record, independently supplied target-Permit and
WebAuthn verification context, and the expected verdict and reason.

Run the dependency-free Node.js reference verifier from the repository root:

```sh
node test-vectors/permit_co_signature/v1/reference_verify.mjs
```

Regenerate the committed corpus deterministically with:

```sh
node scripts/build_permit_co_signature_vectors.mjs
```

The generator's private keys are deterministic test-only material. Only public
COSE keys and assertions are emitted into `corpus.json`; none of this material
is suitable for production use.
