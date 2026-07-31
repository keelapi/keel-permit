# permit.co_signature.v2 golden vectors

This corpus reuses the deterministic v1 WebAuthn ceremonies while changing the
target contract: the challenge hash is compared with a separately supported
`permit.decision.v1` canonical hash.

`negative-replay-different-permit` is the false-target vector. Its WebAuthn
assertion remains cryptographically valid for the original decision hash while
the independently supported target context identifies a different Permit and
decision hash. A conforming verifier returns
`CO_SIGNATURE_PERMIT_BINDING_MISMATCH`.

Run:

```sh
node test-vectors/permit_co_signature/v2/reference_verify.mjs
```
