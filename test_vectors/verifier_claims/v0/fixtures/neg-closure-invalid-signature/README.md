# neg-closure-invalid-signature

Closure binding signature is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `closure.signature.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-closure-v2-dispatch-binding`
  - Delta: Replaced closure_signature_b64 with an Ed25519-sized invalid signature and resealed the export manifest.
