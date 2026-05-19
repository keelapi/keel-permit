# neg-closure-dispatch-binding-mismatch

closure_v2 dispatch digest mismatch is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `closure.dispatch_binding.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-closure-v2-dispatch-binding`
  - Delta: Changed the signed closure dispatch_request_digest_v1 while leaving the permit binding_request_hash at the valid parent value.
