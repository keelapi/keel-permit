# neg-closure-provider-digest-mismatch

Closure provider response digest mismatch is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `closure.digest_consistency.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-closure-v2-dispatch-binding`
  - Delta: Changed the signed closure provider_response_digest_v1 away from the provider.response.received event digest and resealed the closure plus export manifest.
