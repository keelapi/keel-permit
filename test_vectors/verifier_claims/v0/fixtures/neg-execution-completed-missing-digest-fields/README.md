# neg-execution-completed-missing-digest-fields

execution.completed alias without digest fields is insufficient

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `closure.digest_consistency.v1` -> `insufficient_evidence`
- Mutation:
  - Parent fixture: `valid-closure-execution-completed-alias`
  - Delta: Removed provider_response_digest_v1 and client_response_digest_v1 from the execution.completed payload and resealed the export manifest.
