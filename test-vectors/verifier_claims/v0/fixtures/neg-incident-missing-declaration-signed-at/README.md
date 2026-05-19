# neg-incident-missing-declaration-signed-at

Incident v2 declaration missing declaration_signed_at is insufficient

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `workflow.declaration_signature.v1` -> `insufficient_evidence`
- Mutation:
  - Parent fixture: `valid-incident-v2-bundle`
  - Delta: Removed declaration_signed_at from workflow_declarations.jsonl and resealed the incident zip/export manifest.
