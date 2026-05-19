# neg-export-forged-manifest-signature

Forged export manifest signature is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `export.integrity.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-export-hash-signature`
  - Delta: Replaced manifest.signature with a syntactically valid Ed25519-sized zero signature without changing export bytes or content_hash.
