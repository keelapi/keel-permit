# neg-checkpoint-forged-signature

Checkpoint signature forgery is rejected

- Kind: `checkpoint`
- Expected current outcome: `FAIL`
- Claims:
  - `checkpoint.signature.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-checkpoint-legacy-single-tsa`
  - Delta: Replaced checkpoint.signature with a syntactically valid Ed25519-sized zero signature while preserving chain_heads, composite_hash, public_key, key_id, and TSA receipt.
