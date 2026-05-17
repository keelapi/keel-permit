# neg-checkpoint-composite-hash-mismatch

Checkpoint composite_hash mismatch is rejected

- Kind: `checkpoint`
- Expected current outcome: `FAIL`
- Claims:
  - `checkpoint.composite_hash.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-checkpoint-legacy-single-tsa`
  - Delta: Changed one chain_heads last_record_hash nibble while preserving the original composite_hash and signature.
