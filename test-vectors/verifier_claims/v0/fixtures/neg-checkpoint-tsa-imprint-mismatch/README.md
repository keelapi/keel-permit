# neg-checkpoint-tsa-imprint-mismatch

Checkpoint TSA imprint mismatch is rejected

- Kind: `checkpoint`
- Expected current outcome: `FAIL`
- Claims:
  - `checkpoint.tsa_imprint.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-checkpoint-legacy-single-tsa`
  - Delta: Replaced tsa.receipt_b64 with a receipt whose MessageImprint does not equal composite_hash.
