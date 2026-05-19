# neg-checkpoint-missing-trust-root

Checkpoint signature cannot verify without a resolvable trust root

- Kind: `checkpoint`
- Expected current outcome: `FAIL`
- Claims:
  - `checkpoint.signature.v1` -> `insufficient_evidence`
- Mutation:
  - Parent fixture: `valid-checkpoint-legacy-single-tsa`
  - Delta: Kept checkpoint bytes unchanged but supplied a trust root that has no integrity_checkpoint entry for the checkpoint key_id.
