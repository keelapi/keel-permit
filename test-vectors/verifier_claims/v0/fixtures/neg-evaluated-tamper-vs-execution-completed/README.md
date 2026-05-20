# neg-evaluated-tamper-vs-execution-completed

Tampered permit.evaluated record is rejected at the execution.completed boundary.

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `governance_chain.local_continuity.v1` -> `disproved`
- Mutation:
  - Parent fixture shape: `valid-audit-bundle-per-record-chain`
  - Delta: Changed `permit.evaluated` decision payload and `resource_id` after sealing, recomputed only that event record hash, and left `execution.completed.prev_hash` at the sealed value.
