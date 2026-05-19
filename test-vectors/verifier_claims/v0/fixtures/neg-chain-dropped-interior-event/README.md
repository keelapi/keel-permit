# neg-chain-dropped-interior-event

Dropped interior chain event breaks prev_hash continuity

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `governance_chain.local_continuity.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-audit-bundle-per-record-chain`
  - Delta: Removed chain entry evt_002 while preserving evt_003.prev_hash, then resealed the export manifest.
