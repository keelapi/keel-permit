# neg-chain-record-hash-altered

Tampered chain record hash is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `governance_chain.local_continuity.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-audit-bundle-per-record-chain`
  - Delta: Changed chain_entries[1].record_hash to 64 zeroes and resealed the export manifest so only local continuity is under test.
