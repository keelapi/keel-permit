# neg-vanta-permit-snapshot-effective-hash-mismatch

Vanta permit snapshot effective intent hash mismatch is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `workflow.permit_snapshot.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-vanta-workflow-sibling`
  - Delta: Changed the main export permit workflow_state_json.effective_intent_hash to 64 zeroes and resealed the export manifest.
