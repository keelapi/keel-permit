# neg-vanta-workflow-sibling-content-hash-mismatch

Vanta workflow sibling content_hash mismatch is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `workflow_evidence.sibling_integrity.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-vanta-workflow-sibling`
  - Delta: Changed sibling_artifacts.workflow_evidence.workflow_evidence.content_hash to sha256:000... while leaving workflow_evidence.json bytes intact.
