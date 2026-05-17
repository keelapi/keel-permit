# neg-incident-v2-incomplete-file-set

Incident v2 bundle missing required file is rejected

- Kind: `export`
- Expected current outcome: `FAIL`
- Claims:
  - `incident.bundle_manifest.v1` -> `disproved`
- Mutation:
  - Parent fixture: `valid-incident-v2-bundle`
  - Delta: Removed admin_actions.jsonl from both the manifest file list and the zip payload.
