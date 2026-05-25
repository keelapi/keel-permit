# Verifier Claim Golden Fixture Corpus v0

Frozen synthetic evidence packs for `verifier-claims.v0`. The expected doctrine verdicts in `corpus.json` are derived from `claim_registry/v0.json` and `spec/verifier-claims-v0.md`; they are not copied from any verifier's current output.

Earlier verifier CLI surfaces expose whole-pack PASS/FAIL with reason text rather than structured per-claim verdicts. `expected_current` captures that compatibility assertion layer, while the `claims[].expected_verdict` fields are the durable doctrine expectations.

Negative fixtures are documented single-delta mutations of valid parents. Some mutated payloads are resealed with the corpus test export key so the fixture isolates the claim under test instead of failing earlier at export-integrity.
