# Bounded Work v1 contract vectors

`corpus.json` supplies one schema-valid payment-only Work chain plus focused
negative mutations. The assembly block expands shared objects into the
`work-chain.v1` pack before validation so the vector does not duplicate large
objects.

Use the assembled `valid.pack` and each negative mutation's committed `pack`.
The negative packs re-commit and sign unaffected populations and Permit bytes;
do not reapply the mutation to the valid pack and expect the same failure code.
Each `expected_failure_code` must be present in the rejected report. Dependent
claims may also be rejected; they do not replace the named failure.

`test_trust` discloses deterministic synthetic Ed25519 seeds and the independently
selected fixture root. Pass that root to `keel-verify work-chain`; these keys are
not Keel production keys. The payment receipt and settlement objects are synthetic
contract fixtures, not evidence of any provider or external effect.

Reproduce the authored bytes with the repository validation dependencies:

```sh
python tools/refresh_permit_to_work_vector_artifacts.py --check
```

The helper without `--check` regenerates this authored test corpus only. Never use
it to modify customer exports. The executable conformance regression in
`keel-verifier/tests/test_work_chain_corpus_conformance.py` requires the valid pack
to verify and all eight negative packs to reach their advertised failure codes.

These are contract vectors. They do not claim that an API producer or released
verifier supports the four Work claims until those implementations ship with
the same pinned artifacts.
