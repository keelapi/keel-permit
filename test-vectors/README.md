# Permit Spec — Conformance Test Vectors

A versioned collection of test fixtures that a conforming verifier MUST process correctly. The goal: any verifier implementation — Keel's reference verifier, or an independent third-party verifier — can be tested against the same fixture set and produce the same pass/fail outcomes.

## Foundational framing

Three principles that shape every decision in this directory:

1. **The committed fixture bytes in `vectors/*/input/` are the conformance product.** Implementers and customers run their verifiers against the committed bytes. Those bytes are what counts. (Currently scaffolded with placeholders — see "Status" below.)
2. **The fixture generator is a reproducibility tool, not the source of truth.** When committed (TODO under `tools/`), the generator's job is to make committed fixtures reproducible from source — not to define correctness. Correctness is defined by `CONFORMANCE.md` + the per-vector `expected.json` files.
3. **A conformance runner CLI is planned.** The intended shape is `keel-conformance run --verifier <command> --vectors <directory>` — invokes any verifier against any version of this fixture set and produces a machine-readable `verifier-conformance-report.json`. This is the artifact a customer cites when evaluating verifiers ("verifier X is Level 3 conforming against test-vectors v0.1.0"). Spec for this CLI lands alongside the first fully-populated v0.1 fixture set.

## Why this exists

A specification document is text. Two implementers can read the same text and produce verifiers that disagree on edge cases. Test vectors collapse that ambiguity: each case is a concrete input + a documented expected outcome. If two verifiers process the same fixture and disagree, at least one is non-conforming.

This is the same role test vectors play for cryptographic primitives (FIPS test vectors), JSON canonicalization (JCS test vectors), JWT/JWS (RFC 7520), and Sigstore's transparency log proofs.

For Permit Spec, this enables:

- **Independent implementations.** A Go or Rust verifier can be developed against this fixture set with no Keel-internal access.
- **Drift detection.** A change to a verifier that breaks a fixture is detected immediately.
- **Standards-track positioning.** When this spec is proposed to a venue (OpenSSF / CNCF), reviewers can see the conformance model is concrete, not aspirational.
- **Cross-verifier auditing.** Customers running two verifiers against the same export bundle gain assurance from agreement; disagreement is investigable.

## Status

**Version:** `0.1.0-draft` (initially pinned to Permit Spec v1.0.0; newer semantic artifacts may cite later spec-document revisions while preserving Permit wire format `v1`).

`MANIFEST.json` uses `permit_spec_version` to record the fixture suite's original Permit Spec baseline, not the current repository release. Individual semantic artifacts and fixtures may carry their own version references when they exercise later spec-document additions.

### Current conformance artifacts

- `verifier_claims/v0/` contains the pinned-semantics golden corpus consumed by the public verifier.
- `semantics/` contains semantic-artifact conformance records for export manifests, governance-chain hashing, closures, checkpoints, workflow evidence, and Permit binding.
- `vectors/cat-08-permit-chains/` contains self-contained Permit Chain semantic vectors. These assume the cryptographic substrate is valid and focus on claim-layer semantics.
- `vectors/cat-01-baseline/` and `vectors/cat-02-tamper-chain/` contain the first byte-level fixture scaffolds, with placeholder hashes pending the deterministic fixture generator.

### Planned expansion

The original cryptographic conformance suite (`cat-01` through `cat-07`) is still being populated. Categories and category structure are enumerated in `MANIFEST.json`; complete byte-level fixtures will be added incrementally. The conformance model in `CONFORMANCE.md` is the binding contract for verifier behavior, even where a specific fixture is still TODO.

A **14-vector MVP subset** is marked in `MANIFEST.json` under `version_milestones.v0.1`. These 14 vectors exercise all 8 categories at minimum coverage and unblock independent verifier implementations. The remaining 22 vectors are marked `priority: "deferred_post_v0_1"` and are populated once v0.1 is solid.

When a verifier conformance result is published, it MUST cite the test-vector version (`test-vectors-v0.1.0`) so the result is reproducible against the same fixture set.

## Structure

```
test-vectors/
├── README.md                — this file
├── MANIFEST.json            — machine-readable index of all categories + test cases
├── CONFORMANCE.md           — the conformance model: what a verifier MUST do per fixture
├── vectors/                 — the test cases themselves
│   ├── cat-01-baseline/
│   │   ├── 01-01-valid-permit-export/
│   │   │   ├── description.md       — human-readable explanation
│   │   │   ├── expected.json        — machine-readable expected verifier output
│   │   │   └── input/               — artifacts under test
│   │   │       ├── permit.json
│   │   │       ├── export.jsonl
│   │   │       ├── manifest.json
│   │   │       └── signature.bin
│   │   └── …
│   ├── cat-02-tamper-chain/
│   ├── cat-03-tamper-signature/
│   ├── cat-04-closure-binding/
│   ├── cat-05-canonicalization/
│   ├── cat-06-key-rotation/
│   ├── cat-07-bundle-format/
│   └── cat-08-permit-chains/
└── tools/                   — fixture generation + verification scripts
    └── (TODO)
```

## How to use as an implementer

If you are writing a new verifier (Go, Rust, TypeScript, etc.):

1. **Read `CONFORMANCE.md`.** It defines what a conforming verifier MUST output for each failure code in `spec/failure-codes.md`.
2. **Pick a test category.** Run your verifier against every input in that category's fixture directories.
3. **Compare to `expected.json`.** A conforming verifier produces an output where (a) the `result` field matches, (b) the set of `failure_codes` matches, and (c) for cases where the spec requires identification of the first failure position, that position matches.
4. **Report a `verifier-conformance-report.json` against `test-vectors-v0.1.0`.** Cite which categories passed, which had mismatches, and any fixtures that are TODO in this version.

## How to use as a customer

If you are evaluating two verifiers for cross-verification of the same export bundle:

1. Run both verifiers against this fixture set.
2. Both should pass every fixture identically (or both fail identically on the same TODO fixtures).
3. If they disagree on any fixture, the disagreement is your investigation point — at least one is non-conforming on that case.

## Categories

| Category | What it tests | # vectors planned |
|---|---|---|
| **cat-01-baseline** | A correctly-signed, correctly-chained, correctly-bound export bundle. Pass cases. | 4 |
| **cat-02-tamper-chain** | Hash chain integrity failures — modified record hashes, broken prev-hash links, gaps in sequence. | 6 |
| **cat-03-tamper-signature** | Signature failures — modified signed bytes, wrong key, missing manifest signature. | 4 |
| **cat-04-closure-binding** | Closure record binding failures — dispatch digest mismatch, provider digest mismatch, client digest mismatch. | 5 |
| **cat-05-canonicalization** | JSON canonicalization edge cases — key reordering, whitespace, Unicode normalization, escape sequence handling, **plus negative cases** (visually-similar JSON that must NOT canonicalize identically). | 6 |
| **cat-06-key-rotation** | Multi-key trust root scenarios — verifying old artifacts with retired keys, post-rotation freshness. | 3 |
| **cat-07-bundle-format** | Bundle format edge cases — empty bundle, single-entry bundle, multi-gigabyte bundle reference. | 3 |
| **cat-08-permit-chains** | Permit Chain semantic claims — envelope subset, expiry, unsupported envelope versions, missing comparator registry. | 5 |

Total planned: 36 fixtures (14 in v0.1 MVP scope, 22 deferred to post-v0.1). Current scaffolded count: see `MANIFEST.json`.

The original conformance levels cover the cryptographic fixture categories (`cat-01` through `cat-07`). Permit Chain semantics are additive: `CONFORMANCE.md` defines Level 5 for `cat-08` so existing Level 4 claims keep their original meaning.

## Adding a new test vector

1. Choose the appropriate category directory.
2. Create a numbered subdirectory: `NN-NN-short-name/` (e.g., `02-03-prev-hash-mismatch`).
3. Add three files at minimum:
   - `description.md` — what the test exercises (1-2 paragraphs).
   - `expected.json` — the expected verifier output, in the schema defined in `CONFORMANCE.md`.
   - `input/` — directory containing the artifacts under test.
4. Add an entry to `MANIFEST.json`.
5. Open a PR. CI runs the reference verifier against all fixtures; if it disagrees with any `expected.json`, CI fails.

## Cryptographic content disclosure

**Most fixtures use placeholder hashes and signatures.** A "tampered" fixture is constructed by editing a known-good fixture and recording the expected failure mode — the signature in the fixture is intentionally invalid, the hash in the fixture is intentionally wrong, etc.

**A small subset of "golden path" fixtures use real cryptographic material** signed with dedicated test-only keys (NOT production keys). These keys are committed in `tools/test-keys/` and rotated only when test vectors are regenerated. Production verifiers MUST reject test-key signatures in production mode — see `CONFORMANCE.md` §6.

## Relationship to keel-permit/examples/

`examples/` (in the spec repo root) contains illustrative reference artifacts for documentation. `test-vectors/` contains conformance fixtures with binding expected outcomes. The two are intentionally separate:

- An example can be lossy or stylized for human readability.
- A test vector must be byte-precise and machine-reproducible.

## Future: splitting to a standalone repo

This directory may be promoted to a standalone repository (`keelapi/keel-permit-test-vectors`) when:

- A second independent verifier implementation is in development.
- A standards venue (OpenSSF / CNCF) requests separability for proposal review.
- Fixture count exceeds ~100 and growth velocity warrants its own release cadence.

Until then, co-locating with the spec keeps versioning aligned and reduces friction for early contributors.

## License

Apache License 2.0, same as the Permit Spec.
