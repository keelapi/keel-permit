# Verifier Conformance Model

This document defines what a Permit Spec verifier MUST do when processing the test vectors in this directory. It is the binding contract for conformance.

## Versioning

This conformance model pins to:

- **Permit Spec:** v1.0.0
- **Test vectors version:** 0.1.0-draft
- **Failure-code taxonomy:** `spec/failure-codes.md` in the keel-permit repository

When citing a conformance result, all three versions MUST be reported together. A result of "verifier X passes test vectors" without version pins is not citable.

## Verifier output schema

For every test vector input, a conforming verifier MUST produce machine-readable output (the format below is canonical; equivalent serializations are acceptable so long as the same fields are present):

```json
{
  "test_vector_id": "cat-02-tamper-chain/02-01-record-hash-modified",
  "test_vector_version": "0.1.0-draft",
  "verifier_id": "<implementation-identifier>",
  "verifier_version": "<implementation-version>",
  "result": "PASS" | "FAIL",
  "failure_codes": ["<code from spec/failure-codes.md>"],
  "first_failure_at": {
    "type": "permit" | "chain_entry" | "closure_record" | "manifest" | "signature" | "tsa_receipt" | "checkpoint",
    "id": "<artifact id if applicable>",
    "sequence": <int if applicable, e.g. chain entry sequence>
  },
  "evidence_inspected": {
    "permits": <int>,
    "chain_entries": <int>,
    "closure_records": <int>,
    "checkpoints": <int>
  },
  "trust_root_source": "bundled-wheel" | "cached-manifest" | "fetched-from-keel" | "fetched-from-pypi" | "fetched-from-github" | "explicit-flag"
}
```

The `expected.json` file in each test vector directory contains the same schema with the `required` values filled in. A conforming verifier matches the test vector's expected output when:

- `result` field matches exactly.
- `failure_codes` set is equal as a set (order-independent).
- If `first_failure_at` is present in the expected output, the verifier's value matches.
- Other fields (`evidence_inspected`, `trust_root_source`, `verifier_id`, `verifier_version`) are informational and not part of the conformance match.

## Conformance levels

| Level | Required behavior |
|---|---|
| **Level 1 (Baseline)** | Passes all `cat-01-baseline` and `cat-02-tamper-chain` vectors. |
| **Level 2 (Signed)** | Level 1 + passes all `cat-03-tamper-signature` and `cat-04-closure-binding` vectors. |
| **Level 3 (Canonical)** | Level 2 + passes all `cat-05-canonicalization` vectors. |
| **Level 4 (Full)** | All categories pass, including key rotation and bundle-format edge cases. |

A verifier MUST declare which level it conforms to. A Level 1 verifier is useful but not sufficient for tamper-evident audit use; Level 4 is the bar for production audit.

## What a conforming verifier MUST do per failure code

This table is the failure-code-to-verifier-behavior contract. For every failure code in `spec/failure-codes.md`, a conforming verifier MUST:

1. Detect the failure condition when it occurs in any artifact.
2. Emit the named failure code in its output.
3. Identify the first artifact at which the failure occurred (when the code is positional — chain entries, sequenced records, etc.).
4. NOT continue verification past a failure in a way that masks subsequent failures the user would want to know about. (Implementations MAY continue and report multiple failures; implementations MAY stop at first failure and report just that one. Both are conforming. Implementations MUST NOT report PASS when any failure code triggered.)

See `spec/failure-codes.md` in the keel-permit root for the full taxonomy. The test vectors exercise each code at least once.

## What a conforming verifier MUST NOT do

- **MUST NOT accept production trust roots in test mode.** Test-key signatures (where the signing key is committed under `tools/test-keys/`) MUST verify only when the verifier is explicitly in test mode. Default mode MUST reject test-key signatures.
- **MUST NOT silently swap trust roots.** If the verifier resolves the trust root through multiple channels (bundled wheel, cached manifest, GitHub mirror, etc.), it MUST report which channel was used in `trust_root_source`.
- **MUST NOT report PASS when any required signature is missing.** A test vector with a manifest but no signature file is FAIL with code `MANIFEST_SIGNATURE_MISSING`, not PASS.
- **MUST NOT modify input artifacts under test.** Verifier behavior is read-only with respect to the input directory.

## Test-key disclosure

For golden-path fixtures that require a real Ed25519 signature (most cases in `cat-01-baseline`), test keys are committed in `tools/test-keys/`. These are dedicated test keys with no production use. Their public keys are:

```
TODO: regenerate test keys and commit here on first fixture population.
```

A conforming verifier in production mode MUST reject signatures made with these test keys. A conforming verifier in test mode (e.g., the verifier's own CI) MAY accept them.

This is the same convention as Sigstore's test keys and JWS test vector keys.

## Reporting a conformance result

A verifier that has run the test vector set should publish a `verifier-conformance-report.json`:

```json
{
  "verifier_id": "<impl-identifier>",
  "verifier_version": "<impl-version>",
  "test_vectors_version": "0.1.0-draft",
  "permit_spec_version": "1.0.0",
  "conformance_level_claimed": 1 | 2 | 3 | 4,
  "vectors": [
    {
      "test_vector_id": "<id>",
      "result_match": true | false,
      "verifier_output": {...},
      "expected_output": {...},
      "notes": "..."
    }
  ],
  "summary": {
    "total_vectors": <int>,
    "passed": <int>,
    "failed": <int>,
    "skipped_todo": <int>
  }
}
```

Publish the report alongside the verifier release. Customers and procurement reviewers can compare reports across verifiers.

## Future revisions

When Permit Spec v1.1.0 ships (e.g., adding counter-signatures), this conformance model gains:

- New test categories for the v1.1 capabilities.
- A v1.1-conformance level above the current Level 4.
- Existing v1.0 vectors remain valid — backwards-compatible verifiers still pass them.

When Permit Spec v2.0 ships (a breaking wire-format change), this conformance model forks: `test-vectors-v0.1.x` continues to validate v1 artifacts, and `test-vectors-v2.x` covers v2.
