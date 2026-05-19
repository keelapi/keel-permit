# Verifier Conformance Model

This document defines what a Permit Spec verifier MUST do when processing the test vectors in this directory. It is the binding contract for conformance.

## Versioning

This conformance model pins to:

- **Permit Spec:** v1.0.0
- **Test vectors version:** 0.1.0-draft
- **Failure-code taxonomy:** `spec/failure-codes.md` in the keel-permit repository

When citing a conformance result, all three versions MUST be reported together. A result of "verifier X passes test vectors" without version pins is not citable.

## Two related schemas

This document defines **two related but distinct JSON schemas**:

1. **Verifier output schema** — what a verifier MUST emit when it runs against any input.
2. **Vector expectation schema** (`expected.json`) — what a fixture asserts must be true for a conforming verifier's output.

A conformance match is a comparison of the two: the verifier's output is matched against the vector's expectation. See "How matching works" below.

## Verifier output schema

For every test vector input, a conforming verifier MUST produce machine-readable output (the format below is canonical; equivalent serializations are acceptable so long as the same fields are present):

```json
{
  "test_vector_id": "cat-02-tamper-chain/02-01-record-hash-modified",
  "test_vectors_version": "0.1.0-draft",
  "verifier_id": "<implementation-identifier>",
  "verifier_version": "<implementation-version>",
  "verifier_mode": "PRODUCTION" | "TEST",
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

## Vector expectation schema (`expected.json`)

Each test vector directory contains an `expected.json` declaring what a conforming verifier MUST produce when run against that vector's input. This schema is more granular than the verifier output schema because it captures **why** a fixture should fail (or pass), not just **whether** it should fail.

The richer schema prevents the canonical interoperability failure mode where two verifiers both reject a fixture but report different failure codes — see the §"Layer enumeration" and §"Failure isolation" sections.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "vector_id": "cat-02-tamper-chain/02-01-record-hash-modified",
  "spec_version": "permit-v1.0.0",
  "test_vectors_version": "0.1.0-draft",
  "expected_mode": "TEST",
  "expected_result": "PASS" | "FAIL",
  "primary_failure_code": "<code from spec/failure-codes.md or null when expected_result is PASS>",
  "acceptable_secondary_codes": ["<additional codes a conforming verifier MAY emit alongside the primary code>"],
  "valid_layers": ["<layer-name from the enumeration below>"],
  "invalid_layers": ["<layer-name from the enumeration below>"],
  "expected_first_failure_at": {
    "type": "<artifact type>",
    "id": "<artifact id>",
    "sequence": <int or null>
  } | null,
  "artifact_hashes": {
    "<filename relative to input/>": "sha256:<hex>"
  },
  "expected_evidence_inspected_at_least": {
    "permits": <int>,
    "chain_entries": <int>,
    "closure_records": <int>,
    "checkpoints": <int>
  },
  "trust_root_resolution": "<human-readable description of which trust root flag the verifier must pass>",
  "error_precedence_note": "<documentation of which failure codes might fire if a non-conforming verifier mishandles this fixture>",
  "failure_isolation_note": "<documentation of which layers are deliberately valid vs invalid in this fixture, to prevent failure-mode confusion>",
  "notes": "<human-readable explanation>"
}
```

### Layer enumeration

The `valid_layers` and `invalid_layers` arrays MUST use values from the following normative enumeration. Every verification layer that a conforming verifier checks MUST appear in either `valid_layers` or `invalid_layers` for any non-trivial fixture.

| Layer name | What it means |
|---|---|
| `json` | All fixture files parse as well-formed JSON. |
| `schema` | All fixture artifacts validate against their respective JSON schemas in `keel-permit/schemas/`. |
| `manifest_hash` | The manifest's `content_hash` field matches the actual SHA-256 of the content bytes. |
| `manifest_signature` | The detached Ed25519 signature over the manifest verifies against the trust root. |
| `chain_record_hash` | Every chain entry's `record_hash` field equals the recomputed SHA-256 of its content. |
| `chain_linkage` | Every chain entry's `prev_hash` field equals the previous entry's `record_hash`. |
| `chain_sequence` | Chain entry sequence numbers are monotonic and contiguous (no gaps, no duplicates, no reordering). |
| `closure_dispatch_binding` | The closure record's `dispatch_digest_v1` matches the SHA-256 of the dispatched canonical request bytes. |
| `closure_provider_binding` | The closure record's `provider_response_digest_v1` matches the recorded provider response bytes. |
| `closure_client_binding` | The closure record's `client_response_digest_v1` matches the bytes delivered to the client. |
| `permit_dispatch_binding` | The Permit's `binding_request_hash` matches the canonical hash of the dispatched request. |
| `tsa_receipt` | The RFC 3161 TSA receipt verifies and binds to the externally anchored checkpoint hash. |
| `key_validity` | The signing key referenced by the manifest signature was active at the recorded `signed_at` time. |
| `canonicalization` | Equivalent JSON representations produce identical canonical bytes per `spec/canonical-json.md`. |

### Failure isolation

A test vector that fails on `chain_record_hash` MUST list `json`, `schema`, `manifest_hash`, `manifest_signature`, and `chain_linkage` in `valid_layers` if those layers are intended to remain valid in this fixture. This prevents the canonical interoperability failure: two verifiers both reject the fixture but for different reasons, and a non-conforming verifier passes by accidentally checking only one layer.

**Failure isolation is the primary guarantee of every tampered vector.** Each tampered vector deliberately invalidates exactly the layer(s) listed in `invalid_layers`, and a fixture-generator MUST recompute all other layers' hashes/signatures to keep them valid after tampering.

### Error precedence

A conforming verifier MAY check layers in any order. However, the test vector's `expected_first_failure_at` SHOULD reflect the **earliest layer** at which a conforming verifier MUST detect the invalid state. For a fixture that invalidates `chain_record_hash`, a verifier that checks the chain before reading the manifest may detect the failure earlier than one that processes the manifest first; both are conforming if they emit the correct primary code, but only the second would report a position consistent with a chain-walk-first implementation.

**The `acceptable_secondary_codes` array enumerates additional codes a conforming verifier MAY emit alongside the primary code** if its layer-checking order would surface them. The set MUST NOT include codes that would mask the primary failure.

### Artifact hashes

The `artifact_hashes` field is the byte-level expected SHA-256 of each file under `input/`. This is the **fixture-local cross-platform tripwire**: a verifier or a CI job reading these fixtures can confirm bytes are intact end-to-end, catching invisible line-ending corruption, encoding drift, or partial-extract errors. Until the fixture generator is committed, these values are placeholders (`sha256:TBD-generator-pending`); they MUST be filled in when fixtures are populated.

## How matching works

A conformance match is computed as:

1. **`expected_result`** matches `result` exactly (`PASS` vs `FAIL`).
2. **`primary_failure_code`** matches the first entry of `failure_codes`, OR is contained in `failure_codes` if the verifier emits multiple codes.
3. **`failure_codes`** is a subset of `[primary_failure_code] + acceptable_secondary_codes`.
4. **`expected_first_failure_at`** (when not null) matches `first_failure_at` exactly.
5. **`evidence_inspected`** counts meet the lower bound in `expected_evidence_inspected_at_least` (verifier may inspect more, never less).
6. **`artifact_hashes`** validate against the actual bytes in `input/` (independent of the verifier — this is a fixture integrity check the CI runs).

A verifier whose output satisfies all 6 is conforming on that vector.

## Conformance levels

| Level | Required behavior |
|---|---|
| **Level 1 (Baseline)** | Passes all `cat-01-baseline` and `cat-02-tamper-chain` vectors. |
| **Level 2 (Signed)** | Level 1 + passes all `cat-03-tamper-signature` and `cat-04-closure-binding` vectors. |
| **Level 3 (Canonical)** | Level 2 + passes all `cat-05-canonicalization` vectors. |
| **Level 4 (Full Cryptographic)** | Level 3 + passes `cat-06-key-rotation` and `cat-07-bundle-format` vectors. |
| **Level 5 (Permit Chains)** | Level 4 + passes `cat-08-permit-chains` semantic vectors. |

A verifier MUST declare which level it conforms to. A Level 1 verifier is useful but not sufficient for tamper-evident audit use. Level 4 preserves the original full cryptographic conformance target for the `cat-01` through `cat-07` suite; Level 5 adds Permit Chain claim semantics without redefining existing Level 4 claims.

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
  "conformance_level_claimed": 1 | 2 | 3 | 4 | 5,
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
