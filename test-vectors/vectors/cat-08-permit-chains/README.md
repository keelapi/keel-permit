# cat-08 — Permit Chains

Conformance test vectors for [Permit Chain v1](../../../spec/permit-chain-v1.md).

These vectors exercise the issuance-validity rules (§7.1), envelope-comparator semantics (§3), and the four verifier result statuses (§10.6). Vectors in this category focus on **chain semantics** — they assume cryptographic primitives (signatures, chain hashing) verify cleanly. Cryptographic-tamper vectors are covered in `cat-02-tamper-chain` and `cat-03-tamper-signature`.

## Status

This category is **scaffolded**. Inputs and expected outputs encode the spec semantics in self-contained illustrative form. Bundle-level cryptographic reconstruction (signed exports, real chain entries with valid `record_hash` linkage, signed manifests) is deferred to a follow-up vector pass that ships with the reference implementation.

## Vectors

| ID | Scenario | Expected status | Failure code |
|---|---|---|---|
| `08-01-clean-parent-child` | Valid root + child with envelope subset and expiry within parent | `supported` | — |
| `08-02-child-violates-subset` | Child's `authority_envelope.actions` includes an action not in parent's | `disproved` | `WALK_PERMIT_CHAIN_ENVELOPE_VIOLATION` |
| `08-03-child-violates-expiry` | Child's `expires_at` exceeds parent's | `disproved` | `WALK_PERMIT_CHAIN_EXPIRY_VIOLATION` |
| `08-04-unknown-envelope-version` | Permit declares an unsupported `authority_envelope_version` | `unverifiable_scope` | `WALK_PERMIT_CHAIN_UNKNOWN_ENVELOPE_VERSION` |
| `08-05-missing-comparator` | Pack lacks the comparator registry for the declared envelope version | `insufficient_evidence` | `WALK_PERMIT_CHAIN_MISSING_COMPARATOR` |

## Claim-type coverage (PR1 scope)

All five `cat-08` vectors target the `permit_lineage_internally_consistent` claim (`spec/permit-chain-v1.md` §10.2), each exercising a different failure or success path in the envelope-subset, expiry, version, or comparator-registry semantics. The other four claim types defined in §10.1–§10.5 are deferred to follow-up vector passes alongside the reference implementation:

- `export_integrity_only` (§10.1) — needs real signed bundles; arrives with `cat-01-baseline` cryptographic reconstruction.
- `permit_lineage_complete_to_root` (§10.3) — needs completeness-manifest semantics; deferred.
- `execution_authorized_at_boundary` (§10.4) — needs execution receipt + revocation completeness + resolved policy bundle; deferred.
- `delegation_denied_correctly` (§10.5) — needs a recorded `permit.delegated_denied` chain event; deferred.

This is an intentional PR1 scope boundary, not an omission.

## Vector format

Each vector directory contains:

- `input.json` — the chain artifacts (permits, optionally inline comparator registry, optionally inline policy bundle) plus the verifier claim being evaluated.
- `expected.json` — the expected verifier result envelope per `spec/permit-chain-v1.md` §10.9.

A conforming verifier given the `input.json` MUST emit a result envelope matching `expected.json` on `status`, `claim_type`, and (where present) `failure_code` and `revocation_status`. Implementations MAY add additional fields to the result envelope provided they do not contradict the expected ones.

## What these vectors do not cover

- Real Ed25519 signatures over closure or bundle envelopes (covered by `cat-01-baseline` once signed).
- Hash-chain `prev_hash` linkage tampering (covered by `cat-02-tamper-chain`).
- Cross-project delegation (out of scope for `v1`; see `spec/permit-chain-v1.md` §13).
- Aggregate quota conservation across siblings (out of scope for `v1`; see §5.3).
- Strict-revalidation policy mode (out of scope for `v1`; see §13).
