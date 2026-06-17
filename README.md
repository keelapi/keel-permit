# Permit Specification

[![License](https://img.shields.io/github/license/keelapi/keel-permit)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/keelapi/keel-permit?label=release)](https://github.com/keelapi/keel-permit/releases)
![Spec version](https://img.shields.io/badge/spec-1.5.0-blue)

A pre-execution decision record for AI agent systems. A Permit records that an action was evaluated and decided, and, for dispatched allow executions, can be bound to the final provider or tool request. A Permit JSON object alone is not self-authenticating; verification is performed from signed export artifacts and the relevant public keys or key manifest. Those artifacts are verifiable without contacting the issuer when the verifier has the signed export artifacts and relevant public keys/key manifest.

This repository contains the wire-format specification, JSON schemas, and verification rules for **Permit v1**.

## Status

| | |
|---|---|
| Spec document version | 1.5.0 |
| Permit wire format | `v1` |
| Closure record format | `closure_v1`, `closure_v2` |
| Chain entry hash format | `v1` |
| Reference implementation | [keel-api](https://github.com/keelapi/keel-api) |
| Reference verifier | [keel-verifier](https://github.com/keelapi/keel-verifier) (`pip install keel-verifier`) |

## Why this exists

AI agents increasingly act faster than humans can review every step. Permit gives systems a standard way to record what was authorized before execution and prove it later from signed, offline-verifiable evidence.

```mermaid
flowchart LR
  Agent["Agent"] --> Policy["Policy evaluation"]
  Policy --> Permit["Permit issued"]
  Permit --> Dispatch["Dispatch"]
  Dispatch --> Closure["Closure record"]
  Closure --> Export["Signed export bundle"]
  Export --> Verifier["Offline verifier"]
```

## What this specifies

- **Permit object** — fields, types, lifecycle, decision shapes.
- **Closure record** — the signed artifact that links a permit to its execution outcome (`closure_v1`, `closure_v2`).
- **Chain entry** — the record-hash algorithm and continuity rules for tamper-evident chains when entries are delivered through signed bundles or anchored checkpoints.
- **Audit export bundle** — the file format and manifest for offline-verifiable evidence packs.
- **Canonicalization** — JSON canonicalization rules for hashing.
- **Failure codes** — the normative taxonomy a verifier emits when integrity fails.

## What this does not specify

- A policy language or evaluation engine. Permits attest decisions; how decisions are reached is implementation-defined.
- A runtime, gateway, or proxy. Permits can be emitted by any system that wants to produce them.
- An identity or RBAC model. Subject and identity fields are open-ended.
- Live runtime API envelopes, network protocols, transport, or retrieval APIs. Permit v1 specifies audit-export artifacts and evidence semantics.
- Storage, indexing, or query semantics.

## Specifications

- [`spec/permit-v1.md`](spec/permit-v1.md) — Permit object
- [`spec/closure-v2.md`](spec/closure-v2.md) — Execution closure record
- [`spec/chain-entry.md`](spec/chain-entry.md) — Tamper-evident chain entry
- [`spec/audit-export-bundle.md`](spec/audit-export-bundle.md) — Evidence bundle format
- [`spec/canonical-json.md`](spec/canonical-json.md) — Canonicalization rules
- [`spec/failure-codes.md`](spec/failure-codes.md) — Verification failure taxonomy
- [`spec/permit-chain-v1.md`](spec/permit-chain-v1.md) — Delegated Permit Chain semantics
- [`spec/verifier-claims-v0.md`](spec/verifier-claims-v0.md) — Verifier claim model
- [`spec/verifier-pack-pinning-v0.md`](spec/verifier-pack-pinning-v0.md) — Pinned semantics for evidence packs
- [`spec/permit-revoked-event-v1.md`](spec/permit-revoked-event-v1.md) — Signed permit revocation event
- [`spec/key-status-event-v1.md`](spec/key-status-event-v1.md) — Signed key status event
- [`spec/dispatch-absence-after-revocation-v1.md`](spec/dispatch-absence-after-revocation-v1.md) — Scope-faithful absence adjudication after revocation

## Schemas

Most JSON Schema (Draft 2020-12) files in [`schemas/`](schemas/) are generated from the reference implementation's Pydantic models and then post-processed with public wire-format constraints. Regenerate with [`tools/export_schemas.py`](tools/export_schemas.py). `schemas/closure-v2.schema.json` and `schemas/audit-export-manifest.schema.json` are hand-maintained because the reference implementation builds those envelopes dynamically rather than from Pydantic models.

## Released artifacts

- [`claim_registry/`](claim_registry/) — stable verifier-claim registry artifacts.
- [`comparator_registry/`](comparator_registry/) — authority-envelope comparator semantics for Permit Chains.
- [`semantics/`](semantics/) — pinned semantic artifacts consumed by verifiers for export manifests, governance chains, closure records, checkpoints, workflows, and Permit binding.

## Examples

Reference artifacts in [`examples/`](examples/) — schema-valid illustrative permits, closure records, chain entries, and an illustrative audit export bundle. Unless an example is explicitly marked as a cryptographically verifiable reference bundle, hashes, signatures, and key identifiers are placeholders.

## Control framework mappings

[`mappings/control-frameworks.schema-mapping.json`](mappings/control-frameworks.schema-mapping.json) — machine-readable mapping from Permit v1 wire-format fields and audit-export-bundle artifacts to specific control IDs across 14 frameworks (CCPA §1798.105, CPPA ADMT regulations, EU AI Act, GDPR, AICPA SOC 2, NIST AI RMF, ISO/IEC 42001:2023, OWASP LLM Top 10 2025, MITRE ATLAS, OWASP API Security Top 10 2023, OWASP ASVS v5.0.0, FedRAMP / NIST SP 800-53 Rev 5, CIS Controls v8.1, PCI DSS v4.0.1).

See [`mappings/README.md`](mappings/README.md) for status, scope, evidence-support disclaimers, schema shape, and explicit non-mappings documenting controls Keel does not address.

## Conformance test vectors

[`test-vectors/`](test-vectors/) — a versioned conformance fixture set that any verifier (Keel's reference verifier or independent third-party implementations) can be tested against. Each fixture has an `expected.json` defining the required outcome; a verifier that disagrees on any fixture is non-conforming.

Current conformance artifacts include the pinned-semantics golden corpus in [`test-vectors/verifier_claims/`](test-vectors/verifier_claims/), semantic-artifact conformance records in [`test-vectors/semantics/`](test-vectors/semantics/), and self-contained Permit Chain semantic vectors under [`test-vectors/vectors/cat-08-permit-chains/`](test-vectors/vectors/cat-08-permit-chains/). See [`test-vectors/README.md`](test-vectors/README.md) and [`test-vectors/CONFORMANCE.md`](test-vectors/CONFORMANCE.md).

## Versioning

Three orthogonal version axes:

- **Permit wire format** (`v1`): the on-the-wire structure of a Permit object. Bumping this is a breaking change.
- **Closure record format** (`closure_v1`, `closure_v2`): the signed envelope for execution closure. New formats are added; old formats remain valid indefinitely.
- **Chain entry hash format** (`v1`): the input string layout passed to SHA-256 to produce a record hash. Bumping this is a breaking change.

This **specification document** uses semver independently of the wire formats — a 1.0.0 → 1.1.0 spec release may clarify normative language without changing any byte-level format.

## Conformance

A Permit emitter conforms to this specification if and only if:

1. Every emitted Permit object validates against `schemas/permit-v1.schema.json`.
2. Every closure record emitted in `closure_v2` form validates against `schemas/closure-v2.schema.json` and satisfies the digest-presence matrix in [`spec/closure-v2.md`](spec/closure-v2.md) §3.
3. Every chain entry conforms to the record-hash algorithm in [`spec/chain-entry.md`](spec/chain-entry.md).
4. Every audit export bundle validates against `schemas/audit-export-bundle.schema.json` and ships a companion signature manifest as defined in [`spec/audit-export-bundle.md`](spec/audit-export-bundle.md).

A Permit verifier conforms if it implements the failure codes in [`spec/failure-codes.md`](spec/failure-codes.md) and rejects any artifact that violates the rules in the corresponding spec document.

## Stability

The wire formats and hash algorithms in this spec are stable. A breaking change to any wire format requires a new format version (`v2`, `closure_v3`, etc.); the previous version remains valid indefinitely so that historical artifacts continue to verify. See [`CHANGELOG.md`](CHANGELOG.md).

## Project Stewardship

Permit Spec is maintained by Keel API, Inc.

- Website: https://keelapi.com
- Reference implementation: https://github.com/keelapi/keel-api
- Reference verifier: https://github.com/keelapi/keel-verifier

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
