# Checkpoint Scope-State Sidecar v1

This document specifies the `checkpoint_scope_state.v1` sidecar artifact and
the `checkpoint.scope_state.v1` verifier claim. A sidecar is a detached,
Ed25519-signed scope-state object tied to one checkpoint and one `chain_scope`.
It lets an export segment reconcile its declared population or declared sample
against a checkpoint-bound membership commitment without changing checkpoint
composite or signature semantics.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Artifact Shape

The artifact type is `checkpoint_scope_state`; the version is
`checkpoint_scope_state.v1`. The strict JSON Schema is
[`../schemas/checkpoint-scope-state-v1.schema.json`](../schemas/checkpoint-scope-state-v1.schema.json).

Required top-level fields:

| Field | Purpose |
|---|---|
| `artifact_type` | Exactly `checkpoint_scope_state`. |
| `version` | Exactly `checkpoint_scope_state.v1`. |
| `scope_state_id` | Deterministic sidecar identifier. |
| `checkpoint_id` | Anchored checkpoint this sidecar reconciles against. |
| `chain_scope` | Chain scope covered by this sidecar. |
| `predicate_grammar_version` | Exactly `keel.scope_predicate.v1`. |
| `predicate_basis` | Canonicalization profile, supported v1 predicate kinds, and reserved namespaces. |
| `commitment_profile` | Exactly `keel.scope_state.merkle.v1`. |
| `scope_commitments` | Predicate commitments for this checkpoint and chain scope. |
| `tree_size` | Signed chain-scope state tree size at the checkpoint. |
| `signed_at` | Signing timestamp used for trust-root key-window resolution. |
| `signature` | Ed25519 signature block. |
| `trust_root_reference` | Trust-root manifest version, purpose, and key id. |

## 3. Identifier and Storage Key

`scope_state_id` is:

```text
keel.scope_state.v1:<chain_scope_hash>:<checkpoint_id>
```

where `chain_scope_hash = hex(SHA-256(canonical_json({"chain_scope":
chain_scope})))` under `keel.canonical_json.payload.v1`.

Storage keys SHOULD use:

```text
scope-state/v1/<chain_scope_hash>/<checkpoint_id>/checkpoint-scope-state-v1.json
```

Offline v1 verification requires the referenced sidecar artifact to be supplied
with the export pack or verifier input.

## 4. Predicate Basis

`predicate_basis.canonicalization_profile` MUST be
`keel.canonical_json.payload.v1`.

`predicate_basis.supported_predicate_kinds` MUST contain only the 14 v1
predicate kinds defined in [`scope-predicate-v1.md`](scope-predicate-v1.md).
Reserved namespace labels MAY be advertised through
`predicate_basis.reserved_namespaces`, but v1 verifiers MUST NOT evaluate
reserved names.

## 5. Commitment Profile

`commitment_profile` is exactly `keel.scope_state.merkle.v1`; it is a pinned
semantic artifact, not inferred from the sidecar version. It fixes:

- RFC 6962/RFC 9162-style left-to-right Merkle tree topology.
- No duplicate-last-leaf padding.
- Leaf prefix `0x00` and node prefix `0x01`.
- SHA-256 as the hash function.
- The empty-tree representation
  `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Leaf canonical object and ordering rules.
- Predicate field lookup hierarchy.

Each `scope_commitments[]` entry binds:

- `predicate_value`
- `predicate_value_hash`
- `first_matching_sequence`
- `last_matching_sequence`
- `matching_count`
- `membership_root_hash`

`matching_count = 0` is valid. In that case `first_matching_sequence` and
`last_matching_sequence` MUST be `null`, and `membership_root_hash` MUST be the
empty-tree representation.

## 6. Signature Rule

The sidecar signature format is pinned by
`keel.scope_state.sidecar_format.v1`.

The Ed25519 signature signs the Keel canonical JSON bytes of the sidecar object
with `signature.signature` removed and every other field retained, including:

- `artifact_type`
- `version`
- `scope_state_id`
- `checkpoint_id`
- `chain_scope`
- `predicate_grammar_version`
- `predicate_basis`
- `commitment_profile`
- every `scope_commitments[]` entry
- `tree_size`
- `signed_at`
- `signature.algorithm`
- `signature.key_id`
- `trust_root_reference`

The signature field itself is encoded as `ed25519:<base64>`.

## 7. Trust Root Purpose

`scope_state` is a distinct key purpose. Initial physical key material MAY match
the `integrity_checkpoint` key material, but trust resolution MUST evaluate the
purpose declared by `trust_root_reference.purpose`.

The sidecar signing key is resolved from a `keel.public_key_manifest.v1`
manifest using the sidecar `signed_at` time and the key's active window.

## 8. Checkpoint Claim

`checkpoint.scope_state.v1` verifies that a `checkpoint_scope_state` sidecar is
signed by a trusted scope-state or checkpoint-class key, references an anchored
checkpoint whose `chain_heads` contain the declared `chain_scope`, uses a
supported predicate grammar, and names an allowlisted commitment profile.

Required evidence:

- `checkpoint_scope_state` sidecar JSON.
- Referenced checkpoint JSON.
- Trust-root/key manifest.
- Pinned sidecar-format semantics.
- Pinned scope-state Merkle commitment profile.

The verdict enum is unchanged:

- `supported`
- `disproved`
- `insufficient_evidence`
- `unverifiable_scope`

## 9. Adjudication Summary

The verifier:

1. Resolves the supplied sidecar.
2. Strictly schema-validates `checkpoint_scope_state.v1`.
3. Verifies the Ed25519 signature using the declared trust-root purpose.
4. Resolves and verifies the referenced checkpoint under existing checkpoint
   composite-hash and signature semantics.
5. Confirms the checkpoint contains the sidecar `chain_scope`.
6. Confirms commitment ranges do not exceed the checkpoint head sequence.
7. Confirms the predicate grammar is supported.
8. Resolves the commitment profile against the pinned semantic registry.
9. Recomputes every `predicate_value_hash`.
10. Rejects duplicate `predicate_value_hash` entries.

`tree_size` is signed for future consistency-proof adjudication. v1 records it
but does not require or compute cross-sidecar consistency proofs.
