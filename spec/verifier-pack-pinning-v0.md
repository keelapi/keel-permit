# Verifier Pack Pinning v0

Status: **released pre-publication v0**. This document defines the pack data
model for `verifier-claims.v0` semantic pinning. The released semantic artifact
bytes live under `../semantics/`.

This document extends [`verifier-claims-v0.md`](verifier-claims-v0.md). The
keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 1. Purpose

Verifier claim verdicts must be durable across future verifier builds. Pack
pinning makes the claim registry, comparator, serialization, canonicalization,
digest, and artifact-format recipes explicit evidence-pack inputs rather than
mutable verifier defaults.

## 2. Semantic artifact references

Every semantic artifact reference has:

- `id`: stable semantic artifact ID.
- `hash`: `sha256:<64 lowercase hex>` over the exact UTF-8 artifact bytes.
- one byte carrier: `content_b64` for inline bytes, or a pack-relative `path`
  to exact bytes supplied with the pack or explicit local registry bundle.

The verifier MUST decode or read the exact bytes, compute the declared hash,
and only then parse JSON. It MUST NOT hash a parsed or reserialized object.

A semantic artifact JSON object has `id`, `version`, `kind`, `status`, and
`body`. Released artifacts use `status: "released"`.

## 3. Top-level pack fields

Pinned packs carry both `claim_set` and `semantics_pins`.

```json
{
  "claim_set": {
    "version": "verifier-claims.v0",
    "registry": {
      "id": "keel.verifier_claim_registry.v0",
      "hash": "sha256:d4ff07076f823d3f6a9bd7ce17f6096b035ca466b8ec71996d5417e4957ec7c8",
      "path": "claim_registry/v0.json"
    },
    "claims": [
      {
        "name": "export.integrity.v1",
        "required": true
      },
      {
        "name": "closure.dispatch_binding.v1",
        "required": true
      }
    ]
  },
  "semantics_pins": {
    "version": "keel-semantics-pins.v0",
    "mode": "pinned",
    "profile": {
      "id": "keel.pre_pinning_default.v0",
      "hash": "sha256:8475b44ef4141b58687dd04ef3a59cc39619a7ab1083a629192b57ac5cf084fe",
      "path": "semantics/profiles/pre_pinning_default_v0.json"
    },
    "artifacts": [
      {
        "id": "keel.export_manifest.integrity.v1",
        "hash": "sha256:d1d67dca7eb9a662d26463c3dec841f47f8791df2fafb21e911dd26a83dabb76",
        "path": "semantics/export_manifest/integrity_v1.json"
      },
      {
        "id": "keel.closure.format.v2",
        "hash": "sha256:476b9aaf8f1b3e0fd46b9cfae522062e803ecbb1c24fdbb6ec60775b979d59f1",
        "path": "semantics/closure/format_v2.json"
      },
      {
        "id": "keel.closure.digest_rules.v1",
        "hash": "sha256:eca06d960a9e16468a622938a17b77244d487b58459be4dce3e55ef006f29454",
        "path": "semantics/closure/digest_rules_v1.json"
      },
      {
        "id": "keel.permit_binding.canonical_request.v1",
        "hash": "sha256:59633003ed97b2a65e756007fddd6f525a8c056de57a1cd40971034fa044f0ac",
        "path": "semantics/permit_binding/canonical_request_v1.json"
      }
    ]
  }
}
```

`claim_set.claims[].required` controls compatibility exit-code aggregation. It
does not change the claim semantics.

`semantics_pins.profile` MAY name a profile artifact. `semantics_pins.artifacts`
MUST still resolve every semantic required by requested claims, either directly
or via a resolved allowlisted profile. Direct artifacts MAY repeat profile
members if the bytes and hashes match.

## 4. Inline content example

The inline form carries the exact artifact bytes in `content_b64`. This example
inlines `keel.checkpoint.composite_hash.v1`; the verifier hashes the decoded
bytes and obtains
`sha256:68aafa26d6f1c8cf5ba83c7596209888d8e529d81f1a2c58f31e2fc41fc136de`.

```json
{
  "id": "keel.checkpoint.composite_hash.v1",
  "hash": "sha256:68aafa26d6f1c8cf5ba83c7596209888d8e529d81f1a2c58f31e2fc41fc136de",
  "content_b64": "ewogICJpZCI6ICJrZWVsLmNoZWNrcG9pbnQuY29tcG9zaXRlX2hhc2gudjEiLAogICJ2ZXJzaW9uIjogInYxIiwKICAia2luZCI6ICJjaGVja3BvaW50X2NvbXBvc2l0ZV9oYXNoX3JlY2lwZSIsCiAgInN0YXR1cyI6ICJyZWxlYXNlZCIsCiAgImJvZHkiOiB7CiAgICAiY29tcG9zaXRlX2hhc2hfZmllbGQiOiAiY2hlY2twb2ludC5jb21wb3NpdGVfaGFzaCBtdXN0IGJlIGEgc3RyaW5nIHN0YXJ0aW5nIHdpdGggc2hhMjU2OiIsCiAgICAiY2hhaW5faGVhZHNfc291cmNlIjogImNoZWNrcG9pbnQuY2hhaW5faGVhZHMgb3Ige30gd2hlbiBtaXNzaW5nL251bGwvZmFsc2V5IiwKICAgICJjaGFpbl9oZWFkc190eXBlIjogIm9iamVjdCByZXF1aXJlZCBhZnRlciBkZWZhdWx0aW5nIiwKICAgICJoZWFkX3ZhbGlkYXRpb24iOiB7CiAgICAgICJoZWFkIjogImVhY2ggdmFsdWUgbXVzdCBiZSBhbiBvYmplY3QiLAogICAgICAic2VxdWVuY2VfbnVtYmVyIjogIm11c3Qgc2F0aXNmeSBQeXRob24gaXNpbnN0YW5jZSh2YWx1ZSwgaW50KTsgYm9vbCBpcyBub3QgZXhjbHVkZWQgYnkgY3VycmVudCB2ZXJpZmllciIsCiAgICAgICJsYXN0X3JlY29yZF9oYXNoIjogIm11c3QgYmUgYSBzdHJpbmc7IG5vIGhleC9wcmVmaXggdmFsaWRhdGlvbiIKICAgIH0sCiAgICAiYWxnb3JpdGhtIjogewogICAgICAic29ydCI6ICJzb3J0IGNoYWluX2hlYWRzIGtleXMgbGV4aWNvZ3JhcGhpY2FsbHkgYnkgUHl0aG9uIHNvcnRlZChrZXlzKSIsCiAgICAgICJsaW5lX2Zvcm1hdCI6ICI8c2NvcGVfa2V5Pjo8c2VxdWVuY2VfbnVtYmVyPjo8bGFzdF9yZWNvcmRfaGFzaD4iLAogICAgICAiam9pbmVyIjogIlxuIiwKICAgICAgImVtcHR5X2lucHV0IjogInNoYTI1NiBvZiBlbXB0eSBieXRlIHN0cmluZyB3aXRoIHNoYTI1NjogcHJlZml4IiwKICAgICAgImVuY29kaW5nIjogInV0Zi04IiwKICAgICAgIm91dHB1dCI6ICJzaGEyNTY6PGxvd2VyY2FzZSBoZXggZGlnZXN0PiIKICAgIH0sCiAgICAiY29tcGFyZSI6ICJyZWNvbXB1dGVkIGNvbXBvc2l0ZSBoYXNoIG11c3QgZXF1YWwgY2hlY2twb2ludC5jb21wb3NpdGVfaGFzaCBleGFjdCBzdHJpbmciCiAgfQp9Cg=="
}
```

## 5. Legacy profile

An evidence pack with no `claim_set` and no `semantics_pins` is evaluated under
`keel.pre_pinning_default.v0`, never under mutable verifier build defaults.

The profile artifact is
`semantics/profiles/pre_pinning_default_v0.json` with hash
`sha256:8475b44ef4141b58687dd04ef3a59cc39619a7ab1083a629192b57ac5cf084fe`.
It expands to these base components:

| ID | Hash |
| --- | --- |
| `keel.verifier_claim_registry.v0` | `sha256:d4ff07076f823d3f6a9bd7ce17f6096b035ca466b8ec71996d5417e4957ec7c8` |
| `keel.export_manifest.integrity.v1` | `sha256:d1d67dca7eb9a662d26463c3dec841f47f8791df2fafb21e911dd26a83dabb76` |
| `keel.governance_chain.record_hash.v1` | `sha256:a3213706c9e9531a74cd2355f2f05e537c7a70604cb869b7b76c65cba4a2b707` |
| `keel.governance_event.integrity_digest.v1` | `sha256:7d3f447e215ca53dd5add04b4a62b4223d28ad22210b5a3df8fcbc85f5dbe440` |
| `keel.closure.format.v1` | `sha256:b208b82fbf8187ecdc85410630fbfa30f86f34c4da28d4b418c5788a8ec893ba` |
| `keel.closure.format.v2` | `sha256:476b9aaf8f1b3e0fd46b9cfae522062e803ecbb1c24fdbb6ec60775b979d59f1` |
| `keel.closure.digest_rules.v1` | `sha256:eca06d960a9e16468a622938a17b77244d487b58459be4dce3e55ef006f29454` |
| `keel.permit_binding.canonical_request.v1` | `sha256:59633003ed97b2a65e756007fddd6f525a8c056de57a1cd40971034fa044f0ac` |
| `keel.workflow.canonicalization.v1` | `sha256:b7359ae11dc1d8cfad51bf3e6fec32a0209bf38097a01fa4f878e3a068184501` |
| `keel.workflow_evidence.sibling_integrity.v1` | `sha256:c4e99745893e6c66afa89ad46602b0cf1931530f78875e18387381fca8c2a5aa` |
| `keel.incident.bundle_manifest.v2` | `sha256:ed112e365985d79192a4cb7c3248625d8294d2d2c5210ce31960eb7d55f4b9eb` |
| `keel.checkpoint.composite_hash.v1` | `sha256:68aafa26d6f1c8cf5ba83c7596209888d8e529d81f1a2c58f31e2fc41fc136de` |
| `keel.checkpoint.signature.v1` | `sha256:af16c66e8a0b295cd2e5e436169bf0e3d628c1fc4901b6eba6596e86e3ad256b` |
| `keel.checkpoint.tsa_imprint.v1` | `sha256:a4e02133537a190c3795737beb4bb2ddf823cd09d5b6dcba43c682fb9e37d79e` |
| `authority-envelope.v0` | `sha256:a2505ac94f27c1d0096fa977f25be699fa00a9ff507a0c4cbe0d1edf2e44cee2` |

Permit-chain delegation-denial verification requires both `keel.governance_event.integrity_digest.v1` and the existing `authority-envelope.v0` comparator as real semantic dependencies. The comparator bytes live at `comparator_registry/v0.json` and are allowlisted under the hash listed above.

## 6. Resolver failure mapping

The dispatch layer resolves semantic artifacts before running claim logic:

| Condition | Claim verdict |
| --- | --- |
| Required claim registry missing or unresolved | `insufficient_evidence` |
| Required semantic artifact missing or unresolved | `insufficient_evidence` |
| Resolved bytes do not match declared hash | `insufficient_evidence` |
| `(id, hash)` is not in the permanent allowlist | `unverifiable_scope` |
| Known semantics and invalid evidence | `disproved` |
| Known semantics and sufficient valid evidence | `supported` |

If either `claim_set` or `semantics_pins` is present, a verifier MUST NOT use
`keel.pre_pinning_default.v0` as a partial fallback.

## 7. Conformance records

Each recipe artifact has a small conformance record under
`../test_vectors/semantics/`. Those records contain minimal inputs and exact
outputs captured from the current `keel-verifier` functions. Pinned verifier
implementations MUST reproduce those outputs before they are wired to the
permanent allowlist.
