# Verifier Pack Pinning v0

Status: **DRAFT for PR2**. This file records the intended data model for
pack-pinned verifier semantics. It is not a released semantic artifact and does
not define final artifact hashes until PR2 creates and allowlists those
artifacts.

This draft extends [`verifier-claims-v0.md`](verifier-claims-v0.md). The
keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) once
this draft is finalized.

## 1. Purpose

Verifier claim verdicts must be durable across future verifier builds. Pack
pinning makes the claim registry, comparator, serialization, canonicalization,
digest, and artifact-format semantics explicit evidence-pack inputs rather than
mutable verifier defaults.

## 2. Pack fields

Pinned packs carry two top-level manifest blocks:

```json
{
  "claim_set": {
    "registry": {
      "id": "keel.verifier_claim_registry.v0",
      "hash": "sha256:<registry-artifact-bytes>"
    },
    "claims": [
      "export.integrity.v1",
      "governance_chain.local_continuity.v1"
    ]
  },
  "semantics_pins": {
    "schema": "keel-semantics-pins.v0",
    "profile": {
      "id": "keel.pre_pinning_default.v0",
      "hash": "sha256:<profile-artifact-bytes>"
    },
    "artifacts": [
      {
        "id": "keel.export_manifest.integrity.v1",
        "hash": "sha256:<semantic-artifact-bytes>"
      }
    ]
  }
}
```

`claim_set.registry` identifies the immutable claim registry artifact used to
interpret claim names and verdict values. `claim_set.claims` lists the claims
requested for the pack.

`semantics_pins.profile` MAY identify a profile artifact that expands to a
fixed set of semantic artifacts. `semantics_pins.artifacts` MAY additionally
pin individual semantic artifacts required by requested claims. The final PR2
resolver defines exact precedence, validation, and allowlist rules.

## 3. Legacy profile

`keel.pre_pinning_default.v0` is the explicit legacy profile for packs that
have no `claim_set` and no `semantics_pins`.

The profile expands to these component semantics:

1. `keel.verifier_claim_registry.v0`
2. `keel.export_manifest.integrity.v1`
3. `keel.governance_chain.record_hash.v1`
4. `keel.closure.format.v1`
5. `keel.closure.format.v2`
6. `keel.closure.digest_rules.v1`
7. `keel.permit_binding.canonical_request.v1`
8. `keel.workflow.canonicalization.v1`
9. `keel.workflow_evidence.sibling_integrity.v1`
10. `keel.incident.bundle_manifest.v2`
11. `keel.checkpoint.composite_hash.v1`
12. `keel.checkpoint.signature.v1`
13. `keel.checkpoint.tsa_imprint.v1`

Permit-chain claims that request authority-envelope comparison also require the
existing `authority-envelope.v0` comparator semantics. That comparator is
conditional on those claims and is not part of the base 13-component profile.

## 4. PR1 transition behavior

PR1 structured verifier output labels current unpinned packs as:

```json
{
  "mode": "legacy_unpinned",
  "profile_id": "keel.pre_pinning_default.v0",
  "profile_hash": null,
  "warning": "pack has no semantics_pins; evaluated under the permanent pre-pinning v0 profile"
}
```

`profile_hash` is `null` in PR1 because PR2 creates the immutable profile
artifact and its hash. PR1 does not dispatch on pins, enforce an allowlist, or
emit `claim_set` / `semantics_pins` from producers.

## 5. Finalization notes for PR2

PR2 must create released semantic artifacts, compute their hashes, and define a
permanent allowlist keyed by `(id, hash)`.

PR2 must reject malformed pinned packs without falling back to
`keel.pre_pinning_default.v0`. Unknown pinned semantics become
`unverifiable_scope`; missing required pinned semantics become
`insufficient_evidence`.
