# Verifier Claims v0

This document defines the durability invariant and verdict semantics for
`verifier-claims.v0`, published in [`../claim_registry/v0.json`](../claim_registry/v0.json).

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 1. Verdict-durability invariant

> A v0 evidence pack must verify to the same claim verdict on every future public verifier, forever. The verifier must pin comparator, serialization, canonicalization, digest, and claim semantics from the pack itself, never from the verifier build that happens to run later.

## 2. Verdict values

The only verdict values for `verifier-claims.v0` are:

- Missing pack-pinned semantics -> `insufficient_evidence`.
- Unknown pack-pinned semantics -> `unverifiable_scope`.
- Known pack-pinned semantics with invalid evidence -> `disproved`.
- Known pack-pinned semantics with sufficient valid evidence -> `supported`.

## 3. Registry relationship

The claim registry defines stable claim names, assertions, required evidence,
and the allowed verdict enum. It is the source of truth for claim definitions,
not a record of current verifier implementation coverage.

A released claim registry version is immutable. Any change to a claim's
assertion, required evidence, or verdict semantics requires a new registry
version. Historical evidence packs MUST continue to resolve the claim
definitions they pinned when they were produced.

## 4. Pack-pinned semantics

Pinned evidence packs that assert `verifier-claims.v0` claims MUST carry two
top-level manifest blocks: `claim_set` and `semantics_pins`.

`claim_set` MUST be a JSON object with:

- `version`: exactly `verifier-claims.v0`.
- `registry`: an artifact reference whose `id` is
  `keel.verifier_claim_registry.v0` and whose `hash` is the `sha256:<hex>` hash
  of the exact UTF-8 bytes of `claim_registry/v0.json`.
- `claims`: a non-empty array of objects. Each object MUST have `name` matching
  a claim in the resolved registry and `required` as a boolean.

`semantics_pins` MUST be a JSON object with:

- `version`: exactly `keel-semantics-pins.v0`.
- `mode`: exactly `pinned`.
- `artifacts`: an array of artifact references for every non-registry semantic
  required by the requested claims.

Artifact references MUST name `id` and `hash`. They MUST also provide a way to
resolve the exact artifact bytes, either inline with `content_b64` or by a
hash-addressed path/reference supplied with the pack or an explicit local
registry bundle. The hash is computed over the resolved bytes before JSON
parsing. A verifier MUST NOT hash a parsed or reserialized JSON object.

The same pinning rule applies to comparator, serialization, canonicalization,
digest, and artifact-format semantics required by a claim. The
`authority-envelope.v0` comparator is a semantic artifact and MUST be pinned
when a requested claim depends on authority-envelope comparison.

A verifier MUST evaluate claims against the semantics pinned by the pack, not
against mutable defaults from the verifier build. Resolution failures are
mapped before claim logic runs:

- Required claim registry missing or unresolved -> `insufficient_evidence`.
- Required semantic pin missing or unresolved -> `insufficient_evidence`.
- Resolved artifact bytes do not match the declared hash ->
  `insufficient_evidence`.
- `(id, hash)` not in the verifier's permanent allowlist ->
  `unverifiable_scope`.

If either `claim_set` or `semantics_pins` is present, the verifier MUST NOT
partially fall back to `keel.pre_pinning_default.v0`.

## 5. Unpinned legacy packs

A pack with no `claim_set` and no `semantics_pins` MUST be evaluated under the
explicit legacy semantic profile `keel.pre_pinning_default.v0`.

The absence of pins MUST NOT be interpreted as permission to evaluate against
mutable verifier build defaults. `keel.pre_pinning_default.v0` is the stable
profile label for pre-pinning v0 evidence packs, including the frozen
verifier-claim corpus.

If either `claim_set` or `semantics_pins` is present, the pack is no longer an
unpinned legacy pack. A verifier MUST NOT partially fall back to
`keel.pre_pinning_default.v0` for malformed or incomplete pinned-pack
semantics.

## 6. Pre-publication claim clarifications

For `closure.digest_consistency.v1`, catalog-approved provider/client digest
evidence is either the specific `provider.response.received` and
`client.response.delivered` events, or an `execution.completed` event carrying
the corresponding `provider_response_digest_v1` and
`client_response_digest_v1` fields. This clarification is part of local v0
finalization before publication; after publication, semantic changes require a
new registry version.

## 7. `permit_chain.delegation_denied_correctly.v1`

This claim adjudicates whether a supplied `permit.delegated_denied` governance
event was correctly denied under pinned permit-chain semantics. The verifier
MUST evaluate this claim with the pinned `keel.governance_chain.record_hash.v1`,
`keel.governance_event.integrity_digest.v1`, and `authority-envelope.v0`
artifacts. Missing pins resolve before claim logic as
`insufficient_evidence`; unknown artifact hashes resolve as
`unverifiable_scope`.

Required evidence inputs:

- A `permit.delegated_denied` governance event, or an event collection containing
  one. If more than one denied event is supplied, the caller MUST provide
  `event_id`.
- Strict supplied chain fields for every event in the evidence collection:
  `event_id`, `event_type`, `severity`, `occurred_at`, `sequence_number`,
  `record_hash`, and `prev_hash`.
- A contiguous supplied prefix per `chain_scope`, starting at sequence `1` with
  the genesis prev_hash `sha256("keel-audit-chain-genesis-v1")` as lowercase
  hex without prefix. Each next event's `prev_hash` MUST equal the previous
  event's `record_hash`.
- An `audit.integrity_digest` event whose payload covers the target denied
  event with `covered_events`, `covered_event_count`, and `batch_hash` under the
  pinned governance-event integrity-digest recipe.
- Target payload fields: `authority_envelope_version`,
  `child_requested_authority_envelope`, `failed_fields`, and `reason_code`.
  `parent_authority_envelope` is required except for
  `reason_code == "authority_envelope.parent_missing"` with
  `failed_fields` containing `authority_envelope`.

Verdict schema:

- `supported`: the strict chain prefix verifies, the integrity digest covers the
  target payload, and rerunning the pinned authority-envelope comparator proves
  the recorded denial.
- `disproved`: the chain or integrity digest is tampered, the comparator allows
  the child authority, or recorded `failed_fields` differ from comparator output.
- `unverifiable_scope`: the evidence names an authority envelope version or
  semantic artifact hash outside the verifier's allowlist.
- `insufficient_evidence`: required chain fields, integrity-digest coverage,
  semantic pins, version fields, comparable envelopes, or disambiguating
  `event_id` are missing or malformed.

Result shape for the public claim helper is a JSON object with
`claim_type: "delegation_denied_correctly"`, `status`, `supported_checks`,
`missing_requirements`, `errors`, `supported_envelope_versions`, and, when
applicable, `event_id`, `failed_fields`, `comparison_details`,
`expected_failed_fields`, and `event_failed_fields`.

Failure modes include `chain_events`, `chain_field:<field>`,
`contiguous_chain_prefix`, `prev_hash_mismatch`, `record_hash_mismatch`,
`payload_integrity_digest`, `payload_integrity_mismatch`,
`integrity_digest_batch_hash_mismatch`, `integrity_digest_resource_mismatch`,
`integrity_digest_count_mismatch`, `unsupported_authority_envelope_version`,
`comparable_authority_envelopes`, `comparator_allows_child_authority`, and
`failed_fields_mismatch`.
