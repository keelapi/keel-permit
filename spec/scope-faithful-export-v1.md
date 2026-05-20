# Scope-Faithful Export v1

This document specifies the `export.scope_faithfulness.v1` verifier claim and
the signed export-payload additions that allow an auditor to reconcile a
declared population or declared sample against a signed scope-state sidecar.

`export.scope_faithfulness.v1` adjudicates whether a signed export pack is a
scope-faithful slice of the recorded chain for the declared population or
declared sample up to the declared checkpoint boundary, and supports auditor
testing of the completeness assertion for the declared evidence population and
the accuracy assertion for records inside the declared scope.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Boundary Claim

Doctrine language is binding for this claim:

> Keel exports are not "complete" or "omission-proof." The verifier can prove whether an export is cryptographically intact and, with anchored scope reconciliation, whether the supplied export is a faithful slice of the recorded chain up to the declared checkpoint boundary. Recording coverage remains a runtime/instrumentation question, not a verifier claim.

The verifier never claims to prove completeness flatly. It produces evidence
the auditor uses in separate completeness testing. The signed export pack is
Information Produced by the Entity (IPE); this claim narrows whether the
supplied IPE is faithful to the declared population or declared sample and to
the checkpoint boundary named by the pack.

## 3. Standards Alignment

The design follows established transparency-log patterns without claiming
conformance to a receipt format it does not implement:

| Reference | Relevant pattern | Keel use |
|---|---|---|
| RFC 6962 / RFC 9162 Certificate Transparency | Append-only log, signed tree heads, inclusion and consistency proof vocabulary. | Keel uses a signed sidecar rather than mutating checkpoint entries. |
| SCITT architecture | Detached signed evidence and verifiable data structure pattern. | The sidecar is receipt-aligned, not a SCITT receipt. |
| COSE Merkle tree proofs work | Explicit Merkle topology and proof encoding discipline. | v1 pins topology so a future proof wrapper can reuse it. |
| Sigstore Rekor | Append-only Merkle-based transparency log with supplementary signed objects. | Scope-state evidence is a new signed object tied to a checkpoint. |

## 4. Export-Payload Additions

The `scope_faithfulness` block lives inside the exact export payload bytes
covered by `export.integrity.v1` through `manifest.content_hash`. It is not
trusted merely because it appears in the manifest envelope.

The additions are defined by
[`../schemas/export-scope-faithfulness-v1.schema.json`](../schemas/export-scope-faithfulness-v1.schema.json).
The top-level block is:

```json
{
  "scope_faithfulness": {
    "version": "keel.export_scope_faithfulness.v1",
    "segments": []
  }
}
```

Each segment covers one `chain_scope` and one referenced `checkpoint_scope_state`
sidecar. Multi-chain-scope exports MUST use multiple segments. A single segment
that contains entries from multiple `chain_scope` values fails with
`EXPORT_SCOPE_CHAIN_SCOPE_MISMATCH`.

## 5. Segment Fields

| Field | Purpose |
|---|---|
| `segment_id` | Stable segment identifier inside the export payload. |
| `declared_scope` | Structured declared population or declared sample: chain scope, predicate, and presentation policy. |
| `declared_start` | Start boundary: `genesis`, `predecessor_proof`, or `checkpoint_anchor`. |
| `declared_end` | Checkpoint boundary: checkpoint id, chain scope, sequence number, last record hash, and boundary policy. |
| `scope_state_reference` | Pointer to the signed sidecar used for reconciliation. |
| `canonical_filters` | Raw normalized filters and their canonical hash, signed for auditor inspection. |
| `chain_evidence.disclosure_records` | In-scope records presented as the declared sample or declared population. |
| `chain_evidence.proof_bridge_records` | Out-of-scope records supplied only to satisfy continuity. These records MUST NOT count as scope members. |

`canonical_filters.raw_filters` are audit-relevant IPE context. The verifier
does not infer scope from hash-only filters; it adjudicates only the structured
v1 predicate in `declared_scope.predicate`.

## 6. Presentation Policy

Plan-tier filtering is not predicate scope. It is represented by
`presentation_policy`, signed inside `declared_scope`.

The verifier adjudicates whether the export is faithful to the declared scope
with the declared `presentation_policy` applied. It does not adjudicate whether
the policy itself is commercially or operationally correct. The policy tells
the auditor what was redacted, projected, or restricted from the evidence pack.

## 7. Adjudication Summary

`export.scope_faithfulness.v1` runs once per segment:

1. Run `export.integrity.v1`; failure short-circuits.
2. Run `checkpoint.scope_state.v1` for the referenced sidecar; failure
   short-circuits.
3. Schema-validate the `scope_faithfulness` declaration.
4. Recompute `canonical_filters.filters_hash`.
5. Confirm all segment fields and records use the same `chain_scope`.
6. Confirm `declared_end` matches the sidecar checkpoint head.
7. Verify the declared start boundary.
8. Verify chain continuity over disclosure records plus proof bridge records.
9. Verify every disclosure record satisfies the v1 predicate after applying the
   presentation policy.
10. Verify proof bridge records are not counted as disclosure records.
11. Locate the sidecar commitment whose `predicate_value_hash` equals the hash
    of `declared_scope.predicate`.
12. Recompute the Merkle root from disclosure records only under
    `keel.scope_state.merkle.v1`.
13. Compare signed cardinality and first/last matching sequence values to the
    supplied disclosure records.

The aggregate export claim is `supported` only when every segment is
`supported`.

## 8. Evidence and Verdicts

Required evidence:

- `export.integrity.v1` evidence.
- Signed export-payload `scope_faithfulness` block.
- `checkpoint.scope_state.v1` sidecar evidence.
- Referenced checkpoint JSON.
- Chain entries separated into disclosure records and proof bridge records.
- Pinned governance-chain, export scope-faithfulness, and scope-state Merkle
  semantics.

The verdict enum is unchanged:

- `supported`
- `disproved`
- `insufficient_evidence`
- `unverifiable_scope`

Unsupported predicate grammar or predicate kind yields `unverifiable_scope`.
Malformed v1 syntax yields `disproved`. Missing sidecar or missing chain proof
evidence yields `insufficient_evidence`.
