# Dispatch Absence After Revocation v1

This document specifies the
`permit.dispatch_absence_after_revocation.v1` verifier claim.

The claim provides scope-faithful absence adjudication for post-revocation
dispatch initiation. It adjudicates the absence of `dispatch.egress_bound`
events within a declared, signed, checkpoint-bounded scope. It does not claim
omniscient knowledge of all possible history.

---

## 1. Conformance Keywords

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Claim Scope

`permit.dispatch_absence_after_revocation.v1` depends on:

- `permit.revoked.v1` for a supported signed revocation event.
- `checkpoint.scope_state.v1` for a supported signed sidecar bound to the
  checkpoint and chain scope.
- `export.scope_faithfulness.v1` for a supported signed export segment whose
  declared scope matches this claim.

The primary predicate covers only dispatch initiation:

```json
{
  "version": "keel.scope_predicate.v1",
  "operator": "and",
  "equals": {
    "project_id": "<revocation.project_id>",
    "permit_id": "<revocation.permit_id>",
    "event_type": "dispatch.egress_bound"
  },
  "ranges": {
    "occurred_at": {
      "gte": "<revocation.effective_at>",
      "lt": "<checkpoint_boundary>"
    }
  }
}
```

Both `occurred_at` bounds are REQUIRED. Open-ended ranges are not valid for this
claim.

The lower bound is `occurred_at >= revocation.effective_at`. The upper bound is
`occurred_at < checkpoint_boundary`. In v1, `revocation.effective_at` equals
`revocation.revoked_at` under
[`permit-revoked-event-v1.md`](permit-revoked-event-v1.md).

## 3. Predicate Grammar

The predicate MUST use `keel.scope_predicate.v1`, defined in
[`scope-predicate-v1.md`](scope-predicate-v1.md). v1 is AND-of-equality plus
bounded ranges only. `IN`, OR, NOT, wildcard, regex, script, CEL, Rego, and
multi-event-type predicates are out of grammar.

Step 4 uses a single event type segment:
`event_type == "dispatch.egress_bound"`.

A predicate that requires a grammar extension returns `unverifiable_scope` with
`EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR` or
`EXPORT_SCOPE_PREDICATE_UNSUPPORTED`. Predicate syntax that claims v1 but
violates the v1 shape returns `disproved` with
`EXPORT_SCOPE_PREDICATE_MALFORMED`.

## 4. Primary and Corroborating Events

The only primary disproof event type is `dispatch.egress_bound`.

The following event types are corroborating evidence, not primary disproof:

- `execution.completed`
- `provider.response.received`
- `client.response.delivered`

Post-revocation completion can be legitimate for work that was dispatched
before revocation. A verifier MUST NOT disprove this claim solely because a
downstream completion event occurs after `revoked_at`.

## 5. Scope-Faithful Absence Adjudication

Scope-faithful absence adjudication means the verifier checks the declared
predicate against the supplied signed export segment and its signed
checkpoint-scope sidecar. For this claim, `supported` requires:

- The revocation event is supported for the same `permit_id` and `project_id`.
- The declared predicate exactly covers the post-revocation
  `dispatch.egress_bound` scope described in §2.
- The sidecar commitment for that predicate has `matching_count == 0`.
- No disclosure, bridge, proof, or continuity record supplied in the pack
  satisfies the declared predicate.
- The checkpoint boundary is the declared upper bound.

If a bridge, proof, or continuity record satisfies the predicate, the verifier
returns `disproved` or emits
`EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE`. This is not
`unverifiable_scope`: the predicate can be evaluated, and the supplied evidence
contradicts the claimed empty matching set.

## 6. Trust Model

The verifier's trust model is falsifiability-oriented, not
omniscience-oriented. Keel's verifier does not claim omniscient proof over all
possible history; it claims independently auditable scoped evidence whose
dishonesty is detectable under declared assumptions.

An auditor with chain access can falsify a dishonest sidecar by independently
re-walking the chain and recomputing the matching set against the declared
predicate.

## 7. Standards Context

Keel's v1 scope-state commitment uses RFC 9162-style Merkle tree construction
for membership roots. [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)
defines Certificate Transparency v2 and specifies Merkle inclusion and
consistency proof machinery for append-only transparency logs.

The COSE Merkle Tree Proofs draft
([draft-ietf-cose-merkle-tree-proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/))
registers COSE receipt structures for verifiable data structure proofs,
including RFC 9162 inclusion and consistency receipts. This v1 claim does not
depend on a COSE proof type for native non-membership.

The SCITT architecture draft
([draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/))
describes receipts and Verifiable Data Structures as implementation-specific
proof semantics for transparency services. Keel's v1 claim therefore states
its own scoped predicate, checkpoint, sidecar, and trust assumptions rather
than importing stronger semantics from SCITT or COSE.

## 8. Reserved Future Namespace

`non_membership_profile` is a reserved semantic-registry namespace for future
SMT, NMT, or accumulator-backed native non-membership semantics. It is not
implemented in v1, and v1 verifiers MUST NOT evaluate it as current Step 4
behavior.

The reservation follows the same name-reservation discipline as
[`permit-v1.md`](permit-v1.md) §11 reserves `signature` and
`counter_signature`.

## 9. Correct Framing

Correct: "The verifier performs scope-faithful absence adjudication for
post-revocation `dispatch.egress_bound` events within the declared signed scope
and checkpoint boundary."

Correct: "A post-revocation `execution.completed` event may corroborate a
timeline, but it does not by itself disprove the claim."

Incorrect: "The verifier proves that no execution occurred after revocation."

Incorrect: "A completion event after revocation always disproves the claim."

## 10. Claim Verdicts

`supported`: the scope is valid, all dependency claims are supported, the
predicate is in grammar, the matching count is zero, and no supplied record
satisfies the predicate.

`disproved`: a matching post-revocation `dispatch.egress_bound` record exists
in the declared scope, a bridge/proof/continuity record satisfies the
predicate, or the signed sidecar commitment contradicts disclosed evidence.

`insufficient_evidence`: required revocation, checkpoint, sidecar, export,
trust-root, or pinned-semantic evidence is missing.

`unverifiable_scope`: the scope predicate, grammar version, range shape, or
commitment profile is unsupported.

## 11. Failure Codes

Applicable standard failure codes are defined in
[`failure-codes.md`](failure-codes.md):

- `EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR`
- `EXPORT_SCOPE_PREDICATE_UNSUPPORTED`
- `EXPORT_SCOPE_PREDICATE_MALFORMED`
- `EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE`
- `EXPORT_SCOPE_CARDINALITY_MISMATCH`
- `EXPORT_SCOPE_COMMITMENT_MISSING`
- `CHECKPOINT_SCOPE_STATE_MISSING`
- `CHECKPOINT_SCOPE_STATE_COMMITMENT_PROFILE_UNKNOWN`

The pinned semantic artifact is
[`../semantics/permit/dispatch_absence_after_revocation_v1.json`](../semantics/permit/dispatch_absence_after_revocation_v1.json).
