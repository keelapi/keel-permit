# `quota.reservation_linkage.v1`

Status: released (gated on ratification before publication with the verifier release train).

This claim links a quota / cost-permit **reservation** to the **permit or execution** that consumed it. The linkage is reconciled over the append-only budget-allocation event family grouped by `reservation_id`, and the verifier emits an explicit **attestation grade** so a downstream reader can never mistake unsigned-row evidence for signed-identity evidence, nor unanchored evidence for anchored evidence.

The reference producer is [keel-api](https://github.com/keelapi/keel-api) (the `budget_allocation_events` ledger, gated behind `KEEL_R4_RESERVATION_LEDGER`). The pinned recipe is `semantics/quota/reservation_linkage_v1.json`.

## Evidence

Two evidence shapes, in decreasing strength:

1. **Signed identity** — a detached signed digest over the reservation-linkage tuple `{project_id, budget_envelope_id|cost_permit_id, permit_id|execution_id, request_id, reserved_amount, reservation_event_id|reservation_id, signing_time}`, verifiable against a `permit_binding_signing` key from the supplied trust root active at `signing_time`. **Not produced by this build** (demand-gated); reserved for the strongest grade.
2. **Unsigned rows** — `budget_allocation_events` rows carried inside a verified self-attesting compliance-export bundle. The grouping key (`reservation_id`) is **unsigned**; the integrity of the row *set* derives from the bundle's anchor when present.

## Reconciliation

For a `reservation_id`, the per-permit transitions `reserve`, `reserve_adjust`, `release`, `commit` reconcile a single reservation lifecycle:

- A re-price is a `reserve_adjust` under the **same** `reservation_id` — there is no `supersede`.
- A reservation is consumed by exactly one `permit_id`.
- Conservation: `reserved == Σ(reserve + reserve_adjust amounts) − Σ(release amounts) − Σ(commit.reserved_released)` and `spent == Σ(commit.spent_added)`, where `commit.spent_added` is the **clamped** applied delta `min(actual, cap − spent)`, not the raw actual.

## Attestation grade (anchor-contingent)

The verifier reports a machine-checkable `epistemic_state.trust_grade`, ordered strictly:

| grade | order | meaning |
|---|---|---|
| `signed_identity` | 30 | The linkage tuple is signed or recoverable from signed canonical identity evidence. Outranks anchor state. |
| `keel_attested_unsigned` | 20 | Unsigned grouping key, but the event set is inside a verified bundle whose signed body carries an **accepted anchor**. Keel-attested with external anchor context — never "independent". |
| `keel_self_signed_unanchored` | 10 | Unsigned grouping key **and** no accepted body anchor. The report proves only that Keel self-signed the export, not that the row set is anchored to a published checkpoint. |

The grade for unsigned-row evidence is **contingent on the verified bundle body's anchor state**, keyed off `body.anchor` only — never off manifest text, API metadata, filenames, download route, caller flags, or producer-declared labels. TSA receipts in the signature envelope **without** `body.anchor` do not make a bundle anchored for this claim.

**Hard rule:** over an unanchored bundle the verifier MUST NOT emit `keel_attested_unsigned`. It either withholds the claim or emits it as `supported` with `trust_grade=keel_self_signed_unanchored`. When a caller pins `minimum_trust_grade >= keel_attested_unsigned`, unanchored unsigned evidence yields `insufficient_evidence` (fail-closed).

## Verdicts

- `supported` — a reservation lifecycle reconciles for a `reservation_id` and links to a single permit/execution; `trust_grade` is set from evidence + anchor state.
- `disproved` — the signed-identity tuple conflicts with the unsigned-row tuple, conservation fails, or a reservation links to more than one permit. Failure code `RESERVATION_LINKAGE_CONFLICT`.
- `insufficient_evidence` — the linkage tuple cannot be determined, the bundle wrapper/signature cannot be validated, or a requested minimum trust grade is not met. Failure code `RESERVATION_LINKAGE_INSUFFICIENT`.
- `unverifiable_scope` — the canonicalization profile, trust-root profile, or bundle schema is unsupported.
