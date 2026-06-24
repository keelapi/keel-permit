# `budget.partition_ledger.v1`

Status: released (gated on ratification before publication with the verifier release train).

Within a budget envelope, the sum of **active** agent-allocation caps must not exceed the envelope capacity. This claim recomputes that sum from the append-only **cap-lifecycle** event family rather than the mutable cap, so it is reproducible offline from the anchored event set.

The reference producer is [keel-api](https://github.com/keelapi/keel-api) (`budget_allocation_events`, `metric = agent_allocation_cap`). The pinned recipe is `semantics/budget/partition_ledger_v1.json`.

## Evidence

Cap-lifecycle rows from `budget_allocation_events` carried inside a verified self-attesting compliance-export bundle: `transition ∈ {cap_allocate, cap_update, cap_deactivate}`, each carrying `allocation_id`, `is_active`, and the cap `amount`.

## Replay

- Group cap-lifecycle events by `allocation_id`. The current cap and active state of an allocation are the `amount` and `is_active` of its **latest** event by `seq`.
- An allocation contributes its cap to the partition sum only when its latest event leaves `is_active = true`.
- Invariant, per envelope: `Σ(latest active allocation caps) ≤ envelope.total_budget_usd_micros`.
- The replay reads the cap-lifecycle **events**, never the mutable `allocation.cap_usd_micros`.

## Anchor dependency

As with [`quota.reservation_linkage.v1`](quota-reservation-linkage-v1.md), the strength of this claim depends on the verified bundle body's anchor state. Over an unanchored bundle the event set carries only Keel's export signature; the verifier surfaces that via the same anchor-keyed grade discrimination and never implies external anchoring when `body.anchor` is absent.

## Verdicts

- `supported` — the active-cap sum recomputed from events is `≤` envelope capacity for every envelope in scope.
- `disproved` — the active-cap sum exceeds envelope capacity for some envelope when replayed from events. Failure code `PARTITION_LEDGER_OVERCOMMIT`.
- `insufficient_evidence` — cap-lifecycle events or the envelope capacity for an in-scope allocation are missing, or the bundle wrapper/signature cannot be validated. Failure code `PARTITION_LEDGER_INSUFFICIENT`.
- `unverifiable_scope` — the canonicalization profile or bundle schema is unsupported.
