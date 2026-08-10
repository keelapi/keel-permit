# Transactional CX exact-action contract v1

This extension defines five customer-service actions whose provider effects are
materially different and therefore must not share a generic authorization:

| Exact action | Provider operation | Human artifact |
| --- | --- | --- |
| `payment.refund` | Stripe `refunds.create` | `AI Permit-to-Refund-Payment` |
| `customer.credit.issue` | Stripe `customer_balance_transactions.create` | `AI Permit-to-Issue-Account-Credit` |
| `subscription.cancellation.schedule` | Stripe `subscriptions.update` with `cancel_at_period_end=true` | `AI Permit-to-Schedule-Subscription-Cancellation` |
| `subscription.cancellation.withdraw` | Stripe `subscriptions.update` with `cancel_at_period_end=false` | `AI Permit-to-Withdraw-Subscription-Cancellation` |
| `support.case.resolve` | HubSpot ticket stage update | `AI Permit-to-Resolve-Support-Case` |

The withdrawal action applies only while period-end cancellation is pending.
It does not claim to reinstate an already canceled or ended subscription.

## Trusted preflight

Each action requires a short-lived gateway-authenticated provider preflight.
The signed facts bind the connector contract, exact arguments, provider
environment and API version, observed provider state, preflight expiry,
idempotency identity, and the requested mutation. The agent cannot supply the
trusted connector identity, provider observation, or closed-stage metadata.

For support-case resolution, the gateway reads the ticket and its ticket
pipeline, then selects a stage whose provider metadata declares
`ticketState=CLOSED`. A label such as "Closed" is not sufficient. The request
binds both the observed open stage and selected closed stage.

## Action-specific invariants

- Refund amount is positive and no greater than the provider-observed
  refundable amount. Connect fee refund and transfer reversal are false unless
  a future, separately named action authorizes those effects.
- Account credit uses a positive human credit amount and an equal-magnitude
  negative Stripe balance-transaction amount. Its expected ending balance is
  the observed balance minus the positive credit amount.
- Scheduling requires an active, trialing, or past-due subscription whose
  `cancel_at_period_end` value is false.
- Withdrawal requires `cancel_at_period_end=true` and null provider
  `canceled_at` and `ended_at` values.
- Support resolution requires an OPEN current stage, a provider-declared CLOSED
  destination stage, a provider-state recheck immediately before mutation, and
  durable gateway idempotency because the HubSpot ticket update endpoint does
  not provide the same request-level idempotency primitive as Stripe.

## Evidence boundary

The Permit establishes exact pre-execution authorization. A dispatch record
establishes that the controlled gateway attempted the bound provider call. A
provider response or later provider read can support provider outcome, but is
not independent attestation and does not prove financial settlement, customer
satisfaction, future renewal success, or absence of a concurrent provider
update. Those limitations remain explicit in every presentation profile.
