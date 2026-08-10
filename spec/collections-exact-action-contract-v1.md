# Collections Arrangement exact action contract v1

This contract defines the four externally meaningful actions in Keel's
Collections Arrangement habitat. A model may propose an action, but only a
Keel-controlled gateway may resolve provider identifiers, read current state,
derive the exact facts, and dispatch after Keel authorizes that same snapshot.

| Tool | Real boundary | Permit |
| --- | --- | --- |
| `collections.payment.collect` | One exact Stripe test-mode PaymentIntent created and confirmed against one attached test payment method | `AI Permit-to-Collect-Payment` |
| `collections.payment_plan.create` | One finite Stripe test-mode subscription schedule created for one delinquent obligation | `AI Permit-to-Create-Payment-Plan` |
| `collections.autopay.change` | One existing Stripe test-mode subscription's collection method changed from the observed state to the requested state | `AI Permit-to-Change-Autopay` |
| `collections.notice.send` | One approved, versioned collections-notice template sent to one dedicated demo recipient | `AI Permit-to-Send-Collections-Notice` |

## Required enforcement order

1. The voice/browser agent holds only Keel credentials and stable demo aliases.
2. The Keel-controlled gateway resolves aliases and reads the current Stripe or
   notification-provider state.
3. The gateway signs a short-lived, single-use preflight binding the exact
   arguments, facts, action, connector audience, and current provider state.
4. Keel validates the action-specific fact contract and evaluates policy.
5. Deny and unapproved review outcomes terminate before any action-provider call.
6. Immediately before an allowed effect, the gateway verifies the preflight,
   re-reads authoritative state, refuses drift, and consults a durable
   exactly-once action journal.
7. The gateway dispatches once and records provider response and immediate
   readback separately from Keel authorization.

## Payment boundary

The Permit binds the delinquent obligation, customer, attached payment method,
amount, currency, remaining balance, consent-record digest, and exact
idempotency key. The amount cannot exceed the provider-observed remaining
balance. Authorization does not establish provider acceptance, settlement,
chargeback immunity, or legal collectability of the debt.

## Payment-plan boundary

The plan is a real finite Stripe subscription schedule, not a conversational
promise. The Permit binds the exact price, installment amount/count/interval,
total, remaining balance, start time, collection method, consent record, and
absence of an existing active plan. Creating the plan does not authorize its
future installment charges; those remain provider-scheduled effects under the
customer's recorded consent and Stripe configuration.

## Autopay boundary

Autopay is a separate authority from creating a plan. The gateway binds the
exact subscription, current collection method, requested collection method,
default-payment-method presence, effective time, and customer consent record.
Disabling autopay may change invoice handling; enabling it may cause future
provider-scheduled charges. Neither is implied by a payment-plan Permit.

## Notice boundary

The agent cannot supply arbitrary email HTML or choose an arbitrary recipient.
The gateway resolves one dedicated demo recipient and one operator-approved
template, then binds the template id/version/digest, rendered-content digest,
amount, due date, jurisdiction, reason, and prior-notice count. A provider
acceptance response does not establish delivery, receipt, legal sufficiency, or
compliance in a real jurisdiction.

## Outcome and evidence boundary

Keel authorization, gateway dispatch, provider response, and provider readback
are different evidence layers. Stripe and notification-provider responses are
Keel-mediated observations, not independent provider attestations. A timeout or
ambiguous provider outcome is never retried automatically; operator
reconciliation is required.
