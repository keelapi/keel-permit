# Commerce and regulated-workflow exact-action contract v1

## Scope

This contract defines exact Permit-to-X semantics for four real demo habitats:
a test storefront, a synthetic benefits case system, a self-hosted HAPI FHIR
prior-authorization workflow, and a self-hosted HAPI FHIR patient-administration
workflow.

| Exact action | Human title |
| --- | --- |
| `commerce.order.place` | AI Permit-to-Place-Order |
| `commerce.merchant.pay` | AI Permit-to-Pay-Merchant |
| `commerce.inventory.reserve` | AI Permit-to-Reserve-Inventory |
| `benefits.case.grant` | AI Permit-to-Grant-Benefit |
| `benefits.case.deny` | AI Permit-to-Deny-Benefit |
| `benefits.eligibility.change` | AI Permit-to-Change-Benefit-Eligibility |
| `benefits.payment.issue` | AI Permit-to-Issue-Benefit-Payment |
| `benefits.determination.notice.send` | AI Permit-to-Send-Benefit-Determination-Notice |
| `healthcare.prior_authorization.submit` | AI Permit-to-Submit-Prior-Authorization |
| `healthcare.prior_authorization.clinical_information.request` | AI Permit-to-Request-Clinical-Information |
| `healthcare.prior_authorization.approve` | AI Permit-to-Approve-Prior-Authorization |
| `healthcare.prior_authorization.deny` | AI Permit-to-Deny-Prior-Authorization |
| `healthcare.appointment.schedule` | AI Permit-to-Schedule-Appointment |
| `healthcare.claim.submit` | AI Permit-to-Submit-Healthcare-Claim |
| `healthcare.patient_administrative_record.update` | AI Permit-to-Update-Patient-Administrative-Record |

## Required enforcement boundary

The agent receives only Keel credentials. Stripe, PostgreSQL, storefront,
HAPI FHIR, and mail-sink credentials remain in Keel or a Keel-controlled
gateway. The gateway reads the exact provider state and issues a short-lived
authenticated preflight bound to the action, complete arguments, idempotency
key, connector contract, request digest, and state digest. It verifies that
preflight and re-reads every material provider fact immediately before a write.

Every action is single use and fail closed. DENY and unresolved REVIEW produce
zero provider calls. Completed replays return a durable journaled outcome only
after provider readback agrees; unknown outcomes stop automatic retry.

## Co-signature and review

Granting or denying benefits, changing benefit eligibility, issuing benefit
payments, and approving or denying prior authorization require a credentialed
human co-signature in the demo policy. REVIEW freezes the exact request. Any
edited request is a new authorization request, not a ratification.

## Negative space

- Stripe test-mode actions do not establish settlement, recipient receipt,
  payment finality, or a real obligation.
- Synthetic benefits actions do not establish identity, legal eligibility,
  due process, appeal finality, or a decision about a real person.
- Synthetic FHIR actions do not establish medical necessity, clinical
  correctness, real coverage, real care, payer adjudication, or legal
  compliance.
- Storefront and inventory actions do not establish fulfillment, acceptance,
  delivery, or a real purchase.
- Keel-mediated readback and gateway-local counters are not independent
  provider attestation.
