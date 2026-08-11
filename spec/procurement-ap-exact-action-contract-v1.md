# Procurement and Accounts Payable exact-action contract v1

## Scope

This contract defines six exact Permit-to-X semantics for synthetic records in
one pinned, self-hosted Odoo database. The payment-release action additionally
binds a Stripe test-mode transfer destination and a two-step provider saga.

| Exact action | Human title | Consequence |
| --- | --- | --- |
| `procurement.vendor.create` | AI Permit-to-Create-Vendor | Create one synthetic supplier record without a bank account. |
| `procurement.purchase_order.issue` | AI Permit-to-Issue-Purchase-Order | Create one bounded Odoo draft purchase order; do not confirm, notify, invoice, or pay. |
| `procurement.spend.commit` | AI Permit-to-Commit-Procurement-Spend | Confirm one provider-observed draft purchase order within the observed demo budget. |
| `ap.invoice.approve` | AI Permit-to-Approve-Invoice | Post one unpaid synthetic draft vendor bill after a deterministic three-way match. |
| `ap.invoice.duplicate.reject` | AI Permit-to-Reject-Duplicate-Invoice | Cancel one unpaid draft bill only after an exact provider-derived duplicate match. |
| `ap.invoice.payment.release` | AI Permit-to-Release-Invoice-Payment | Authorize one Stripe test transfer plus matching Odoo payment registration as an explicit two-step saga. |

## Required enforcement boundary

The agent receives only Keel credentials. Odoo, PostgreSQL, Stripe, and MCP
credentials remain in Keel or a Keel-controlled gateway. Before policy
evaluation, the gateway reads the pinned provider state and creates a
short-lived authenticated preflight bound to the exact arguments,
idempotency key, connector contract, schema, request digest, and state digest.
The gateway verifies the same preflight and re-reads all material state before
any provider write.

All six actions require `max_uses=1`, a synthetic record declaration, and
provider readback. Unknown outcomes stop automatic retries. A completed replay
returns the journaled outcome only after the provider still matches it and
causes no additional provider write.

## Negative space

- Creating a vendor does not validate identity, tax status, or bank ownership.
- Issuing the purchase-order record leaves it in Odoo `draft`, sends no
  supplier notice, and commits no spend.
- Committing spend does not establish supplier acceptance, delivery, invoice,
  or payment.
- Approving or rejecting an invoice does not release money.
- Payment release in Stripe test mode does not establish bank settlement,
  supplier receipt, payment finality, or any real commercial obligation.
- Keel-mediated provider readback is not independent provider attestation.

## Co-signature and workflow truth

Policies may require a credentialed human co-signature before purchase-order
confirmation, invoice posting, invoice rejection, or payment release. REVIEW
must produce zero provider writes until the frozen request is ratified.

`ap.invoice.payment.release` is a workflow, not an atomic provider primitive.
Each step remains separately observable. Partial completion is reported as
partial or reconciliation-required; it is never rendered as a completed
invoice payment. Any compensation requires its own exact authorization.
