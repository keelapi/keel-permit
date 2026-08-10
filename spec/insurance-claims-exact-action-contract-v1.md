# Insurance Claims exact action contract v1

This contract defines four externally meaningful actions in Keel's synthetic
Insurance Claims habitat. A model may propose an action, but only a
Keel-controlled gateway may resolve demo aliases, read current state, derive
the exact facts, and dispatch after Keel authorizes that same snapshot.

| Tool | Real boundary | Permit |
| --- | --- | --- |
| `insurance.claim.decision.record` | One approve-or-deny determination appended to one synthetic claim after an eligible human approver co-signs the exact Permit | `AI Permit-to-Decide-Claim` |
| `insurance.claim.settlement.set` | One exact settlement record created in the synthetic claims system for one approved claim | `AI Permit-to-Settle-Claim` |
| `insurance.claim.payment.send` | One Stripe test-mode Connect transfer created to one allowlisted demo claimant destination | `AI Permit-to-Pay-Claim` |
| `insurance.claim.notice.send` | One approved, versioned determination notice sent by Resend to one dedicated demo recipient | `AI Permit-to-Send-Claim-Determination-Notice` |

## Required enforcement order

1. The claims agent holds only Keel credentials and stable demo aliases.
2. The Keel-controlled gateway resolves aliases and reads the current claims,
   Stripe, or notification-provider state.
3. The gateway signs a short-lived, single-use preflight binding the exact
   arguments, facts, action, connector audience, and current provider state.
4. Keel validates the action-specific fact contract and evaluates policy.
5. A claim determination and a settlement record always enter review under a
   pre-execution `require_co_signature` rule. The approver must be an eligible
   claims adjuster, must be separate from the requester, and must co-sign the
   exact Permit decision with WebAuthn before dispatch.
6. Deny and unapproved review outcomes terminate before any claims-system,
   payment-provider, or notification-provider action call.
7. Immediately before an allowed effect, the gateway verifies the preflight,
   re-reads authoritative state, refuses drift, and consults a durable
   exactly-once action journal.
8. The gateway dispatches once and records provider response and immediate
   readback separately from Keel authorization.

## Determination boundary

The Permit binds the claim, policy, claimant, proposed approve-or-deny outcome,
controlled reason code, evidence and criteria-pack digests, current claim
state, and the signed co-signature requirement. The co-signature is separate
evidence: a fact saying that review is required is not itself proof of human
approval. A verified co-signature proves that the registered credential
approved this exact Permit; it does not prove the legal correctness of the
coverage determination or the identity, license, or independent judgment of a
real-world adjuster.

## Settlement boundary

Settlement is a separate authority from determining coverage and has its own
human co-signature requirement. The Permit binds the approved decision record,
requested settlement, covered amount, policy limit, currency, controlled terms
template, and absence of an existing settlement. The settlement cannot exceed
the covered amount or policy limit. Creating a settlement record does not move
money or notify the claimant.

## Payment boundary

Payment is a separate authority from both determination and settlement. The
Permit binds one approved settlement, one allowlisted Stripe test connected
account, the exact remaining payable amount, currency, transfer group, and
idempotency key. Keel authorization does not establish Stripe acceptance,
bank settlement, recipient receipt, finality, or the validity of a real claim.

## Notice boundary

The agent cannot supply arbitrary email HTML or choose an arbitrary recipient.
The gateway resolves one dedicated demo recipient and one operator-approved
template whose outcome matches the recorded determination, then binds the
template version and digest, rendered subject/content digests, decision record,
settlement amount when applicable, appeal instructions, and jurisdiction. A
Resend acceptance response does not establish delivery, receipt, legal
sufficiency, or compliance in a real jurisdiction.

## Outcome and evidence boundary

Keel authorization, human co-signature, gateway dispatch, provider response,
and provider readback are different evidence layers. Stripe, Resend, and the
synthetic claims system are Keel-mediated observations, not independent
attestations. A timeout or ambiguous provider outcome is never retried
automatically; operator reconciliation is required. The habitat uses only
synthetic people, policies, and claims and must never contain real claimant
data.
