# ERP/CRM exact-action contract v1

Status: released contract candidate

This contract defines three provider-bound HubSpot actions used by the ERP/CRM
Operations habitat. It does not authorize a generic CRM write and it does not
turn a draft quote into a signed or accepted agreement.

## Environment boundary

- `provider_environment` MUST be `developer_test`.
- `connector_identity` MUST be the operator-registered value `hubspot`.
- `provider_account_type` MUST be `DEVELOPER_TEST` and the observed portal MUST
  match the gateway's pinned portal commitment.
- The access token and MCP bearer terminate in a Keel-controlled gateway. The
  agent receives only Keel credentials.
- All records MUST be synthetic fixtures in a dedicated HubSpot developer-test
  account. These actions are not eligible for a standard or production portal.

## `crm.deal.stage.change`

Customer title: **AI Permit-to-Change-Deal-Stage**

The authorization binds one deal and pipeline, the provider-observed current
stage and record update time, the exact requested stage, an allowed-transition
decision derived by the gateway, and a digest of the complete pre-write state.
The gateway MUST re-read the deal and pipeline immediately before dispatch and
MUST reject stale or mutated state. After the PATCH it MUST re-read the same deal
and report the observed stage separately from authorization evidence.

It does not establish that the deal is commercially valid, that a stage change
is correct under the operator's sales process, or that the provider state
remains unchanged after the immediate readback.

## `crm.customer.record.update`

Customer title: **AI Permit-to-Update-Customer-Record**

The authorization binds one synthetic contact, exactly one operator-allowlisted
property, commitments to the provider-observed value before and the requested
value after, the provider update time, the property's definition digest, and a
digest of the complete pre-write state. Arbitrary property maps, association
changes, batch updates, deletes, and upserts are outside this action.

The gateway MUST re-read the contact and property definition immediately before
dispatch, reject non-allowlisted or read-only properties, and re-read the same
contact after the PATCH. The permit keeps values committed by default; any
human-readable opening is optional, separately disclosed, and not needed for
offline verification.

It does not establish the truth of the customer data, consent for downstream
use, or absence of later writes by other HubSpot users or integrations.

## `crm.quote.create`

Customer title: **AI Permit-to-Create-Quote**

The authorization binds one deal, one bounded set of existing line items, their
provider-observed pricing state, currency and computed total, the quote title
commitment, expiration date, exact associations, and a preflight proving that
the idempotency marker is absent. The authorized quote state is `DRAFT`; payment,
e-signature, publication, acceptance, countersignature, and order creation MUST
all be disabled or absent.

The gateway MUST re-read the deal, line items, relevant association labels, and
account type immediately before dispatch. It MUST create at most one quote,
record the provider object ID in a durable gateway ledger, and re-read the quote
and its associations after creation. An ambiguous provider outcome MUST block
automatic retry pending reconciliation.

It does not establish that a quote was published, delivered, signed, accepted,
paid, or converted into a legally binding contract. Each such consequence would
require its own exact action and Permit.

## Common proof requirements

Every action carries:

- the exact fact-profile ID and action;
- connector-contract, tool-schema, decision-trace, arguments, request,
  preflight-snapshot, and idempotency digests;
- observed-at and expires-at timestamps for a short-lived, single-use preflight;
- `enforcement_mode = enforced_in_path` and `max_uses = 1`;
- the pinned portal commitment, developer-test account assertion, and provider
  API version.

The `.keelpermit` proves Keel's authorization decision over those signed facts.
Provider and habitat readbacks are separate observations and are not independent
attestations merely because Keel recorded them.
