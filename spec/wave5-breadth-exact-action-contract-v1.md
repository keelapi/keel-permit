# Wave 5 breadth exact-action contract v1

Status: implementation contract

This contract defines the customer-visible authorization vocabulary for habitats 21–33. It adds 33 exact action semantics and deliberately reuses the existing `crm.deal.stage.change` semantic, yielding 34 governed customer actions in the Wave 5 portfolio.

## Non-negotiable execution boundary

- The agent receives only Keel credentials.
- Every consequential or spend-bearing provider call is made by Keel or a Keel-controlled gateway after an allow decision.
- The gateway obtains fresh provider state, authenticates the preflight, binds the exact arguments and state snapshot, and refuses drift, replay, expired authorization, and non-demo targets.
- A deny, review, unavailable authorization service, invalid signature, wrong audience, stale state, or malformed request results in zero provider calls.
- A Permit-to-X authorizes one exact attempt. It is not proof that the provider accepted the call or that a later real-world outcome occurred.
- Human-first artifacts show title, action, target, scope, Issued at, Expires at, decision, limits, dispatch, and provider outcome. Raw signed bytes remain an advanced view.

## Portfolio actions

| Habitat | Exact customer actions |
|---|---|
| Trust & Safety Enforcement | AI Permit-to-Remove-Community-Content; AI Permit-to-Suspend-Community-Member; AI Permit-to-Restore-Community-Member |
| Recruiting Decision | AI Permit-to-Advance-Candidate; AI Permit-to-Reject-Candidate; AI Permit-to-Send-Employment-Offer |
| Contract Dispatch | AI Permit-to-Send-Agreement; AI Permit-to-Void-Agreement |
| Paper Trading | AI Permit-to-Place-Paper-Trade; AI Permit-to-Cancel-Paper-Trade |
| Supply Chain | AI Permit-to-Issue-Replenishment-Order; AI Permit-to-Create-Shipment; AI Permit-to-Purchase-Test-Shipping-Label; AI Permit-to-Change-Shipment-Route |
| Legacy App Transaction | AI Permit-to-Change-Customer-Address |
| SDR Outreach | AI Permit-to-Send-Sales-Email; AI Permit-to-Change-Deal-Stage (existing exact action); AI Permit-to-Offer-Discount |
| Executive Personal Assistant | AI Permit-to-Create-Calendar-Event; AI Permit-to-Send-Email; AI Permit-to-Purchase-Item |
| Marketing Publishing & Spend | AI Permit-to-Publish-Content; AI Permit-to-Launch-Campaign; AI Permit-to-Change-Campaign-Budget |
| Student Administration | AI Permit-to-Enroll-Student; AI Permit-to-Drop-Enrollment; AI Permit-to-Release-Transcript |
| Research Acquisition & Publishing | AI Permit-to-Purchase-Dataset; AI Permit-to-Publish-Research-Artifact |
| Metered API & Compute | AI Permit-to-Purchase-API-Usage; AI Permit-to-Purchase-Compute-Units |
| Physical Access & Actuation | AI Permit-to-Unlock-Demo-Door; AI Permit-to-Actuate-Demo-Relay; AI Permit-to-Move-Demo-Arm |

## Provider truth boundaries

- Discord suspension and restoration mean a ban/unban inside one dedicated demo community, never a global Discord account action.
- DocuSign uses a developer account and the agent is never a signatory. Sending or voiding an envelope does not establish contract formation, enforceability, or rescission of a completed agreement.
- Alpaca actions are paper trades only. They never authorize real securities trading.
- Shippo uses a dedicated test token. The artifact says “test account” and “test label”; it does not claim Shippo has a separate sandbox or that a carrier accepted a live shipment.
- Odoo, Mailpit, the legacy application, CMS, ad system, LMS, data market, and research repository contain synthetic records in self-hosted demo environments.
- Google and HubSpot actions are restricted to dedicated demo accounts and allowlisted recipients or records.
- x402 and MPP actions use controlled test services and bounded test value. Provider results establish only the immediate controlled transaction.
- Physical permits become executable only for explicitly approved, isolated hardware with an authenticated device identity, armed interlock, verified emergency stop, bounded motion or actuation, and contemporaneous human safety signoff. Until those inputs exist, the actions remain contract-complete but execution-blocked and must never be simulated as a real physical consequence.

## Exact-action invariants

Every new Wave 5 fact profile requires:

- one connector identity and versioned tool contract;
- a dedicated demo target commitment;
- exact target and material request fields;
- provider-observed state and a fresh expiry-bound preflight;
- an authenticated preflight and exact request digest;
- one idempotency identity and `max_uses = 1`;
- an explicit provider environment and provider API version;
- action-specific ceilings, allowlists, state transitions, and safety facts.

The registries are additive:

- consequence registry `keel.consequence_registry.v12`;
- fact profile registry `keel.fact_profile_registry.v15`;
- semantic selector registry `keel.semantic_selector_registry.v17`;
- presentation registry `keel.presentation_registry.v16`;
- exact consequence vectors `keel.consequence_registry.test_vectors.v13`;
- exact facts schema `keel.wave5_breadth_exact_facts.v1`.

## Certification requirement

Each feasible habitat must show a real provider or self-hosted state change, a provider readback, an allow path, a deny path with zero provider calls, an independently downloadable `.keelpermit`, offline verification under a pinned key, and material-tamper rejection. Provider credentials remain exclusively in the controlled gateway. External prerequisites that cannot be supplied by code must be recorded precisely and may not be replaced with a claimed real outcome.
