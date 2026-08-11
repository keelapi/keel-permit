#!/usr/bin/env python3
"""Build the additive exact-action contract for Wave 5 breadth habitats."""

from __future__ import annotations

import copy
from typing import Any

import build_commerce_regulated_registries as base
from build_collections_registries import digest as sample_digest
from build_transactional_cx_registries import load, sha256, write
from build_transactional_cx_registries import commitment as sample_commitment


FACT_SCHEMA = "schemas/wave5-breadth-exact-facts-v1.schema.json"
FACT_VERSION = "keel.wave5_breadth_exact_facts.v1"


def cref() -> dict[str, str]:
    return base.C()


def dref() -> dict[str, str]:
    return base.D()


def tref() -> dict[str, str]:
    return base.T()


def text(maximum: int = 256) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": maximum}


def enum(*values: str) -> dict[str, Any]:
    return {"enum": list(values)}


def integer(minimum: int = 0, maximum: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "integer", "minimum": minimum}
    if maximum is not None:
        value["maximum"] = maximum
    return value


def field(
    name: str,
    schema: dict[str, Any],
    sample: Any,
    *,
    target: bool = False,
) -> tuple[str, dict[str, Any], Any, bool]:
    return name, schema, sample, target


def reference(name: str, character: str, *, target: bool = True):
    return field(name, cref(), sample_commitment(character), target=target)


def digest(name: str, character: str):
    return field(name, dref(), sample_digest(character))


def exact_action(
    *,
    consequence_type: str,
    semantic_id: str,
    name: str,
    connector: str,
    environment: str,
    api_version: str,
    title: str,
    definition: str,
    provider: str,
    operation: str,
    fields: list[tuple[str, dict[str, Any], Any, bool]],
    trusted: list[str],
    limits: list[str],
    risks: list[str],
    leading: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    all_fields = [
        reference("provider_instance_reference_commitment", "7"),
        field("target_is_dedicated_demo", {"const": True}, True),
        *fields,
    ]
    properties = {item[0]: item[1] for item in all_fields}
    sample = {item[0]: item[2] for item in all_fields}
    targets = [item[0] for item in all_fields if item[3]]
    return base.action(
        consequence_type=consequence_type,
        semantic_id=semantic_id,
        name=name,
        connector=connector,
        environment=environment,
        api_version=api_version,
        title=title,
        definition=definition,
        provider=provider,
        operation=operation,
        properties=properties,
        sample=sample,
        targets=targets,
        trusted=[
            "gateway_pinned_dedicated_demo_target",
            *trusted,
        ],
        leading=leading
        or [
            {"field": "resource", "label": "Dedicated demo target"},
            {"field": "provider", "label": "Action provider"},
            {"field": "request_digest", "label": "Bound request"},
            {"field": "linked_to", "label": "Exact demo target"},
        ],
        limits=limits,
        risks=risks,
    )


def transition_fields(
    subject: str,
    *,
    before: str,
    after: str,
    reason: str = "demo-policy-reason",
) -> list[tuple[str, dict[str, Any], Any, bool]]:
    return [
        reference(f"{subject}_reference_commitment", "8"),
        field("state_before", text(128), before),
        field("requested_state", text(128), after),
        field("reason_code", text(128), reason),
        field("version_precondition_matches", {"const": True}, True),
        digest("provider_state_digest", "9"),
    ]


DEMO_LIMITS = [
    "authority_over_any_non_demo_account_or_record",
    "legal_or_business_correctness_of_the_requested_action",
    "provider_state_after_the_immediate_readback",
]


ACTION_DEFS: list[dict[str, Any]] = [
    exact_action(
        consequence_type="trust_safety.content.remove.v1",
        semantic_id="keel.action.trust_safety_content_remove.v1",
        name="trust_safety.content.remove",
        connector="discord",
        environment="dedicated_demo_community",
        api_version="discord-api-v10",
        title="AI Permit-to-Remove-Community-Content",
        definition="Exact authorization to remove one pinned message from one dedicated demo community",
        provider="discord",
        operation="channels.messages.delete",
        fields=[
            reference("community_reference_commitment", "8"),
            reference("channel_reference_commitment", "9"),
            reference("message_reference_commitment", "a"),
            reference("author_reference_commitment", "b"),
            field("content_present_before", {"const": True}, True),
            field("moderation_reason_code", text(128), "demo-abuse-policy"),
            digest("message_state_digest", "c"),
        ],
        trusted=["provider_message_preflight", "gateway_community_allowlist"],
        limits=["global_account_or_platform_enforcement", *DEMO_LIMITS],
        risks=["trust_safety", "content_removal", "external_state_change"],
    ),
    exact_action(
        consequence_type="trust_safety.member.suspend.v1",
        semantic_id="keel.action.trust_safety_member_suspend.v1",
        name="trust_safety.member.suspend",
        connector="discord",
        environment="dedicated_demo_community",
        api_version="discord-api-v10",
        title="AI Permit-to-Suspend-Community-Member",
        definition="Exact authorization to ban one dedicated demo member from one dedicated demo community",
        provider="discord",
        operation="guilds.bans.create",
        fields=[
            reference("community_reference_commitment", "8"),
            reference("member_reference_commitment", "9"),
            field("membership_state_before", {"const": "active"}, "active"),
            field("requested_membership_state", {"const": "suspended"}, "suspended"),
            field("moderation_reason_code", text(128), "demo-abuse-policy"),
            field("member_is_operator", {"const": False}, False),
            digest("membership_state_digest", "a"),
        ],
        trusted=["provider_membership_preflight", "gateway_operator_exclusion"],
        limits=["global_discord_account_suspension", *DEMO_LIMITS],
        risks=["trust_safety", "account_access", "external_state_change"],
    ),
    exact_action(
        consequence_type="trust_safety.member.restore.v1",
        semantic_id="keel.action.trust_safety_member_restore.v1",
        name="trust_safety.member.restore",
        connector="discord",
        environment="dedicated_demo_community",
        api_version="discord-api-v10",
        title="AI Permit-to-Restore-Community-Member",
        definition="Exact authorization to remove one ban for one dedicated demo community member",
        provider="discord",
        operation="guilds.bans.delete",
        fields=[
            reference("community_reference_commitment", "8"),
            reference("member_reference_commitment", "9"),
            field("membership_state_before", {"const": "suspended"}, "suspended"),
            field("requested_membership_state", {"const": "restored"}, "restored"),
            field("restoration_reason_code", text(128), "demo-appeal-granted"),
            digest("membership_state_digest", "a"),
        ],
        trusted=["provider_ban_preflight", "gateway_community_allowlist"],
        limits=["global_discord_account_restoration", *DEMO_LIMITS],
        risks=["trust_safety", "account_access", "external_state_change"],
    ),
    exact_action(
        consequence_type="recruiting.candidate.advance.v1",
        semantic_id="keel.action.recruiting_candidate_advance.v1",
        name="recruiting.candidate.advance",
        connector="odoo-hr",
        environment="self_hosted_synthetic",
        api_version="odoo-jsonrpc-v19",
        title="AI Permit-to-Advance-Candidate",
        definition="Exact authorization to advance one synthetic applicant to one allowlisted recruiting stage",
        provider="odoo",
        operation="hr.applicant.stage.update",
        fields=[
            reference("candidate_reference_commitment", "8"),
            reference("job_reference_commitment", "9"),
            field("stage_before", text(128), "screening"),
            field("requested_stage", text(128), "interview"),
            field("stage_transition_allowlisted", {"const": True}, True),
            field("required_review_complete", {"const": True}, True),
            digest("candidate_state_digest", "a"),
        ],
        trusted=["provider_candidate_stage_preflight", "gateway_stage_transition_allowlist"],
        limits=["employment_offer_or_hiring_decision", *DEMO_LIMITS],
        risks=["recruiting", "employment_decision", "record_mutation"],
    ),
    exact_action(
        consequence_type="recruiting.candidate.reject.v1",
        semantic_id="keel.action.recruiting_candidate_reject.v1",
        name="recruiting.candidate.reject",
        connector="odoo-hr",
        environment="self_hosted_synthetic",
        api_version="odoo-jsonrpc-v19",
        title="AI Permit-to-Reject-Candidate",
        definition="Exact authorization to reject one synthetic applicant with one allowlisted disposition reason",
        provider="odoo",
        operation="hr.applicant.refuse",
        fields=[
            reference("candidate_reference_commitment", "8"),
            reference("job_reference_commitment", "9"),
            field("stage_before", text(128), "interview"),
            field("requested_stage", {"const": "rejected"}, "rejected"),
            field("disposition_reason_code", text(128), "demo-role-requirements"),
            field("required_review_complete", {"const": True}, True),
            digest("candidate_state_digest", "a"),
        ],
        trusted=["provider_candidate_stage_preflight", "gateway_disposition_reason_allowlist"],
        limits=["lawfulness_or_fairness_of_an_employment_decision", *DEMO_LIMITS],
        risks=["recruiting", "employment_decision", "record_mutation"],
    ),
    exact_action(
        consequence_type="recruiting.offer.send.v1",
        semantic_id="keel.action.recruiting_offer_send.v1",
        name="recruiting.offer.send",
        connector="notification.email",
        environment="self_hosted_synthetic",
        api_version="mailpit-v1",
        title="AI Permit-to-Send-Employment-Offer",
        definition="Exact authorization to send one approved offer template to one dedicated synthetic recipient",
        provider="mailpit",
        operation="email.send_offer",
        fields=[
            reference("candidate_reference_commitment", "8"),
            reference("job_reference_commitment", "9"),
            reference("recipient_reference_commitment", "a"),
            digest("approved_offer_document_digest", "b"),
            field("offer_approved", {"const": True}, True),
            field("recipient_is_dedicated_demo", {"const": True}, True),
            field("prior_offer_count", {"const": 0}, 0),
        ],
        trusted=["provider_candidate_offer_preflight", "gateway_recipient_allowlist"],
        limits=["acceptance_or_legal_enforceability_of_the_offer", *DEMO_LIMITS],
        risks=["recruiting", "external_communication", "employment_offer"],
    ),
    exact_action(
        consequence_type="legal.agreement.send.v1",
        semantic_id="keel.action.legal_agreement_send.v1",
        name="legal.agreement.send",
        connector="docusign",
        environment="provider_developer_demo",
        api_version="docusign-esign-v2.1",
        title="AI Permit-to-Send-Agreement",
        definition="Exact authorization to send one approved envelope from a DocuSign developer account to dedicated demo recipients",
        provider="docusign",
        operation="envelopes.create_and_send",
        fields=[
            reference("agreement_reference_commitment", "8"),
            reference("envelope_reference_commitment", "9"),
            reference("recipient_set_commitment", "a"),
            digest("approved_document_digest", "b"),
            field("legal_approval_present", {"const": True}, True),
            field("agent_is_signatory", {"const": False}, False),
            field("recipient_set_is_dedicated_demo", {"const": True}, True),
            field("envelope_status_before", {"const": "draft"}, "draft"),
        ],
        trusted=["provider_envelope_preflight", "gateway_signatory_exclusion"],
        limits=["signature_acceptance_contract_formation_or_legal_enforceability", *DEMO_LIMITS],
        risks=["legal", "external_communication", "agreement_dispatch"],
    ),
    exact_action(
        consequence_type="legal.agreement.void.v1",
        semantic_id="keel.action.legal_agreement_void.v1",
        name="legal.agreement.void",
        connector="docusign",
        environment="provider_developer_demo",
        api_version="docusign-esign-v2.1",
        title="AI Permit-to-Void-Agreement",
        definition="Exact authorization to void one in-process DocuSign developer-account envelope with an exact reason",
        provider="docusign",
        operation="envelopes.void",
        fields=[
            reference("agreement_reference_commitment", "8"),
            reference("envelope_reference_commitment", "9"),
            field("envelope_status_before", enum("sent", "delivered"), "sent"),
            field("requested_envelope_status", {"const": "voided"}, "voided"),
            field("void_reason", text(256), "demo-document-superseded"),
            field("legal_approval_present", {"const": True}, True),
            digest("envelope_state_digest", "a"),
        ],
        trusted=["provider_envelope_preflight", "gateway_void_reason_validation"],
        limits=["rescission_of_any_separate_or_completed_contract", *DEMO_LIMITS],
        risks=["legal", "agreement_void", "external_state_change"],
    ),
    exact_action(
        consequence_type="trading.paper.order.place.v1",
        semantic_id="keel.action.trading_paper_order_place.v1",
        name="trading.paper.order.place",
        connector="alpaca-paper",
        environment="provider_paper_trading",
        api_version="alpaca-trading-api-v2",
        title="AI Permit-to-Place-Paper-Trade",
        definition="Exact authorization to place one bounded order in one Alpaca paper-trading account",
        provider="alpaca",
        operation="orders.create",
        fields=[
            reference("paper_account_reference_commitment", "8"),
            reference("asset_reference_commitment", "9"),
            field("side", enum("buy", "sell"), "buy"),
            field("order_type", enum("market", "limit"), "limit"),
            field("time_in_force", enum("day", "gtc"), "day"),
            field("quantity_microunits", integer(1), 2_000_000),
            field("limit_price_minor", integer(1), 18500),
            field("paper_trading", {"const": True}, True),
            field("market_clock_observed", {"const": True}, True),
            digest("account_and_asset_state_digest", "a"),
        ],
        trusted=["provider_paper_account_preflight", "provider_asset_and_clock_preflight"],
        limits=["real_securities_trade_ownership_profit_or_settlement", *DEMO_LIMITS],
        risks=["trading", "paper_trade", "financial_simulation"],
    ),
    exact_action(
        consequence_type="trading.paper.order.cancel.v1",
        semantic_id="keel.action.trading_paper_order_cancel.v1",
        name="trading.paper.order.cancel",
        connector="alpaca-paper",
        environment="provider_paper_trading",
        api_version="alpaca-trading-api-v2",
        title="AI Permit-to-Cancel-Paper-Trade",
        definition="Exact authorization to cancel one open order in one Alpaca paper-trading account",
        provider="alpaca",
        operation="orders.cancel",
        fields=[
            reference("paper_account_reference_commitment", "8"),
            reference("order_reference_commitment", "9"),
            field("order_status_before", enum("new", "accepted", "partially_filled"), "accepted"),
            field("requested_order_status", {"const": "canceled"}, "canceled"),
            field("paper_trading", {"const": True}, True),
            digest("order_state_digest", "a"),
        ],
        trusted=["provider_paper_account_preflight", "provider_open_order_preflight"],
        limits=["cancellation_of_any_real_securities_trade", *DEMO_LIMITS],
        risks=["trading", "paper_trade", "external_state_change"],
    ),
    exact_action(
        consequence_type="supply.replenishment_order.issue.v1",
        semantic_id="keel.action.supply_replenishment_order_issue.v1",
        name="supply.replenishment_order.issue",
        connector="odoo-inventory",
        environment="self_hosted_synthetic",
        api_version="odoo-jsonrpc-v19",
        title="AI Permit-to-Issue-Replenishment-Order",
        definition="Exact authorization to issue one bounded replenishment purchase order in a self-hosted synthetic ERP",
        provider="odoo",
        operation="purchase.order.create_and_confirm",
        fields=[
            reference("warehouse_reference_commitment", "8"),
            reference("supplier_reference_commitment", "9"),
            reference("product_set_commitment", "a"),
            field("line_item_count", integer(1, 50), 3),
            field("total_amount_minor", integer(1), 42000),
            field("currency", {"type": "string", "pattern": "^[A-Z]{3}$"}, "USD"),
            field("reorder_rule_triggered", {"const": True}, True),
            field("amount_within_budget", {"const": True}, True),
            digest("inventory_and_budget_state_digest", "b"),
        ],
        trusted=["provider_reorder_rule_preflight", "provider_supplier_and_budget_preflight"],
        limits=["supplier_acceptance_delivery_or_payment", *DEMO_LIMITS],
        risks=["supply_chain", "procurement", "spend_commitment"],
    ),
    exact_action(
        consequence_type="supply.shipment.create.v1",
        semantic_id="keel.action.supply_shipment_create.v1",
        name="supply.shipment.create",
        connector="shippo",
        environment="provider_test_account",
        api_version="shippo-api-2018-02-08",
        title="AI Permit-to-Create-Shipment",
        definition="Exact authorization to create one shipment quote request in one dedicated Shippo test account",
        provider="shippo",
        operation="shipments.create",
        fields=[
            reference("order_reference_commitment", "8"),
            reference("origin_address_commitment", "9"),
            reference("destination_address_commitment", "a"),
            reference("parcel_set_commitment", "b"),
            field("address_set_is_synthetic", {"const": True}, True),
            field("parcel_count", integer(1, 20), 1),
            field("shipment_status_before", {"const": "absent"}, "absent"),
            digest("shipment_request_digest", "c"),
        ],
        trusted=["gateway_shippo_test_token_constraint", "gateway_synthetic_address_allowlist"],
        limits=["carrier_acceptance_label_purchase_pickup_or_delivery", *DEMO_LIMITS],
        risks=["supply_chain", "shipment", "external_state_change"],
    ),
    exact_action(
        consequence_type="supply.shipping_label.purchase.v1",
        semantic_id="keel.action.supply_shipping_label_purchase.v1",
        name="supply.shipping_label.purchase",
        connector="shippo",
        environment="provider_test_account",
        api_version="shippo-api-2018-02-08",
        title="AI Permit-to-Purchase-Test-Shipping-Label",
        definition="Exact authorization to purchase one test label from one exact Shippo test rate",
        provider="shippo",
        operation="transactions.create",
        fields=[
            reference("shipment_reference_commitment", "8"),
            reference("rate_reference_commitment", "9"),
            field("label_amount_minor", integer(1), 1250),
            field("currency", {"type": "string", "pattern": "^[A-Z]{3}$"}, "USD"),
            field("shippo_test_token", {"const": True}, True),
            field("rate_status", {"const": "valid"}, "valid"),
            field("existing_label_count", {"const": 0}, 0),
            digest("rate_and_shipment_state_digest", "a"),
        ],
        trusted=["gateway_shippo_test_token_constraint", "provider_rate_preflight", "provider_label_absence_preflight"],
        limits=["purchase_of_a_live_postage_label_carrier_acceptance_or_delivery", *DEMO_LIMITS],
        risks=["supply_chain", "test_purchase", "shipping_label"],
    ),
    exact_action(
        consequence_type="supply.shipment.route.change.v1",
        semantic_id="keel.action.supply_shipment_route_change.v1",
        name="supply.shipment.route.change",
        connector="odoo-inventory",
        environment="self_hosted_synthetic",
        api_version="odoo-jsonrpc-v19",
        title="AI Permit-to-Change-Shipment-Route",
        definition="Exact authorization to change one synthetic ERP shipment to one allowlisted route before dispatch",
        provider="odoo",
        operation="stock.picking.route.update",
        fields=[
            reference("shipment_reference_commitment", "8"),
            reference("route_before_reference_commitment", "9"),
            reference("route_after_reference_commitment", "a"),
            field("shipment_status_before", {"const": "ready"}, "ready"),
            field("route_transition_allowlisted", {"const": True}, True),
            field("carrier_dispatch_count", {"const": 0}, 0),
            digest("shipment_route_state_digest", "b"),
        ],
        trusted=["provider_shipment_route_preflight", "gateway_route_transition_allowlist"],
        limits=["carrier_rerouting_delivery_or_physical_custody", *DEMO_LIMITS],
        risks=["supply_chain", "route_change", "external_state_change"],
    ),
    exact_action(
        consequence_type="legacy.customer.address.change.v1",
        semantic_id="keel.action.legacy_customer_address_change.v1",
        name="legacy.customer.address.change",
        connector="legacy-browser",
        environment="self_hosted_synthetic",
        api_version="keel-legacy-app-v1",
        title="AI Permit-to-Change-Customer-Address",
        definition="Exact authorization to change an allowlisted address field set for one synthetic customer through a controlled browser session",
        provider="keel-legacy-app",
        operation="customers.address.update_via_ui",
        fields=[
            reference("customer_reference_commitment", "8"),
            reference("browser_session_reference_commitment", "9"),
            digest("address_before_digest", "a"),
            digest("address_after_digest", "b"),
            field("field_set_allowlisted", {"const": True}, True),
            field("record_version_precondition_matches", {"const": True}, True),
            field("browser_origin_pinned", {"const": True}, True),
        ],
        trusted=["gateway_browser_origin_allowlist", "provider_record_version_preflight"],
        limits=["identity_or_accuracy_of_any_real_customer_address", *DEMO_LIMITS],
        risks=["legacy_app", "personal_data", "record_mutation"],
    ),
    exact_action(
        consequence_type="sales.email.send.v1",
        semantic_id="keel.action.sales_email_send.v1",
        name="sales.email.send",
        connector="notification.email",
        environment="self_hosted_synthetic",
        api_version="mailpit-v1",
        title="AI Permit-to-Send-Sales-Email",
        definition="Exact authorization to send one approved sales template to one dedicated synthetic recipient",
        provider="mailpit",
        operation="email.send_sales_message",
        fields=[
            reference("contact_reference_commitment", "8"),
            reference("recipient_reference_commitment", "9"),
            digest("approved_message_digest", "a"),
            field("recipient_is_dedicated_demo", {"const": True}, True),
            field("contact_opt_out", {"const": False}, False),
            field("daily_send_count_before", integer(0), 2),
            field("daily_send_limit", integer(1), 20),
        ],
        trusted=["provider_contact_consent_preflight", "gateway_recipient_allowlist", "gateway_send_rate_limit"],
        limits=["recipient_engagement_consent_beyond_the_bound_record_or_delivery", *DEMO_LIMITS],
        risks=["sales", "external_communication", "outreach"],
    ),
    exact_action(
        consequence_type="sales.discount.offer.v1",
        semantic_id="keel.action.sales_discount_offer.v1",
        name="sales.discount.offer",
        connector="hubspot",
        environment="provider_developer_test",
        api_version="hubspot-crm-v3",
        title="AI Permit-to-Offer-Discount",
        definition="Exact authorization to record one bounded discount offer on one synthetic developer-test deal",
        provider="hubspot",
        operation="crm.deals.update_discount_offer",
        fields=[
            reference("deal_reference_commitment", "8"),
            reference("contact_reference_commitment", "9"),
            field("discount_basis_points", integer(1, 10000), 750),
            field("discount_ceiling_basis_points", integer(1, 10000), 1000),
            field("discount_within_ceiling", {"const": True}, True),
            field("offer_expires_at", tref(), "2026-08-20T00:00:00Z"),
            digest("deal_pricing_state_digest", "a"),
        ],
        trusted=["provider_deal_pricing_preflight", "gateway_discount_ceiling"],
        limits=["customer_acceptance_contract_formation_or_final_price", *DEMO_LIMITS],
        risks=["sales", "pricing", "commercial_offer"],
    ),
    exact_action(
        consequence_type="calendar.event.create.v1",
        semantic_id="keel.action.calendar_event_create.v1",
        name="calendar.event.create",
        connector="google-calendar",
        environment="dedicated_demo_account",
        api_version="google-calendar-v3",
        title="AI Permit-to-Create-Calendar-Event",
        definition="Exact authorization to create one event on one dedicated demo calendar with an allowlisted attendee set",
        provider="google-calendar",
        operation="events.insert",
        fields=[
            reference("calendar_reference_commitment", "8"),
            reference("attendee_set_commitment", "9"),
            digest("event_payload_digest", "a"),
            field("event_start_at", tref(), "2026-08-20T17:00:00Z"),
            field("event_end_at", tref(), "2026-08-20T17:30:00Z"),
            field("attendee_set_allowlisted", {"const": True}, True),
            field("calendar_conflict_count", {"const": 0}, 0),
        ],
        trusted=["provider_calendar_preflight", "gateway_attendee_allowlist"],
        limits=["attendance_acceptance_or_availability_after_the_bound_snapshot", *DEMO_LIMITS],
        risks=["calendar", "external_communication", "scheduling"],
    ),
    exact_action(
        consequence_type="email.message.send.v1",
        semantic_id="keel.action.email_message_send.v1",
        name="email.message.send",
        connector="google-gmail",
        environment="dedicated_demo_account",
        api_version="gmail-api-v1",
        title="AI Permit-to-Send-Email",
        definition="Exact authorization to send one exact message from one dedicated demo mailbox to allowlisted recipients",
        provider="gmail",
        operation="users.messages.send",
        fields=[
            reference("mailbox_reference_commitment", "8"),
            reference("recipient_set_commitment", "9"),
            digest("message_payload_digest", "a"),
            field("recipient_set_allowlisted", {"const": True}, True),
            field("attachment_count", integer(0, 10), 0),
            field("daily_send_count_before", integer(0), 2),
            field("daily_send_limit", integer(1), 20),
        ],
        trusted=["provider_mailbox_preflight", "gateway_recipient_allowlist", "gateway_send_rate_limit"],
        limits=["delivery_read_receipt_recipient_action_or_consent", *DEMO_LIMITS],
        risks=["email", "external_communication", "reputation"],
    ),
    exact_action(
        consequence_type="commerce.item.purchase.v1",
        semantic_id="keel.action.commerce_item_purchase.v1",
        name="commerce.item.purchase",
        connector="stripe",
        environment="provider_sandbox",
        api_version="2026-07-30.basil",
        title="AI Permit-to-Purchase-Item",
        definition="Exact authorization to purchase one allowlisted synthetic item with one Stripe test-mode payment",
        provider="stripe",
        operation="payment_intents.create_and_confirm",
        fields=[
            reference("item_reference_commitment", "8"),
            reference("merchant_reference_commitment", "9"),
            reference("payment_method_reference_commitment", "a"),
            field("amount_minor", integer(1), 4900),
            field("currency", {"type": "string", "pattern": "^[A-Z]{3}$"}, "USD"),
            field("item_allowlisted", {"const": True}, True),
            field("stripe_livemode", {"const": False}, False),
            field("existing_payment_count", {"const": 0}, 0),
            digest("item_and_payment_state_digest", "b"),
        ],
        trusted=["provider_item_preflight", "stripe_test_mode_preflight", "provider_payment_absence_preflight"],
        limits=["real_purchase_delivery_merchant_receipt_or_settlement", *DEMO_LIMITS],
        risks=["commerce", "payment", "value_movement"],
    ),
    exact_action(
        consequence_type="marketing.content.publish.v1",
        semantic_id="keel.action.marketing_content_publish.v1",
        name="marketing.content.publish",
        connector="demo-cms",
        environment="self_hosted_synthetic",
        api_version="keel-demo-cms-v1",
        title="AI Permit-to-Publish-Content",
        definition="Exact authorization to publish one approved content revision to one self-hosted synthetic site",
        provider="keel-demo-cms",
        operation="content.publish",
        fields=[
            reference("site_reference_commitment", "8"),
            reference("content_reference_commitment", "9"),
            digest("approved_revision_digest", "a"),
            field("publication_status_before", {"const": "draft"}, "draft"),
            field("requested_publication_status", {"const": "published"}, "published"),
            field("editorial_approval_present", {"const": True}, True),
            field("version_precondition_matches", {"const": True}, True),
        ],
        trusted=["provider_content_revision_preflight", "gateway_editorial_approval_check"],
        limits=["accuracy_legality_or_public_reception_of_the_content", *DEMO_LIMITS],
        risks=["marketing", "public_communication", "content_publish"],
    ),
    exact_action(
        consequence_type="marketing.campaign.launch.v1",
        semantic_id="keel.action.marketing_campaign_launch.v1",
        name="marketing.campaign.launch",
        connector="demo-ads",
        environment="self_hosted_synthetic",
        api_version="keel-demo-ads-v1",
        title="AI Permit-to-Launch-Campaign",
        definition="Exact authorization to launch one approved synthetic advertising campaign with a bounded budget",
        provider="keel-demo-ads",
        operation="campaigns.launch",
        fields=[
            reference("advertising_account_reference_commitment", "8"),
            reference("campaign_reference_commitment", "9"),
            digest("approved_creative_set_digest", "a"),
            field("campaign_status_before", {"const": "draft"}, "draft"),
            field("requested_campaign_status", {"const": "active"}, "active"),
            field("daily_budget_minor", integer(1), 5000),
            field("currency", {"type": "string", "pattern": "^[A-Z]{3}$"}, "USD"),
            field("budget_within_ceiling", {"const": True}, True),
        ],
        trusted=["provider_campaign_preflight", "gateway_creative_approval_check", "gateway_budget_ceiling"],
        limits=["real_ad_delivery_audience_reach_spend_or_performance", *DEMO_LIMITS],
        risks=["marketing", "campaign_launch", "spend_authority"],
    ),
    exact_action(
        consequence_type="marketing.campaign.budget.change.v1",
        semantic_id="keel.action.marketing_campaign_budget_change.v1",
        name="marketing.campaign.budget.change",
        connector="demo-ads",
        environment="self_hosted_synthetic",
        api_version="keel-demo-ads-v1",
        title="AI Permit-to-Change-Campaign-Budget",
        definition="Exact authorization to change one synthetic campaign daily budget within an exact ceiling",
        provider="keel-demo-ads",
        operation="campaigns.budget.update",
        fields=[
            reference("advertising_account_reference_commitment", "8"),
            reference("campaign_reference_commitment", "9"),
            field("daily_budget_before_minor", integer(1), 5000),
            field("requested_daily_budget_minor", integer(1), 7500),
            field("daily_budget_ceiling_minor", integer(1), 10000),
            field("currency", {"type": "string", "pattern": "^[A-Z]{3}$"}, "USD"),
            field("budget_within_ceiling", {"const": True}, True),
            digest("campaign_budget_state_digest", "a"),
        ],
        trusted=["provider_campaign_budget_preflight", "gateway_budget_ceiling"],
        limits=["real_ad_spend_delivery_or_performance", *DEMO_LIMITS],
        risks=["marketing", "budget_change", "spend_authority"],
    ),
    exact_action(
        consequence_type="education.student.enroll.v1",
        semantic_id="keel.action.education_student_enroll.v1",
        name="education.student.enroll",
        connector="demo-lms",
        environment="self_hosted_synthetic",
        api_version="keel-demo-lms-v1",
        title="AI Permit-to-Enroll-Student",
        definition="Exact authorization to enroll one synthetic student in one open synthetic course",
        provider="keel-demo-lms",
        operation="enrollments.create",
        fields=[
            reference("student_reference_commitment", "8"),
            reference("course_reference_commitment", "9"),
            field("enrollment_status_before", {"const": "absent"}, "absent"),
            field("requested_enrollment_status", {"const": "active"}, "active"),
            field("course_enrollment_open", {"const": True}, True),
            field("available_seat_count", integer(1), 12),
            digest("student_and_course_state_digest", "a"),
        ],
        trusted=["provider_student_and_course_preflight", "provider_enrollment_absence_preflight"],
        limits=["tuition_payment_academic_eligibility_or_identity_of_a_real_student", *DEMO_LIMITS],
        risks=["education", "enrollment", "student_record"],
    ),
    exact_action(
        consequence_type="education.enrollment.drop.v1",
        semantic_id="keel.action.education_enrollment_drop.v1",
        name="education.enrollment.drop",
        connector="demo-lms",
        environment="self_hosted_synthetic",
        api_version="keel-demo-lms-v1",
        title="AI Permit-to-Drop-Enrollment",
        definition="Exact authorization to drop one active synthetic course enrollment within an allowlisted window",
        provider="keel-demo-lms",
        operation="enrollments.drop",
        fields=[
            reference("student_reference_commitment", "8"),
            reference("course_reference_commitment", "9"),
            reference("enrollment_reference_commitment", "a"),
            field("enrollment_status_before", {"const": "active"}, "active"),
            field("requested_enrollment_status", {"const": "dropped"}, "dropped"),
            field("drop_window_open", {"const": True}, True),
            digest("enrollment_state_digest", "b"),
        ],
        trusted=["provider_enrollment_preflight", "provider_drop_window_preflight"],
        limits=["tuition_refund_financial_aid_or_academic_consequences", *DEMO_LIMITS],
        risks=["education", "enrollment_drop", "student_record"],
    ),
    exact_action(
        consequence_type="education.transcript.release.v1",
        semantic_id="keel.action.education_transcript_release.v1",
        name="education.transcript.release",
        connector="demo-lms",
        environment="self_hosted_synthetic",
        api_version="keel-demo-lms-v1",
        title="AI Permit-to-Release-Transcript",
        definition="Exact authorization to release one synthetic transcript to one dedicated demo recipient",
        provider="keel-demo-lms",
        operation="transcripts.release",
        fields=[
            reference("student_reference_commitment", "8"),
            reference("transcript_reference_commitment", "9"),
            reference("recipient_reference_commitment", "a"),
            digest("transcript_document_digest", "b"),
            field("release_consent_present", {"const": True}, True),
            field("financial_hold_present", {"const": False}, False),
            field("recipient_is_dedicated_demo", {"const": True}, True),
        ],
        trusted=["provider_transcript_and_hold_preflight", "gateway_release_consent_check", "gateway_recipient_allowlist"],
        limits=["authenticity_of_any_real_academic_record_or_recipient_use", *DEMO_LIMITS],
        risks=["education", "student_record", "data_release"],
    ),
    exact_action(
        consequence_type="research.dataset.purchase.v1",
        semantic_id="keel.action.research_dataset_purchase.v1",
        name="research.dataset.purchase",
        connector="demo-data-market",
        environment="self_hosted_synthetic",
        api_version="keel-demo-data-market-v1",
        title="AI Permit-to-Purchase-Dataset",
        definition="Exact authorization to purchase one licensed synthetic dataset within a bounded test budget",
        provider="keel-demo-data-market",
        operation="datasets.purchase",
        fields=[
            reference("dataset_reference_commitment", "8"),
            reference("license_reference_commitment", "9"),
            field("price_minor", integer(1), 2500),
            field("currency", {"type": "string", "pattern": "^[A-Z]{3}$"}, "USD"),
            field("license_allowlisted", {"const": True}, True),
            field("price_within_budget", {"const": True}, True),
            field("existing_purchase_count", {"const": 0}, 0),
            digest("dataset_and_license_state_digest", "a"),
        ],
        trusted=["provider_dataset_and_license_preflight", "gateway_research_budget_ceiling"],
        limits=["scientific_validity_real_payment_or_ownership_beyond_the_demo_license", *DEMO_LIMITS],
        risks=["research", "dataset_purchase", "spend_authority"],
    ),
    exact_action(
        consequence_type="research.artifact.publish.v1",
        semantic_id="keel.action.research_artifact_publish.v1",
        name="research.artifact.publish",
        connector="demo-repository",
        environment="self_hosted_synthetic",
        api_version="keel-demo-repository-v1",
        title="AI Permit-to-Publish-Research-Artifact",
        definition="Exact authorization to publish one approved research artifact revision to one self-hosted demo repository",
        provider="keel-demo-repository",
        operation="artifacts.publish",
        fields=[
            reference("repository_reference_commitment", "8"),
            reference("artifact_reference_commitment", "9"),
            digest("approved_artifact_digest", "a"),
            field("publication_status_before", {"const": "draft"}, "draft"),
            field("requested_publication_status", {"const": "published"}, "published"),
            field("review_approval_present", {"const": True}, True),
            field("license_allowlisted", {"const": True}, True),
        ],
        trusted=["provider_artifact_revision_preflight", "gateway_review_and_license_check"],
        limits=["scientific_validity_peer_review_citation_or_public_acceptance", *DEMO_LIMITS],
        risks=["research", "public_communication", "artifact_publish"],
    ),
    exact_action(
        consequence_type="metered.api.usage.purchase.v1",
        semantic_id="keel.action.metered_api_usage_purchase.v1",
        name="metered.api.usage.purchase",
        connector="x402-test",
        environment="controlled_test_mode",
        api_version="x402-v2",
        title="AI Permit-to-Purchase-API-Usage",
        definition="Exact authorization to purchase one bounded metered API request from one allowlisted test endpoint",
        provider="x402",
        operation="payment.requirement.accept_and_call",
        fields=[
            reference("endpoint_reference_commitment", "8"),
            reference("payment_destination_reference_commitment", "9"),
            field("unit_count", integer(1, 10000), 100),
            field("total_amount_minor", integer(1), 500),
            field("currency", {"type": "string", "pattern": "^[A-Z0-9]{3,12}$"}, "USDC"),
            field("endpoint_allowlisted", {"const": True}, True),
            field("amount_within_budget", {"const": True}, True),
            field("existing_payment_count", {"const": 0}, 0),
            digest("payment_requirement_digest", "a"),
        ],
        trusted=["provider_payment_requirement_preflight", "gateway_endpoint_allowlist", "gateway_budget_ceiling"],
        limits=["quality_availability_or_correctness_of_the_purchased_api_result", *DEMO_LIMITS],
        risks=["metered_api", "payment", "machine_purchase"],
    ),
    exact_action(
        consequence_type="metered.compute.units.purchase.v1",
        semantic_id="keel.action.metered_compute_units_purchase.v1",
        name="metered.compute.units.purchase",
        connector="mpp-test",
        environment="controlled_test_mode",
        api_version="mpp-v1",
        title="AI Permit-to-Purchase-Compute-Units",
        definition="Exact authorization to purchase one bounded compute-unit grant from one allowlisted test service",
        provider="machine-payments-protocol",
        operation="charges.authorize_and_settle_test",
        fields=[
            reference("compute_service_reference_commitment", "8"),
            reference("payment_destination_reference_commitment", "9"),
            field("compute_unit_count", integer(1, 1000000), 1000),
            field("total_amount_minor", integer(1), 900),
            field("currency", {"type": "string", "pattern": "^[A-Z0-9]{3,12}$"}, "USDC"),
            field("service_allowlisted", {"const": True}, True),
            field("amount_within_budget", {"const": True}, True),
            field("existing_payment_count", {"const": 0}, 0),
            digest("compute_offer_digest", "a"),
        ],
        trusted=["provider_compute_offer_preflight", "gateway_service_allowlist", "gateway_budget_ceiling"],
        limits=["performance_availability_or_suitability_of_the_purchased_compute", *DEMO_LIMITS],
        risks=["metered_compute", "payment", "machine_purchase"],
    ),
    exact_action(
        consequence_type="physical.access.unlock.v1",
        semantic_id="keel.action.physical_access_unlock.v1",
        name="physical.access.unlock",
        connector="approved-demo-hardware",
        environment="approved_isolated_demo_hardware",
        api_version="keel-hardware-gateway-v1",
        title="AI Permit-to-Unlock-Demo-Door",
        definition="Exact authorization to unlock one approved isolated demo lock for a bounded interval after human safety signoff",
        provider="keel-hardware-gateway",
        operation="locks.unlock",
        fields=[
            reference("lock_reference_commitment", "8"),
            reference("safety_zone_reference_commitment", "9"),
            field("unlock_duration_seconds", integer(1, 30), 5),
            field("physical_safety_interlock_armed", {"const": True}, True),
            field("human_safety_signoff_present", {"const": True}, True),
            field("emergency_stop_verified", {"const": True}, True),
            field("occupancy_clear", {"const": True}, True),
            digest("lock_and_safety_state_digest", "a"),
        ],
        trusted=["hardware_identity_attestation", "provider_safety_interlock_preflight", "human_safety_signoff"],
        limits=["safety_of_unapproved_hardware_or_access_to_any_real_protected_space", *DEMO_LIMITS],
        risks=["physical_access", "safety", "actuation"],
    ),
    exact_action(
        consequence_type="physical.relay.actuate.v1",
        semantic_id="keel.action.physical_relay_actuate.v1",
        name="physical.relay.actuate",
        connector="approved-demo-hardware",
        environment="approved_isolated_demo_hardware",
        api_version="keel-hardware-gateway-v1",
        title="AI Permit-to-Actuate-Demo-Relay",
        definition="Exact authorization to actuate one approved isolated demo relay to one bounded state after human safety signoff",
        provider="keel-hardware-gateway",
        operation="relays.actuate",
        fields=[
            reference("relay_reference_commitment", "8"),
            reference("safety_zone_reference_commitment", "9"),
            field("relay_state_before", enum("open", "closed"), "open"),
            field("requested_relay_state", enum("open", "closed"), "closed"),
            field("actuation_duration_milliseconds", integer(1, 5000), 500),
            field("physical_safety_interlock_armed", {"const": True}, True),
            field("human_safety_signoff_present", {"const": True}, True),
            field("emergency_stop_verified", {"const": True}, True),
            digest("relay_and_safety_state_digest", "a"),
        ],
        trusted=["hardware_identity_attestation", "provider_safety_interlock_preflight", "human_safety_signoff"],
        limits=["safety_of_unapproved_hardware_or_control_of_any_real_process", *DEMO_LIMITS],
        risks=["physical_control", "safety", "actuation"],
    ),
    exact_action(
        consequence_type="physical.arm.move.v1",
        semantic_id="keel.action.physical_arm_move.v1",
        name="physical.arm.move",
        connector="approved-demo-hardware",
        environment="approved_isolated_demo_hardware",
        api_version="keel-hardware-gateway-v1",
        title="AI Permit-to-Move-Demo-Arm",
        definition="Exact authorization to move one approved isolated demo arm through one bounded trajectory after human safety signoff",
        provider="keel-hardware-gateway",
        operation="arms.move",
        fields=[
            reference("arm_reference_commitment", "8"),
            reference("safety_zone_reference_commitment", "9"),
            digest("trajectory_digest", "a"),
            field("maximum_velocity_millimeters_per_second", integer(1, 100), 25),
            field("physical_safety_interlock_armed", {"const": True}, True),
            field("human_safety_signoff_present", {"const": True}, True),
            field("emergency_stop_verified", {"const": True}, True),
            field("workspace_clear", {"const": True}, True),
            digest("arm_and_safety_state_digest", "b"),
        ],
        trusted=["hardware_identity_attestation", "provider_safety_interlock_preflight", "human_safety_signoff", "gateway_trajectory_bounds_check"],
        limits=["safety_of_unapproved_hardware_or_motion_near_any_person_or_property", *DEMO_LIMITS],
        risks=["robotics", "safety", "physical_motion"],
    ),
]


# The SDR habitat reuses this already-shipped exact action. Duplicating it would
# create two semantic identities for the same provider mutation.
REUSED_ACTIONS = {"crm.deal.stage.change": "AI Permit-to-Change-Deal-Stage"}


INTEGER_FIELDS = {
    name
    for item in ACTION_DEFS
    for name, schema, _sample, _target in [
        (path.removeprefix("/"), item["properties"][path.removeprefix("/")], None, False)
        for path in item["specific_paths"]
    ]
    if schema.get("type") == "integer"
}
BOOLEAN_FIELDS = {
    name
    for item in ACTION_DEFS
    for name, schema in item["properties"].items()
    if isinstance(schema.get("const"), bool)
}
TIMESTAMP_FIELDS = {
    name
    for item in ACTION_DEFS
    for name, schema in item["properties"].items()
    if schema == tref()
}


def configure_base() -> None:
    base.FACT_SCHEMA = FACT_SCHEMA
    base.FACT_VERSION = FACT_VERSION
    base.ACTION_DEFS = ACTION_DEFS
    base.INTEGER_FIELDS.update(INTEGER_FIELDS)
    base.BOOLEAN_FIELDS.update(BOOLEAN_FIELDS)
    base.base.base.TIMESTAMP_FIELDS.update(TIMESTAMP_FIELDS)
    base.configure_base()


def profile_id(item: dict[str, Any]) -> str:
    configure_base()
    return base.profile_id(item)


def build_schema() -> dict[str, Any]:
    configure_base()
    schema = base.build_schema()
    schema["$id"] = "https://github.com/keelapi/keel-permit/schemas/wave5-breadth-exact-facts-v1.schema.json"
    schema["title"] = "Keel exact Wave 5 breadth-habitat facts v1"
    for item in ACTION_DEFS:
        definition = schema["$defs"][item["action"].replace(".", "_")]
        definition["properties"]["version"] = {"const": FACT_VERSION}
        definition["properties"]["provider_environment"] = {"const": item["environment"]}
    return schema


def fact_vector(item: dict[str, Any]) -> dict[str, Any]:
    configure_base()
    value = base.fact_vector(item)
    value["version"] = FACT_VERSION
    value["provider_environment"] = item["environment"]
    value["provider_api_version"] = item["provider_api_version"]
    value["preflight_observed_at"] = "2026-08-11T05:00:00Z"
    value["preflight_expires_at"] = "2026-08-11T05:05:00Z"
    return value


def main() -> None:
    configure_base()
    write(FACT_SCHEMA, build_schema())

    consequence = copy.deepcopy(load("consequence_registry/v11.json"))
    consequence["$schema"] = "./v12.schema.json"
    consequence["version"] = "keel.consequence_registry.v12"
    consequence["consequences"].extend(base.base.base.consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v12.json", consequence)
    consequence_schema = copy.deepcopy(load("consequence_registry/v11.schema.json"))
    consequence_schema["$id"] = "https://github.com/keelapi/keel-permit/consequence_registry/v12.schema.json"
    consequence_schema["title"] = "Keel consequence registry v12"
    consequence_schema["properties"]["version"]["const"] = "keel.consequence_registry.v12"
    write("consequence_registry/v12.schema.json", consequence_schema)

    schema_digest = sha256(FACT_SCHEMA)
    facts = copy.deepcopy(load("fact_profiles/v14.json"))
    facts["$schema"] = "./v15.schema.json"
    facts["version"] = "keel.fact_profile_registry.v15"
    facts["profiles"].extend(base.base.base.fact_profile(item, schema_digest) for item in ACTION_DEFS)
    write("fact_profiles/v15.json", facts)
    facts_schema = copy.deepcopy(load("fact_profiles/v14.schema.json"))
    facts_schema["$id"] = "https://github.com/keelapi/keel-permit/fact_profiles/v15.schema.json"
    facts_schema["title"] = "Keel Permit fact profile registry v15"
    facts_schema["properties"]["version"]["const"] = "keel.fact_profile_registry.v15"
    write("fact_profiles/v15.schema.json", facts_schema)

    semantics = copy.deepcopy(load("semantic_registry/v16.json"))
    semantics["$schema"] = "./v17.schema.json"
    semantics["version"] = "keel.semantic_selector_registry.v17"
    semantics["entries"].extend(base.base.base.semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v17.json", semantics)
    semantic_schema = copy.deepcopy(load("semantic_registry/v16.schema.json"))
    semantic_schema["$id"] = "https://github.com/keelapi/keel-permit/semantic_registry/v17.schema.json"
    semantic_schema["title"] = "Keel Permit semantic selector registry v17"
    semantic_schema["properties"]["version"]["const"] = "keel.semantic_selector_registry.v17"
    write("semantic_registry/v17.schema.json", semantic_schema)

    presentation = copy.deepcopy(load("presentation_registry/v15.json"))
    presentation["$schema"] = "./v16.schema.json"
    presentation["version"] = "keel.presentation_registry.v16"
    presentation["semantic_registry_version"] = "keel.semantic_selector_registry.v17"
    presentation["profiles"].extend(base.base.base.presentation_profile(item) for item in ACTION_DEFS)
    write("presentation_registry/v16.json", presentation)
    presentation_schema = copy.deepcopy(load("presentation_registry/v15.schema.json"))
    presentation_schema["$id"] = "https://github.com/keelapi/keel-permit/presentation_registry/v16.schema.json"
    presentation_schema["title"] = "Keel Permit presentation registry v16"
    presentation_schema["properties"]["version"]["const"] = "keel.presentation_registry.v16"
    presentation_schema["properties"]["semantic_registry_version"]["const"] = "keel.semantic_selector_registry.v17"
    write("presentation_registry/v16.schema.json", presentation_schema)

    vectors = copy.deepcopy(load("consequence_registry/test-vectors/v12.json"))
    vectors["version"] = "keel.consequence_registry.test_vectors.v13"
    vectors["consequence_registry_version"] = consequence["version"]
    vectors["semantic_registry_version"] = semantics["version"]
    vectors["presentation_registry_version"] = presentation["version"]
    for item in ACTION_DEFS:
        vectors["vectors"].append(
            {
                "id": item["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": item["action"],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": ["authorization", "dispatch", "provider_outcome"],
                },
                "expected_semantic_id": item["semantic_id"],
                "expected_title": item["customer_title"],
                "expected_fact_profile_id": profile_id(item),
                "valid_authorization_facts": fact_vector(item),
            }
        )
    write("consequence_registry/test-vectors/v13.json", vectors)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v12", "consequence_registry/v12.json"),
        ("keel.permit.consequence_registry.v12.schema", "consequence_registry/v12.schema.json"),
        ("keel.permit.wave5_breadth_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v15", "fact_profiles/v15.json"),
        ("keel.permit.fact_profile_registry.v15.schema", "fact_profiles/v15.schema.json"),
        ("keel.permit.semantic_selector_registry.v17", "semantic_registry/v17.json"),
        ("keel.permit.semantic_selector_registry.v17.schema", "semantic_registry/v17.schema.json"),
        ("keel.permit.presentation_registry.v16", "presentation_registry/v16.json"),
        ("keel.permit.presentation_registry.v16.schema", "presentation_registry/v16.schema.json"),
        ("permit-to-x.test-vectors.consequence-registry.v13", "consequence_registry/test-vectors/v13.json"),
        ("keel.permit.wave5_breadth_exact_action_contract.v1.spec", "spec/wave5-breadth-exact-action-contract-v1.md"),
    ]
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        if path in existing:
            existing[path].update({"id": artifact_id, "sha256": sha256(path)})
        else:
            manifest["artifacts"].append({"id": artifact_id, "path": path, "sha256": sha256(path)})
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
