#!/usr/bin/env python3
"""Build additive exact-action artifacts for Procurement and Accounts Payable."""

from __future__ import annotations

import copy
from typing import Any

import build_collections_registries as base
from build_transactional_cx_registries import load, sha256, write


FACT_SCHEMA = "schemas/procurement-ap-exact-facts-v1.schema.json"
FACT_VERSION = "keel.procurement_ap_exact_facts.v1"


def currency() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[A-Z]{3}$"}


ACTION_DEFS: list[dict[str, Any]] = [
    {
        "consequence_type": "procurement.vendor.create.v1",
        "semantic_id": "keel.action.procurement_vendor_create.v1",
        "action": "procurement.vendor.create",
        "connector_identity": "odoo",
        "environment": "self_hosted_synthetic",
        "provider_api_version": "odoo-jsonrpc-v2",
        "customer_title": "AI Permit-to-Create-Vendor",
        "type_definition": (
            "Exact authorization to create one synthetic supplier record in one "
            "pinned self-hosted Odoo database"
        ),
        "provider_mapping": {
            "provider": "odoo",
            "operation": "res.partner.create_supplier",
        },
        "specific_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/record_is_synthetic",
            "/vendor_name_commitment",
            "/vendor_tax_reference_commitment",
            "/vendor_email_commitment",
            "/supplier_rank_requested",
            "/duplicate_vendor_count",
            "/required_fields_complete",
            "/bank_account_created",
            "/vendor_schema_digest",
            "/vendor_search_state_digest",
        ],
        "target_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/vendor_name_commitment",
            "/vendor_tax_reference_commitment",
            "/vendor_email_commitment",
        ],
        "material_paths": [
            "/record_is_synthetic",
            "/supplier_rank_requested",
            "/duplicate_vendor_count",
            "/required_fields_complete",
            "/bank_account_created",
            "/vendor_schema_digest",
            "/vendor_search_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_self_hosted_database",
            "provider_company_preflight",
            "provider_duplicate_vendor_search",
            "provider_vendor_schema_preflight",
            "gateway_synthetic_vendor_constraint",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.procurement.vendor.create.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Synthetic vendor"},
            {"field": "linked_to", "label": "Pinned Odoo company"},
            {"field": "provider", "label": "ERP provider"},
            {"field": "request_digest", "label": "Bound request"},
        ],
        "does_not_establish": [
            "vendor_identity_tax_status_or_bank_account_ownership",
            "commercial_approval_or_authority_to_place_orders",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["external_state_change", "procurement", "vendor_master"],
        "properties": {
            "provider_database_reference_commitment": base.cref(),
            "company_reference_commitment": base.cref(),
            "record_is_synthetic": {"const": True},
            "vendor_name_commitment": base.cref(),
            "vendor_tax_reference_commitment": base.cref(),
            "vendor_email_commitment": base.cref(),
            "supplier_rank_requested": {"const": 1},
            "duplicate_vendor_count": {"const": 0},
            "required_fields_complete": {"const": True},
            "bank_account_created": {"const": False},
            "vendor_schema_digest": base.dref(),
            "vendor_search_state_digest": base.dref(),
        },
        "sample": {
            "provider_database_reference_commitment": base.commitment("7"),
            "company_reference_commitment": base.commitment("8"),
            "record_is_synthetic": True,
            "vendor_name_commitment": base.commitment("9"),
            "vendor_tax_reference_commitment": base.commitment("a"),
            "vendor_email_commitment": base.commitment("b"),
            "supplier_rank_requested": 1,
            "duplicate_vendor_count": 0,
            "required_fields_complete": True,
            "bank_account_created": False,
            "vendor_schema_digest": base.digest("c"),
            "vendor_search_state_digest": base.digest("d"),
        },
    },
    {
        "consequence_type": "procurement.purchase_order.issue.v1",
        "semantic_id": "keel.action.procurement_purchase_order_issue.v1",
        "action": "procurement.purchase_order.issue",
        "connector_identity": "odoo",
        "environment": "self_hosted_synthetic",
        "provider_api_version": "odoo-jsonrpc-v2",
        "customer_title": "AI Permit-to-Issue-Purchase-Order",
        "type_definition": (
            "Exact authorization to create one bounded draft purchase order for "
            "one synthetic supplier in one pinned self-hosted Odoo database"
        ),
        "provider_mapping": {
            "provider": "odoo",
            "operation": "purchase.order.create_draft",
        },
        "specific_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/record_is_synthetic",
            "/vendor_reference_commitment",
            "/purchase_order_external_reference_commitment",
            "/line_item_set_commitment",
            "/line_item_count",
            "/total_amount_minor",
            "/currency",
            "/vendor_active",
            "/vendor_supplier_rank_positive",
            "/product_set_allowlisted",
            "/total_matches_provider_pricing",
            "/purchase_order_status_before",
            "/requested_purchase_order_status",
            "/spend_committed",
            "/supplier_notification_sent",
            "/pricing_state_digest",
        ],
        "target_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/vendor_reference_commitment",
            "/purchase_order_external_reference_commitment",
            "/line_item_set_commitment",
        ],
        "material_paths": [
            "/record_is_synthetic",
            "/line_item_count",
            "/total_amount_minor",
            "/currency",
            "/vendor_active",
            "/vendor_supplier_rank_positive",
            "/product_set_allowlisted",
            "/total_matches_provider_pricing",
            "/purchase_order_status_before",
            "/requested_purchase_order_status",
            "/spend_committed",
            "/supplier_notification_sent",
            "/pricing_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_self_hosted_database",
            "provider_vendor_and_product_preflight",
            "provider_pricing_preflight",
            "provider_external_reference_absence_preflight",
            "gateway_product_allowlist",
            "gateway_draft_only_constraint",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.procurement.purchase_order.issue.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Draft purchase order"},
            {"field": "amount", "label": "Order total"},
            {"field": "currency", "label": "Currency"},
            {"field": "provider", "label": "ERP provider"},
        ],
        "does_not_establish": [
            "supplier_delivery_or_acceptance_of_the_order",
            "spend_commitment_invoice_approval_or_payment_release",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["financial_record", "procurement", "purchase_order"],
        "properties": {
            "provider_database_reference_commitment": base.cref(),
            "company_reference_commitment": base.cref(),
            "record_is_synthetic": {"const": True},
            "vendor_reference_commitment": base.cref(),
            "purchase_order_external_reference_commitment": base.cref(),
            "line_item_set_commitment": base.cref(),
            "line_item_count": {"type": "integer", "minimum": 1, "maximum": 25},
            "total_amount_minor": {"type": "integer", "minimum": 1},
            "currency": currency(),
            "vendor_active": {"const": True},
            "vendor_supplier_rank_positive": {"const": True},
            "product_set_allowlisted": {"const": True},
            "total_matches_provider_pricing": {"const": True},
            "purchase_order_status_before": {"const": "absent"},
            "requested_purchase_order_status": {"const": "draft"},
            "spend_committed": {"const": False},
            "supplier_notification_sent": {"const": False},
            "pricing_state_digest": base.dref(),
        },
        "sample": {
            "provider_database_reference_commitment": base.commitment("7"),
            "company_reference_commitment": base.commitment("8"),
            "record_is_synthetic": True,
            "vendor_reference_commitment": base.commitment("9"),
            "purchase_order_external_reference_commitment": base.commitment("a"),
            "line_item_set_commitment": base.commitment("b"),
            "line_item_count": 2,
            "total_amount_minor": 75000,
            "currency": "USD",
            "vendor_active": True,
            "vendor_supplier_rank_positive": True,
            "product_set_allowlisted": True,
            "total_matches_provider_pricing": True,
            "purchase_order_status_before": "absent",
            "requested_purchase_order_status": "draft",
            "spend_committed": False,
            "supplier_notification_sent": False,
            "pricing_state_digest": base.digest("c"),
        },
    },
    {
        "consequence_type": "procurement.spend.commit.v1",
        "semantic_id": "keel.action.procurement_spend_commit.v1",
        "action": "procurement.spend.commit",
        "connector_identity": "odoo",
        "environment": "self_hosted_synthetic",
        "provider_api_version": "odoo-jsonrpc-v2",
        "customer_title": "AI Permit-to-Commit-Procurement-Spend",
        "type_definition": (
            "Exact authorization to confirm one provider-observed draft purchase "
            "order and commit its bounded synthetic procurement spend"
        ),
        "provider_mapping": {
            "provider": "odoo",
            "operation": "purchase.order.button_confirm",
        },
        "specific_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/record_is_synthetic",
            "/purchase_order_reference_commitment",
            "/vendor_reference_commitment",
            "/line_item_set_commitment",
            "/line_item_count",
            "/total_amount_minor",
            "/currency",
            "/available_budget_minor",
            "/amount_within_budget",
            "/current_purchase_order_status",
            "/requested_purchase_order_status",
            "/spend_committed_before",
            "/spend_committed_after",
            "/supplier_notification_sent",
            "/payment_released",
            "/purchase_order_state_digest",
        ],
        "target_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/purchase_order_reference_commitment",
            "/vendor_reference_commitment",
            "/line_item_set_commitment",
        ],
        "material_paths": [
            "/record_is_synthetic",
            "/line_item_count",
            "/total_amount_minor",
            "/currency",
            "/available_budget_minor",
            "/amount_within_budget",
            "/current_purchase_order_status",
            "/requested_purchase_order_status",
            "/spend_committed_before",
            "/spend_committed_after",
            "/supplier_notification_sent",
            "/payment_released",
            "/purchase_order_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_self_hosted_database",
            "provider_purchase_order_preflight",
            "provider_budget_preflight",
            "gateway_spend_limit_derivation",
            "gateway_transition_allowlist",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.procurement.spend.commit.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Draft purchase order"},
            {"field": "amount", "label": "Spend commitment"},
            {"field": "currency", "label": "Currency"},
            {"field": "provider", "label": "ERP provider"},
        ],
        "does_not_establish": [
            "supplier_acceptance_delivery_invoice_or_payment",
            "legal_enforceability_of_the_purchase_commitment",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["financial_commitment", "procurement", "purchase_order"],
        "properties": {
            "provider_database_reference_commitment": base.cref(),
            "company_reference_commitment": base.cref(),
            "record_is_synthetic": {"const": True},
            "purchase_order_reference_commitment": base.cref(),
            "vendor_reference_commitment": base.cref(),
            "line_item_set_commitment": base.cref(),
            "line_item_count": {"type": "integer", "minimum": 1, "maximum": 25},
            "total_amount_minor": {"type": "integer", "minimum": 1},
            "currency": currency(),
            "available_budget_minor": {"type": "integer", "minimum": 1},
            "amount_within_budget": {"const": True},
            "current_purchase_order_status": {"const": "draft"},
            "requested_purchase_order_status": {"const": "purchase"},
            "spend_committed_before": {"const": False},
            "spend_committed_after": {"const": True},
            "supplier_notification_sent": {"const": False},
            "payment_released": {"const": False},
            "purchase_order_state_digest": base.dref(),
        },
        "sample": {
            "provider_database_reference_commitment": base.commitment("7"),
            "company_reference_commitment": base.commitment("8"),
            "record_is_synthetic": True,
            "purchase_order_reference_commitment": base.commitment("9"),
            "vendor_reference_commitment": base.commitment("a"),
            "line_item_set_commitment": base.commitment("b"),
            "line_item_count": 2,
            "total_amount_minor": 75000,
            "currency": "USD",
            "available_budget_minor": 100000,
            "amount_within_budget": True,
            "current_purchase_order_status": "draft",
            "requested_purchase_order_status": "purchase",
            "spend_committed_before": False,
            "spend_committed_after": True,
            "supplier_notification_sent": False,
            "payment_released": False,
            "purchase_order_state_digest": base.digest("c"),
        },
    },
    {
        "consequence_type": "ap.invoice.approve.v1",
        "semantic_id": "keel.action.ap_invoice_approve.v1",
        "action": "ap.invoice.approve",
        "connector_identity": "odoo",
        "environment": "self_hosted_synthetic",
        "provider_api_version": "odoo-jsonrpc-v2",
        "customer_title": "AI Permit-to-Approve-Invoice",
        "type_definition": (
            "Exact authorization to post one provider-observed synthetic vendor "
            "bill after a complete three-way match"
        ),
        "provider_mapping": {
            "provider": "odoo",
            "operation": "account.move.action_post_vendor_bill",
        },
        "specific_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/record_is_synthetic",
            "/invoice_reference_commitment",
            "/purchase_order_reference_commitment",
            "/vendor_reference_commitment",
            "/total_amount_minor",
            "/currency",
            "/current_invoice_status",
            "/requested_invoice_status",
            "/payment_status",
            "/duplicate_candidate_count",
            "/three_way_match_complete",
            "/invoice_total_matches_purchase_order",
            "/receipt_quantity_covers_invoice",
            "/accounting_period_open",
            "/invoice_state_digest",
        ],
        "target_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/invoice_reference_commitment",
            "/purchase_order_reference_commitment",
            "/vendor_reference_commitment",
        ],
        "material_paths": [
            "/record_is_synthetic",
            "/total_amount_minor",
            "/currency",
            "/current_invoice_status",
            "/requested_invoice_status",
            "/payment_status",
            "/duplicate_candidate_count",
            "/three_way_match_complete",
            "/invoice_total_matches_purchase_order",
            "/receipt_quantity_covers_invoice",
            "/accounting_period_open",
            "/invoice_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_self_hosted_database",
            "provider_vendor_bill_preflight",
            "provider_purchase_order_and_receipt_preflight",
            "provider_duplicate_invoice_search",
            "gateway_three_way_match_derivation",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.ap.invoice.approve.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Vendor invoice"},
            {"field": "amount", "label": "Invoice total"},
            {"field": "currency", "label": "Currency"},
            {"field": "provider", "label": "ERP provider"},
        ],
        "does_not_establish": [
            "authenticity_or_legal_validity_of_the_vendor_invoice",
            "payment_dispatch_settlement_or_supplier_receipt",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["accounts_payable", "invoice_approval", "financial_record"],
        "properties": {
            "provider_database_reference_commitment": base.cref(),
            "company_reference_commitment": base.cref(),
            "record_is_synthetic": {"const": True},
            "invoice_reference_commitment": base.cref(),
            "purchase_order_reference_commitment": base.cref(),
            "vendor_reference_commitment": base.cref(),
            "total_amount_minor": {"type": "integer", "minimum": 1},
            "currency": currency(),
            "current_invoice_status": {"const": "draft"},
            "requested_invoice_status": {"const": "posted"},
            "payment_status": {"const": "not_paid"},
            "duplicate_candidate_count": {"const": 0},
            "three_way_match_complete": {"const": True},
            "invoice_total_matches_purchase_order": {"const": True},
            "receipt_quantity_covers_invoice": {"const": True},
            "accounting_period_open": {"const": True},
            "invoice_state_digest": base.dref(),
        },
        "sample": {
            "provider_database_reference_commitment": base.commitment("7"),
            "company_reference_commitment": base.commitment("8"),
            "record_is_synthetic": True,
            "invoice_reference_commitment": base.commitment("9"),
            "purchase_order_reference_commitment": base.commitment("a"),
            "vendor_reference_commitment": base.commitment("b"),
            "total_amount_minor": 75000,
            "currency": "USD",
            "current_invoice_status": "draft",
            "requested_invoice_status": "posted",
            "payment_status": "not_paid",
            "duplicate_candidate_count": 0,
            "three_way_match_complete": True,
            "invoice_total_matches_purchase_order": True,
            "receipt_quantity_covers_invoice": True,
            "accounting_period_open": True,
            "invoice_state_digest": base.digest("c"),
        },
    },
    {
        "consequence_type": "ap.invoice.duplicate.reject.v1",
        "semantic_id": "keel.action.ap_invoice_duplicate_reject.v1",
        "action": "ap.invoice.duplicate.reject",
        "connector_identity": "odoo",
        "environment": "self_hosted_synthetic",
        "provider_api_version": "odoo-jsonrpc-v2",
        "customer_title": "AI Permit-to-Reject-Duplicate-Invoice",
        "type_definition": (
            "Exact authorization to cancel one unpaid synthetic draft vendor bill "
            "after a deterministic exact duplicate match"
        ),
        "provider_mapping": {
            "provider": "odoo",
            "operation": "account.move.button_cancel_duplicate_vendor_bill",
        },
        "specific_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/record_is_synthetic",
            "/invoice_reference_commitment",
            "/duplicate_invoice_reference_commitment",
            "/vendor_reference_commitment",
            "/current_invoice_status",
            "/requested_invoice_status",
            "/payment_status",
            "/payment_released",
            "/duplicate_match_method",
            "/vendor_reference_matches",
            "/invoice_number_matches",
            "/total_amount_matches",
            "/duplicate_match_digest",
            "/invoice_state_digest",
        ],
        "target_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/invoice_reference_commitment",
            "/duplicate_invoice_reference_commitment",
            "/vendor_reference_commitment",
        ],
        "material_paths": [
            "/record_is_synthetic",
            "/current_invoice_status",
            "/requested_invoice_status",
            "/payment_status",
            "/payment_released",
            "/duplicate_match_method",
            "/vendor_reference_matches",
            "/invoice_number_matches",
            "/total_amount_matches",
            "/duplicate_match_digest",
            "/invoice_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_self_hosted_database",
            "provider_vendor_bill_preflight",
            "provider_exact_duplicate_search",
            "gateway_duplicate_derivation_v1",
            "gateway_unpaid_state_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.ap.invoice.duplicate.reject.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Duplicate vendor invoice"},
            {"field": "linked_to", "label": "Existing provider invoice"},
            {"field": "provider", "label": "ERP provider"},
            {"field": "request_digest", "label": "Bound request"},
        ],
        "does_not_establish": [
            "fraud_intent_or_wrongdoing_by_the_vendor",
            "legal_right_to_reject_or_dispute_the_invoice",
            "absence_of_later_recreation_or_other_provider_changes",
        ],
        "risk_tags": ["accounts_payable", "invoice_rejection", "data_mutation"],
        "properties": {
            "provider_database_reference_commitment": base.cref(),
            "company_reference_commitment": base.cref(),
            "record_is_synthetic": {"const": True},
            "invoice_reference_commitment": base.cref(),
            "duplicate_invoice_reference_commitment": base.cref(),
            "vendor_reference_commitment": base.cref(),
            "current_invoice_status": {"const": "draft"},
            "requested_invoice_status": {"const": "cancel"},
            "payment_status": {"const": "not_paid"},
            "payment_released": {"const": False},
            "duplicate_match_method": {
                "const": "provider_vendor_number_and_total_exact.v1"
            },
            "vendor_reference_matches": {"const": True},
            "invoice_number_matches": {"const": True},
            "total_amount_matches": {"const": True},
            "duplicate_match_digest": base.dref(),
            "invoice_state_digest": base.dref(),
        },
        "sample": {
            "provider_database_reference_commitment": base.commitment("7"),
            "company_reference_commitment": base.commitment("8"),
            "record_is_synthetic": True,
            "invoice_reference_commitment": base.commitment("9"),
            "duplicate_invoice_reference_commitment": base.commitment("a"),
            "vendor_reference_commitment": base.commitment("b"),
            "current_invoice_status": "draft",
            "requested_invoice_status": "cancel",
            "payment_status": "not_paid",
            "payment_released": False,
            "duplicate_match_method": "provider_vendor_number_and_total_exact.v1",
            "vendor_reference_matches": True,
            "invoice_number_matches": True,
            "total_amount_matches": True,
            "duplicate_match_digest": base.digest("c"),
            "invoice_state_digest": base.digest("d"),
        },
    },
    {
        "consequence_type": "ap.invoice.payment.release.v1",
        "semantic_id": "keel.action.ap_invoice_payment_release.v1",
        "action": "ap.invoice.payment.release",
        "connector_identity": "odoo",
        "environment": "self_hosted_plus_provider_sandbox",
        "provider_api_version": "odoo-jsonrpc-v2+stripe-2026-07-30.basil",
        "customer_title": "AI Permit-to-Release-Invoice-Payment",
        "type_definition": (
            "Exact authorization for one two-step demo saga that creates a Stripe "
            "test-mode supplier transfer and registers the matching Odoo payment"
        ),
        "provider_mapping": {
            "provider": "odoo+stripe",
            "operation": "transfers.create+account.payment.register",
        },
        "specific_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/record_is_synthetic",
            "/invoice_reference_commitment",
            "/purchase_order_reference_commitment",
            "/vendor_reference_commitment",
            "/payment_destination_reference_commitment",
            "/total_amount_minor",
            "/currency",
            "/invoice_status",
            "/payment_status",
            "/three_way_match_complete",
            "/stripe_livemode",
            "/stripe_transfer_status_before",
            "/existing_transfer_count",
            "/workflow_step_count",
            "/odoo_payment_registration_required",
            "/value_conservation_valid",
            "/invoice_state_digest",
            "/payment_destination_state_digest",
        ],
        "target_paths": [
            "/provider_database_reference_commitment",
            "/company_reference_commitment",
            "/invoice_reference_commitment",
            "/purchase_order_reference_commitment",
            "/vendor_reference_commitment",
            "/payment_destination_reference_commitment",
        ],
        "material_paths": [
            "/record_is_synthetic",
            "/total_amount_minor",
            "/currency",
            "/invoice_status",
            "/payment_status",
            "/three_way_match_complete",
            "/stripe_livemode",
            "/stripe_transfer_status_before",
            "/existing_transfer_count",
            "/workflow_step_count",
            "/odoo_payment_registration_required",
            "/value_conservation_valid",
            "/invoice_state_digest",
            "/payment_destination_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_self_hosted_database",
            "provider_posted_unpaid_invoice_preflight",
            "provider_three_way_match_preflight",
            "provider_stripe_test_destination_preflight",
            "provider_transfer_absence_preflight",
            "gateway_value_conservation_derivation",
            "gateway_workflow_saga_ledger",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.ap.invoice.payment.release.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Approved vendor invoice"},
            {"field": "amount", "label": "Invoice payment"},
            {"field": "currency", "label": "Currency"},
            {"field": "recipient", "label": "Synthetic supplier destination"},
        ],
        "does_not_establish": [
            "bank_settlement_supplier_receipt_or_payment_finality",
            "successful_completion_of_both_steps_without_provider_readback",
            "validity_of_a_real_invoice_supplier_or_payment_obligation",
        ],
        "risk_tags": ["accounts_payable", "value_movement", "workflow_saga"],
        "properties": {
            "provider_database_reference_commitment": base.cref(),
            "company_reference_commitment": base.cref(),
            "record_is_synthetic": {"const": True},
            "invoice_reference_commitment": base.cref(),
            "purchase_order_reference_commitment": base.cref(),
            "vendor_reference_commitment": base.cref(),
            "payment_destination_reference_commitment": base.cref(),
            "total_amount_minor": {"type": "integer", "minimum": 1},
            "currency": currency(),
            "invoice_status": {"const": "posted"},
            "payment_status": {"const": "not_paid"},
            "three_way_match_complete": {"const": True},
            "stripe_livemode": {"const": False},
            "stripe_transfer_status_before": {"const": "absent"},
            "existing_transfer_count": {"const": 0},
            "workflow_step_count": {"const": 2},
            "odoo_payment_registration_required": {"const": True},
            "value_conservation_valid": {"const": True},
            "invoice_state_digest": base.dref(),
            "payment_destination_state_digest": base.dref(),
        },
        "sample": {
            "provider_database_reference_commitment": base.commitment("7"),
            "company_reference_commitment": base.commitment("8"),
            "record_is_synthetic": True,
            "invoice_reference_commitment": base.commitment("9"),
            "purchase_order_reference_commitment": base.commitment("a"),
            "vendor_reference_commitment": base.commitment("b"),
            "payment_destination_reference_commitment": base.commitment("c"),
            "total_amount_minor": 75000,
            "currency": "USD",
            "invoice_status": "posted",
            "payment_status": "not_paid",
            "three_way_match_complete": True,
            "stripe_livemode": False,
            "stripe_transfer_status_before": "absent",
            "existing_transfer_count": 0,
            "workflow_step_count": 2,
            "odoo_payment_registration_required": True,
            "value_conservation_valid": True,
            "invoice_state_digest": base.digest("d"),
            "payment_destination_state_digest": base.digest("e"),
        },
    },
]


INTEGER_FIELDS = {
    "supplier_rank_requested",
    "duplicate_vendor_count",
    "line_item_count",
    "total_amount_minor",
    "available_budget_minor",
    "duplicate_candidate_count",
    "existing_transfer_count",
    "workflow_step_count",
}
BOOLEAN_FIELDS = {
    "record_is_synthetic",
    "required_fields_complete",
    "bank_account_created",
    "vendor_active",
    "vendor_supplier_rank_positive",
    "product_set_allowlisted",
    "total_matches_provider_pricing",
    "spend_committed",
    "supplier_notification_sent",
    "amount_within_budget",
    "spend_committed_before",
    "spend_committed_after",
    "payment_released",
    "three_way_match_complete",
    "invoice_total_matches_purchase_order",
    "receipt_quantity_covers_invoice",
    "accounting_period_open",
    "vendor_reference_matches",
    "invoice_number_matches",
    "total_amount_matches",
    "stripe_livemode",
    "odoo_payment_registration_required",
    "value_conservation_valid",
}


def configure_base() -> None:
    base.FACT_SCHEMA = FACT_SCHEMA
    base.ACTION_DEFS = ACTION_DEFS
    base.INTEGER_FIELDS.update(INTEGER_FIELDS)
    base.BOOLEAN_FIELDS.update(BOOLEAN_FIELDS)


def profile_id(action_def: dict[str, Any]) -> str:
    return base.profile_id(action_def)


def build_schema() -> dict[str, Any]:
    configure_base()
    schema = base.build_schema()
    schema["$id"] = (
        "https://github.com/keelapi/keel-permit/schemas/"
        "procurement-ap-exact-facts-v1.schema.json"
    )
    schema["title"] = "Keel exact Procurement and Accounts Payable facts v1"
    for action_def in ACTION_DEFS:
        definition = schema["$defs"][action_def["action"].replace(".", "_")]
        definition["properties"]["version"] = {"const": FACT_VERSION}
        definition["properties"]["provider_environment"] = {
            "const": action_def["environment"]
        }
    return schema


def fact_vector(action_def: dict[str, Any]) -> dict[str, Any]:
    configure_base()
    value = base.fact_vector(action_def)
    value["version"] = FACT_VERSION
    value["provider_environment"] = action_def["environment"]
    value["provider_api_version"] = action_def["provider_api_version"]
    value["preflight_observed_at"] = "2026-08-11T03:00:00Z"
    value["preflight_expires_at"] = "2026-08-11T03:05:00Z"
    return value


def main() -> None:
    configure_base()
    write(FACT_SCHEMA, build_schema())

    consequence = copy.deepcopy(load("consequence_registry/v9.json"))
    consequence["$schema"] = "./v10.schema.json"
    consequence["version"] = "keel.consequence_registry.v10"
    consequence["consequences"].extend(base.consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v10.json", consequence)

    consequence_schema = copy.deepcopy(load("consequence_registry/v9.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v10.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v10"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v10"
    )
    write("consequence_registry/v10.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts = copy.deepcopy(load("fact_profiles/v12.json"))
    facts["$schema"] = "./v13.schema.json"
    facts["version"] = "keel.fact_profile_registry.v13"
    facts["profiles"].extend(
        base.fact_profile(item, facts_digest) for item in ACTION_DEFS
    )
    write("fact_profiles/v13.json", facts)

    facts_schema = copy.deepcopy(load("fact_profiles/v12.schema.json"))
    facts_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v13.schema.json"
    )
    facts_schema["title"] = "Keel Permit fact profile registry v13"
    facts_schema["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v13"
    )
    write("fact_profiles/v13.schema.json", facts_schema)

    semantics = copy.deepcopy(load("semantic_registry/v14.json"))
    semantics["$schema"] = "./v15.schema.json"
    semantics["version"] = "keel.semantic_selector_registry.v15"
    semantics["entries"].extend(base.semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v15.json", semantics)

    semantic_schema = copy.deepcopy(load("semantic_registry/v14.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v15.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v15"
    semantic_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v15"
    )
    write("semantic_registry/v15.schema.json", semantic_schema)

    presentation = copy.deepcopy(load("presentation_registry/v13.json"))
    presentation["$schema"] = "./v14.schema.json"
    presentation["version"] = "keel.presentation_registry.v14"
    presentation["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v15"
    )
    presentation["profiles"].extend(
        base.presentation_profile(item) for item in ACTION_DEFS
    )
    write("presentation_registry/v14.json", presentation)

    presentation_schema = copy.deepcopy(load("presentation_registry/v13.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "presentation_registry/v14.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v14"
    presentation_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v14"
    )
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v15"
    )
    write("presentation_registry/v14.schema.json", presentation_schema)

    vectors = copy.deepcopy(load("consequence_registry/test-vectors/v10.json"))
    vectors["version"] = "keel.consequence_registry.test_vectors.v11"
    vectors["consequence_registry_version"] = consequence["version"]
    vectors["semantic_registry_version"] = semantics["version"]
    vectors["presentation_registry_version"] = presentation["version"]
    for action_def in ACTION_DEFS:
        vectors["vectors"].append(
            {
                "id": action_def["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": action_def["action"],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "expected_semantic_id": action_def["semantic_id"],
                "expected_title": action_def["customer_title"],
                "expected_fact_profile_id": profile_id(action_def),
                "valid_authorization_facts": fact_vector(action_def),
            }
        )
    write("consequence_registry/test-vectors/v11.json", vectors)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v10", "consequence_registry/v10.json"),
        (
            "keel.permit.consequence_registry.v10.schema",
            "consequence_registry/v10.schema.json",
        ),
        ("keel.permit.procurement_ap_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v13", "fact_profiles/v13.json"),
        (
            "keel.permit.fact_profile_registry.v13.schema",
            "fact_profiles/v13.schema.json",
        ),
        ("keel.permit.semantic_selector_registry.v15", "semantic_registry/v15.json"),
        (
            "keel.permit.semantic_selector_registry.v15.schema",
            "semantic_registry/v15.schema.json",
        ),
        ("keel.permit.presentation_registry.v14", "presentation_registry/v14.json"),
        (
            "keel.permit.presentation_registry.v14.schema",
            "presentation_registry/v14.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v11",
            "consequence_registry/test-vectors/v11.json",
        ),
        (
            "keel.permit.procurement_ap_exact_action_contract.v1.spec",
            "spec/procurement-ap-exact-action-contract-v1.md",
        ),
    ]
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        if path in existing:
            existing[path]["id"] = artifact_id
            existing[path]["sha256"] = sha256(path)
        else:
            manifest["artifacts"].append(
                {"id": artifact_id, "path": path, "sha256": sha256(path)}
            )
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
