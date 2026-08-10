#!/usr/bin/env python3
"""Build the additive Transactional CX exact-action contract artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FACT_SCHEMA = "schemas/transactional-cx-exact-facts-v1.schema.json"


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write(path: str, value: dict) -> None:
    destination = ROOT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


CONSEQUENCES = [
    {
        "consequence_type": "payment.refund.execute.v2",
        "semantic_id": "keel.action.payment_refund.v2",
        "tool_names": ["payment.refund"],
        "customer_title": "AI Permit-to-Refund-Payment",
        "type_definition": (
            "Exact authorization to refund one provider-verified payment amount"
        ),
        "required_material_fields": [
            "original_payment_reference_commitment",
            "amount_minor",
            "currency",
            "refund_reason",
            "payment_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_payment_preflight",
            "refundable_amount_minor_before",
            "provider_environment",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.payment.refund.canonical.v2",
        "provider_mappings": [
            {"provider": "stripe", "operation": "refunds.create"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Original payment"},
            {"field": "amount", "label": "Refund amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "recipient", "label": "Payer"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "settlement",
            "evidence_scope",
        ],
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "funds_returned_to_the_payer",
            "financial_settlement_or_absence_of_later_reversal",
        ],
        "risk_tags": ["value_movement", "refund", "customer_account"],
    },
    {
        "consequence_type": "customer.credit.issue.v1",
        "semantic_id": "keel.action.customer_credit_issue.v1",
        "tool_names": ["customer.credit.issue"],
        "customer_title": "AI Permit-to-Issue-Account-Credit",
        "type_definition": (
            "Exact authorization to create one immutable customer credit-balance adjustment"
        ),
        "required_material_fields": [
            "customer_reference_commitment",
            "amount_minor",
            "provider_amount_minor",
            "currency",
            "customer_balance_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_customer_preflight",
            "credit_sign_invariant",
            "expected_balance_invariant",
            "provider_environment",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.customer.credit.issue.canonical.v1",
        "provider_mappings": [
            {
                "provider": "stripe",
                "operation": "customer_balance_transactions.create",
            }
        ],
        "leading_fields": [
            {"field": "resource", "label": "Customer account"},
            {"field": "amount", "label": "Credit amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "provider", "label": "Billing provider"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "limits",
            "dispatch",
            "provider_outcome",
            "value_conservation",
            "evidence_scope",
        ],
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "application_of_the_credit_to_a_future_invoice",
            "cash_payment_or_cash_refund",
        ],
        "risk_tags": ["financial_record", "account_credit", "customer_account"],
    },
    {
        "consequence_type": "subscription.cancellation.schedule.v1",
        "semantic_id": "keel.action.subscription_cancellation_schedule.v1",
        "tool_names": ["subscription.cancellation.schedule"],
        "customer_title": "AI Permit-to-Schedule-Subscription-Cancellation",
        "type_definition": (
            "Exact authorization to schedule one active subscription to cancel at period end"
        ),
        "required_material_fields": [
            "subscription_reference_commitment",
            "cancel_at_period_end_before",
            "cancel_at_period_end_requested",
            "current_period_end",
            "subscription_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_subscription_preflight",
            "not_already_scheduled",
            "not_ended",
            "provider_environment",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.subscription.cancellation.schedule.canonical.v1",
        "provider_mappings": [
            {"provider": "stripe", "operation": "subscriptions.update"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Subscription"},
            {"field": "effective_at", "label": "Cancellation date"},
            {"field": "recipient", "label": "Customer"},
            {"field": "provider", "label": "Billing provider"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "evidence_scope",
        ],
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "subscription_termination_before_period_end",
            "refund_or_credit_for_unused_service",
        ],
        "risk_tags": ["subscription_change", "customer_account", "future_effect"],
    },
    {
        "consequence_type": "subscription.cancellation.withdraw.v1",
        "semantic_id": "keel.action.subscription_cancellation_withdraw.v1",
        "tool_names": ["subscription.cancellation.withdraw"],
        "customer_title": "AI Permit-to-Withdraw-Subscription-Cancellation",
        "type_definition": (
            "Exact authorization to withdraw a pending period-end cancellation"
        ),
        "required_material_fields": [
            "subscription_reference_commitment",
            "cancel_at_period_end_before",
            "cancel_at_period_end_requested",
            "current_period_end",
            "canceled_at_before",
            "ended_at_before",
            "subscription_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_subscription_preflight",
            "cancellation_is_pending",
            "not_canceled_or_ended",
            "provider_environment",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.subscription.cancellation.withdraw.canonical.v1",
        "provider_mappings": [
            {"provider": "stripe", "operation": "subscriptions.update"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Subscription"},
            {"field": "effective_at", "label": "Former cancellation date"},
            {"field": "recipient", "label": "Customer"},
            {"field": "provider", "label": "Billing provider"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "evidence_scope",
        ],
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "reinstatement_of_an_already_canceled_subscription",
            "future_successful_renewal_or_payment",
        ],
        "risk_tags": ["subscription_change", "customer_account", "future_billing"],
    },
    {
        "consequence_type": "support.case.resolve.v1",
        "semantic_id": "keel.action.support_case_resolve.v1",
        "tool_names": ["support.case.resolve"],
        "customer_title": "AI Permit-to-Resolve-Support-Case",
        "type_definition": (
            "Exact authorization to move one support ticket from an open stage to a provider-declared closed stage"
        ),
        "required_material_fields": [
            "ticket_reference_commitment",
            "pipeline_reference_commitment",
            "current_stage_reference_commitment",
            "requested_stage_reference_commitment",
            "current_stage_state",
            "requested_stage_state",
            "ticket_state_digest",
            "pipeline_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_ticket_preflight",
            "provider_pipeline_preflight",
            "closed_stage_metadata",
            "durable_gateway_idempotency",
            "provider_environment",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.support.case.resolve.canonical.v1",
        "provider_mappings": [
            {"provider": "hubspot", "operation": "tickets.update_stage"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Support case"},
            {"field": "request_digest", "label": "Resolution"},
            {"field": "recipient", "label": "Customer"},
            {"field": "provider", "label": "Support provider"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "evidence_scope",
        ],
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "customer_satisfaction_or_actual_problem_resolution",
            "absence_of_a_concurrent_provider_update",
        ],
        "risk_tags": ["data_mutation", "customer_communication", "case_closure"],
    },
]


FACT_PROFILES = {
    "payment.refund.execute.v2": {
        "fact_profile_id": "keel.facts.refund_exact.v2",
        "target_fact_paths": [
            "/original_payment_reference_commitment",
            "/payer_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/amount_minor",
            "/refund_reason",
            "/payment_state_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/payment_reference_kind",
            "/original_payment_reference_commitment",
            "/payer_reference_commitment",
            "/amount_minor",
            "/refundable_amount_minor_before",
            "/currency",
            "/refund_reason",
            "/refund_application_fee",
            "/reverse_transfer",
            "/payment_state_digest",
        ],
    },
    "customer.credit.issue.v1": {
        "fact_profile_id": "keel.facts.customer_credit_issue_exact.v1",
        "target_fact_paths": ["/customer_reference_commitment"],
        "material_request_fact_paths": [
            "/amount_minor",
            "/provider_amount_minor",
            "/currency",
            "/description_commitment",
            "/customer_balance_state_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/customer_reference_commitment",
            "/amount_minor",
            "/provider_amount_minor",
            "/currency",
            "/customer_balance_before_minor",
            "/expected_customer_balance_after_minor",
            "/credit_direction",
            "/description_commitment",
            "/customer_balance_state_digest",
        ],
    },
    "subscription.cancellation.schedule.v1": {
        "fact_profile_id": "keel.facts.subscription_cancellation_schedule_exact.v1",
        "target_fact_paths": [
            "/subscription_reference_commitment",
            "/customer_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/cancel_at_period_end_before",
            "/cancel_at_period_end_requested",
            "/current_period_end",
            "/subscription_state_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/subscription_reference_commitment",
            "/customer_reference_commitment",
            "/subscription_status_before",
            "/cancel_at_period_end_before",
            "/cancel_at_period_end_requested",
            "/current_period_end",
            "/subscription_state_digest",
        ],
    },
    "subscription.cancellation.withdraw.v1": {
        "fact_profile_id": "keel.facts.subscription_cancellation_withdraw_exact.v1",
        "target_fact_paths": [
            "/subscription_reference_commitment",
            "/customer_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/cancel_at_period_end_before",
            "/cancel_at_period_end_requested",
            "/current_period_end",
            "/subscription_state_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/subscription_reference_commitment",
            "/customer_reference_commitment",
            "/subscription_status_before",
            "/cancel_at_period_end_before",
            "/cancel_at_period_end_requested",
            "/current_period_end",
            "/canceled_at_before",
            "/ended_at_before",
            "/subscription_state_digest",
        ],
    },
    "support.case.resolve.v1": {
        "fact_profile_id": "keel.facts.support_case_resolve_exact.v1",
        "target_fact_paths": [
            "/ticket_reference_commitment",
            "/pipeline_reference_commitment",
            "/requested_stage_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/current_stage_reference_commitment",
            "/current_stage_state",
            "/requested_stage_state",
            "/ticket_updated_at_before",
            "/ticket_state_digest",
            "/pipeline_state_digest",
            "/resolution_summary_commitment",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/ticket_reference_commitment",
            "/pipeline_reference_commitment",
            "/current_stage_reference_commitment",
            "/requested_stage_reference_commitment",
            "/current_stage_state",
            "/requested_stage_state",
            "/ticket_updated_at_before",
            "/ticket_state_digest",
            "/pipeline_state_digest",
            "/resolution_summary_commitment",
        ],
    },
}


COMMON_FACT_PATHS = [
    "/connector_identity",
    "/connector_contract_hash",
    "/tool_schema_hash",
    "/decision_trace_hash",
    "/tool_arguments_hash",
    "/request_digest",
    "/provider_environment",
    "/provider_api_version",
    "/preflight_observed_at",
    "/preflight_expires_at",
    "/preflight_snapshot_digest",
    "/idempotency_digest",
    "/max_uses",
]


INTEGER_FIELDS = {
    "amount_minor",
    "refundable_amount_minor_before",
    "provider_amount_minor",
    "customer_balance_before_minor",
    "expected_customer_balance_after_minor",
    "max_uses",
}
BOOLEAN_FIELDS = {
    "refund_application_fee",
    "reverse_transfer",
    "cancel_at_period_end_before",
    "cancel_at_period_end_requested",
}
TIMESTAMP_FIELDS = {
    "preflight_observed_at",
    "preflight_expires_at",
    "current_period_end",
    "ticket_updated_at_before",
}
NULL_FIELDS = {"canceled_at_before", "ended_at_before"}


def semantic_entry(consequence: dict) -> dict:
    return {
        "semantic_id": consequence["semantic_id"],
        "semantic_kind": "exact_action",
        "trusted_source_kinds": ["action_verb_execute"],
        "match": {
            "action_names": consequence["tool_names"],
            "operations": ["call.tools"],
            "allowed_chain_roles": ["session_root", "action_child"],
            "required_evidence_capabilities": [
                "authorization",
                "dispatch",
                "provider_outcome",
            ],
        },
        "excluded_permit_products": ["cost_permit"],
        "release_state": "eligible",
        "fact_profile_id": FACT_PROFILES[consequence["consequence_type"]][
            "fact_profile_id"
        ],
    }


def presentation_profile(consequence: dict) -> dict:
    return {
        "semantic_id": consequence["semantic_id"],
        "presentation_profile_id": (
            consequence["consequence_type"].rsplit(".v", 1)[0].replace(".", "_")
            + ".r1"
        ),
        "customer_title": consequence["customer_title"],
        "type_definition": consequence["type_definition"],
        "leading_fields": consequence["leading_fields"],
        "evidence_sections": consequence["evidence_sections"],
        "does_not_establish": consequence["does_not_establish"],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    }


def fact_field(path: str) -> dict:
    name = path.removeprefix("/")
    commitment = name.endswith("_commitment")
    digest = name.endswith("_digest") or name.endswith("_hash")
    if commitment:
        value_type = "commitment"
    elif digest:
        value_type = "digest"
    elif name in INTEGER_FIELDS:
        value_type = "integer"
    elif name in BOOLEAN_FIELDS:
        value_type = "boolean"
    elif name in TIMESTAMP_FIELDS:
        value_type = "timestamp"
    elif name in NULL_FIELDS:
        value_type = "null"
    else:
        value_type = "string"
    financial = name in {
        "amount_minor",
        "refundable_amount_minor_before",
        "provider_amount_minor",
        "customer_balance_before_minor",
        "expected_customer_balance_after_minor",
        "currency",
    }
    classification = (
        "financial"
        if financial
        else "personal_data"
        if commitment
        else "operational"
    )
    verifier_disclosure = "commitment" if commitment else "cleartext"
    authorized_disclosure = (
        "commitment_with_optional_opening" if commitment else "cleartext"
    )
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": classification,
        "low_entropy_possible": value_type not in {"digest"},
        "disclosure": {
            "verifier_safe": verifier_disclosure,
            "authorized": authorized_disclosure,
            "private": authorized_disclosure,
        },
        "retention": {
            "class": "deletable_identity" if commitment else "permit_evidence",
            "max_days": None,
            "erasable": commitment,
            "erasure_action": "erase_opening" if commitment else "retain_signed_value",
        },
        "commitment_method": (
            "keel.salted_sha256_jcs.v1" if commitment else "signed_cleartext"
        ),
    }


def fact_profile(consequence: dict, schema_digest: str) -> dict:
    contract = FACT_PROFILES[consequence["consequence_type"]]
    paths = list(dict.fromkeys([*COMMON_FACT_PATHS, *contract["field_paths"]]))
    return {
        "fact_profile_id": contract["fact_profile_id"],
        "semantic_ids": [consequence["semantic_id"]],
        "authorized_action": consequence["tool_names"][0],
        "facts_schema": FACT_SCHEMA,
        "facts_schema_digest": f"sha256:{schema_digest}",
        "target_fact_paths": contract["target_fact_paths"],
        "material_request_fact_paths": contract["material_request_fact_paths"],
        "fields": [fact_field(path) for path in paths],
        "release_state": "eligible",
    }


def commitment(character: str) -> dict[str, str]:
    return {
        "method": "keel.salted_sha256_jcs.v1",
        "digest": "sha256:" + character * 64,
    }


def fact_vector(consequence: dict) -> dict:
    action = consequence["tool_names"][0]
    common = {
        "version": "keel.transactional_cx_exact_facts.v1",
        "fact_profile_id": FACT_PROFILES[consequence["consequence_type"]][
            "fact_profile_id"
        ],
        "action": action,
        "operation": "call.tools",
        "connector_identity": "hubspot" if action == "support.case.resolve" else "stripe",
        "connector_contract_hash": "0" * 64,
        "tool_schema_hash": "1" * 64,
        "decision_trace_hash": "2" * 64,
        "tool_arguments_hash": "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "enforcement_mode": "enforced_in_path",
        "provider_environment": (
            "developer_test" if action == "support.case.resolve" else "test"
        ),
        "provider_api_version": (
            "2026-03" if action == "support.case.resolve" else "2025-07-30.basil"
        ),
        "preflight_observed_at": "2026-08-10T12:00:00Z",
        "preflight_expires_at": "2026-08-10T12:05:00Z",
        "preflight_snapshot_digest": "sha256:" + "a" * 64,
        "idempotency_digest": "sha256:" + "9" * 64,
        "max_uses": 1,
    }
    action_specific = {
        "payment.refund": {
            "payment_reference_kind": "payment_intent",
            "original_payment_reference_commitment": commitment("5"),
            "payer_reference_commitment": commitment("6"),
            "amount_minor": 2500,
            "refundable_amount_minor_before": 5000,
            "currency": "USD",
            "refund_reason": "requested_by_customer",
            "refund_application_fee": False,
            "reverse_transfer": False,
            "payment_state_digest": "sha256:" + "7" * 64,
        },
        "customer.credit.issue": {
            "customer_reference_commitment": commitment("5"),
            "amount_minor": 1500,
            "provider_amount_minor": -1500,
            "currency": "USD",
            "customer_balance_before_minor": 0,
            "expected_customer_balance_after_minor": -1500,
            "credit_direction": "customer_credit",
            "description_commitment": commitment("6"),
            "customer_balance_state_digest": "sha256:" + "7" * 64,
        },
        "subscription.cancellation.schedule": {
            "subscription_reference_commitment": commitment("5"),
            "customer_reference_commitment": commitment("6"),
            "subscription_status_before": "active",
            "cancel_at_period_end_before": False,
            "cancel_at_period_end_requested": True,
            "current_period_end": "2026-09-10T12:00:00Z",
            "subscription_state_digest": "sha256:" + "7" * 64,
        },
        "subscription.cancellation.withdraw": {
            "subscription_reference_commitment": commitment("5"),
            "customer_reference_commitment": commitment("6"),
            "subscription_status_before": "active",
            "cancel_at_period_end_before": True,
            "cancel_at_period_end_requested": False,
            "current_period_end": "2026-09-10T12:00:00Z",
            "canceled_at_before": None,
            "ended_at_before": None,
            "subscription_state_digest": "sha256:" + "7" * 64,
        },
        "support.case.resolve": {
            "ticket_reference_commitment": commitment("5"),
            "pipeline_reference_commitment": commitment("6"),
            "current_stage_reference_commitment": commitment("7"),
            "requested_stage_reference_commitment": commitment("8"),
            "current_stage_state": "OPEN",
            "requested_stage_state": "CLOSED",
            "ticket_updated_at_before": "2026-08-10T11:59:00Z",
            "ticket_state_digest": "sha256:" + "b" * 64,
            "pipeline_state_digest": "sha256:" + "c" * 64,
            "resolution_summary_commitment": commitment("d"),
        },
    }
    return {**common, **action_specific[action]}


def main() -> None:
    consequence_v2 = load("consequence_registry/v2.json")
    consequence_v3 = copy.deepcopy(consequence_v2)
    consequence_v3["$schema"] = "./v3.schema.json"
    consequence_v3["version"] = "keel.consequence_registry.v3"
    consequence_v3["consequences"].extend(copy.deepcopy(CONSEQUENCES))
    write("consequence_registry/v3.json", consequence_v3)

    consequence_schema = copy.deepcopy(load("consequence_registry/v2.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v3.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v3"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v3"
    )
    write("consequence_registry/v3.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v5 = load("fact_profiles/v5.json")
    facts_v6 = copy.deepcopy(facts_v5)
    facts_v6["$schema"] = "./v6.schema.json"
    facts_v6["version"] = "keel.fact_profile_registry.v6"
    facts_v6["profiles"].extend(
        fact_profile(item, facts_digest) for item in CONSEQUENCES
    )
    write("fact_profiles/v6.json", facts_v6)

    facts_schema_v6 = copy.deepcopy(load("fact_profiles/v5.schema.json"))
    facts_schema_v6["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v6.schema.json"
    )
    facts_schema_v6["title"] = "Keel Permit fact profile registry v6"
    facts_schema_v6["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v6"
    )
    facts_schema_v6["$defs"]["field"]["properties"]["value_type"]["enum"].extend(
        ["timestamp", "null"]
    )
    write("fact_profiles/v6.schema.json", facts_schema_v6)

    semantics_v7 = load("semantic_registry/v7.json")
    semantics_v8 = copy.deepcopy(semantics_v7)
    semantics_v8["$schema"] = "./v8.schema.json"
    semantics_v8["version"] = "keel.semantic_selector_registry.v8"
    semantics_v8["entries"].extend(semantic_entry(item) for item in CONSEQUENCES)
    write("semantic_registry/v8.json", semantics_v8)

    semantic_schema_v8 = copy.deepcopy(load("semantic_registry/v7.schema.json"))
    semantic_schema_v8["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v8.schema.json"
    )
    semantic_schema_v8["title"] = "Keel Permit semantic selector registry v8"
    semantic_schema_v8["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v8"
    )
    write("semantic_registry/v8.schema.json", semantic_schema_v8)

    presentation_v6 = load("presentation_registry/v6.json")
    presentation_v7 = copy.deepcopy(presentation_v6)
    presentation_v7["$schema"] = "./v7.schema.json"
    presentation_v7["version"] = "keel.presentation_registry.v7"
    presentation_v7["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v8"
    )
    presentation_v7["profiles"].extend(
        presentation_profile(item) for item in CONSEQUENCES
    )
    write("presentation_registry/v7.json", presentation_v7)

    presentation_schema_v7 = copy.deepcopy(
        load("presentation_registry/v6.schema.json")
    )
    presentation_schema_v7["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v7.schema.json"
    )
    presentation_schema_v7["title"] = "Keel Permit presentation registry v7"
    presentation_schema_v7["properties"]["version"]["const"] = (
        "keel.presentation_registry.v7"
    )
    presentation_schema_v7["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v8"
    )
    write("presentation_registry/v7.schema.json", presentation_schema_v7)

    vectors_v3 = load("consequence_registry/test-vectors/v3.json")
    vectors_v4 = copy.deepcopy(vectors_v3)
    vectors_v4["version"] = "keel.consequence_registry.test_vectors.v4"
    vectors_v4["consequence_registry_version"] = consequence_v3["version"]
    vectors_v4["semantic_registry_version"] = semantics_v8["version"]
    vectors_v4["presentation_registry_version"] = presentation_v7["version"]
    for consequence in CONSEQUENCES:
        vectors_v4["vectors"].append(
            {
                "id": consequence["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": consequence["tool_names"][0],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "expected_semantic_id": consequence["semantic_id"],
                "expected_title": consequence["customer_title"],
                "expected_fact_profile_id": FACT_PROFILES[
                    consequence["consequence_type"]
                ]["fact_profile_id"],
                "valid_authorization_facts": fact_vector(consequence),
            }
        )
    write("consequence_registry/test-vectors/v4.json", vectors_v4)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        (
            "keel.permit.consequence_registry.v1.spec",
            "spec/consequence-registry-v1.md",
        ),
        ("keel.permit.consequence_registry.v3", "consequence_registry/v3.json"),
        (
            "keel.permit.consequence_registry.v3.schema",
            "consequence_registry/v3.schema.json",
        ),
        (
            "keel.permit.transactional_cx_exact_facts.v1.schema",
            FACT_SCHEMA,
        ),
        ("keel.permit.fact_profile_registry.v6", "fact_profiles/v6.json"),
        (
            "keel.permit.fact_profile_registry.v6.schema",
            "fact_profiles/v6.schema.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v8",
            "semantic_registry/v8.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v8.schema",
            "semantic_registry/v8.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v7",
            "presentation_registry/v7.json",
        ),
        (
            "keel.permit.presentation_registry.v7.schema",
            "presentation_registry/v7.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v4",
            "consequence_registry/test-vectors/v4.json",
        ),
        (
            "keel.permit.transactional_cx_contract.v1.spec",
            "spec/transactional-cx-exact-action-contract-v1.md",
        ),
    ]
    existing_by_path = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        if path in existing_by_path:
            existing_by_path[path]["id"] = artifact_id
            existing_by_path[path]["sha256"] = sha256(path)
            continue
        manifest["artifacts"].append(
            {"id": artifact_id, "path": path, "sha256": sha256(path)}
        )
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
