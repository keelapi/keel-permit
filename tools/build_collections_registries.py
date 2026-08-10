#!/usr/bin/env python3
"""Build additive exact-action artifacts for Collections Arrangement."""

from __future__ import annotations

import copy
from typing import Any

from build_transactional_cx_registries import commitment, load, sha256, write


FACT_SCHEMA = "schemas/collections-exact-facts-v1.schema.json"

COMMON_PATHS = [
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


def digest(character: str) -> str:
    return "sha256:" + character * 64


def dref() -> dict[str, str]:
    return {"$ref": "#/$defs/digest"}


def cref() -> dict[str, str]:
    return {"$ref": "#/$defs/saltedCommitment"}


def tref() -> dict[str, str]:
    return {"$ref": "#/$defs/timestamp"}


ACTION_DEFS: list[dict[str, Any]] = [
    {
        "consequence_type": "collections.payment.collect.v1",
        "semantic_id": "keel.action.collections_payment_collect.v1",
        "action": "collections.payment.collect",
        "connector_identity": "payments",
        "customer_title": "AI Permit-to-Collect-Payment",
        "type_definition": (
            "Exact authorization to create and confirm one Stripe test-mode "
            "PaymentIntent for one delinquent obligation using one already "
            "attached test payment method"
        ),
        "provider_mapping": {
            "provider": "stripe",
            "operation": "payment_intents.create_and_confirm",
        },
        "specific_paths": [
            "/obligation_reference_commitment",
            "/customer_reference_commitment",
            "/payment_method_reference_commitment",
            "/amount_minor",
            "/currency",
            "/obligation_status",
            "/remaining_balance_minor",
            "/amount_within_balance",
            "/payment_method_attached",
            "/payment_method_type",
            "/collection_mode",
            "/customer_consent_record_digest",
            "/payment_intent_status_before",
        ],
        "target_paths": [
            "/obligation_reference_commitment",
            "/customer_reference_commitment",
            "/payment_method_reference_commitment",
        ],
        "material_paths": [
            "/amount_minor",
            "/currency",
            "/obligation_status",
            "/remaining_balance_minor",
            "/amount_within_balance",
            "/payment_method_attached",
            "/payment_method_type",
            "/collection_mode",
            "/customer_consent_record_digest",
            "/payment_intent_status_before",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_obligation_allowlist",
            "provider_customer_and_payment_method_preflight",
            "provider_payment_intent_absence_preflight",
            "gateway_remaining_balance_preflight",
            "gateway_consent_record_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.collections.payment.collect.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Delinquent obligation"},
            {"field": "amount", "label": "Collection amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "provider", "label": "Payment provider"},
        ],
        "does_not_establish": [
            "stripe_acceptance_or_success_without_provider_readback",
            "financial_settlement_or_chargeback_immunity",
            "legal_validity_collectability_or_customer_identity",
        ],
        "risk_tags": ["value_movement", "collections", "off_session_payment"],
        "properties": {
            "obligation_reference_commitment": cref(),
            "customer_reference_commitment": cref(),
            "payment_method_reference_commitment": cref(),
            "amount_minor": {"type": "integer", "minimum": 1, "maximum": 1000000},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "obligation_status": {"const": "delinquent"},
            "remaining_balance_minor": {"type": "integer", "minimum": 1},
            "amount_within_balance": {"const": True},
            "payment_method_attached": {"const": True},
            "payment_method_type": {"enum": ["card", "us_bank_account"]},
            "collection_mode": {"const": "off_session"},
            "customer_consent_record_digest": dref(),
            "payment_intent_status_before": {"const": "absent"},
        },
        "sample": {
            "obligation_reference_commitment": commitment("7"),
            "customer_reference_commitment": commitment("8"),
            "payment_method_reference_commitment": commitment("9"),
            "amount_minor": 5000,
            "currency": "USD",
            "obligation_status": "delinquent",
            "remaining_balance_minor": 12000,
            "amount_within_balance": True,
            "payment_method_attached": True,
            "payment_method_type": "card",
            "collection_mode": "off_session",
            "customer_consent_record_digest": digest("a"),
            "payment_intent_status_before": "absent",
        },
    },
    {
        "consequence_type": "collections.payment_plan.create.v1",
        "semantic_id": "keel.action.collections_payment_plan_create.v1",
        "action": "collections.payment_plan.create",
        "connector_identity": "payments",
        "customer_title": "AI Permit-to-Create-Payment-Plan",
        "type_definition": (
            "Exact authorization to create one finite Stripe test-mode subscription "
            "schedule for one provider-verified delinquent obligation"
        ),
        "provider_mapping": {
            "provider": "stripe",
            "operation": "subscription_schedules.create",
        },
        "specific_paths": [
            "/obligation_reference_commitment",
            "/customer_reference_commitment",
            "/price_reference_commitment",
            "/installment_amount_minor",
            "/installment_count",
            "/total_plan_amount_minor",
            "/remaining_balance_minor",
            "/amount_matches_balance",
            "/currency",
            "/billing_interval",
            "/plan_start_at",
            "/default_payment_method_present",
            "/existing_active_plan_count",
            "/schedule_mode",
            "/collection_method",
            "/customer_consent_record_digest",
        ],
        "target_paths": [
            "/obligation_reference_commitment",
            "/customer_reference_commitment",
            "/price_reference_commitment",
        ],
        "material_paths": [
            "/installment_amount_minor",
            "/installment_count",
            "/total_plan_amount_minor",
            "/remaining_balance_minor",
            "/amount_matches_balance",
            "/currency",
            "/billing_interval",
            "/plan_start_at",
            "/default_payment_method_present",
            "/existing_active_plan_count",
            "/schedule_mode",
            "/collection_method",
            "/customer_consent_record_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_obligation_and_price_allowlist",
            "provider_customer_and_price_preflight",
            "provider_active_schedule_preflight",
            "gateway_remaining_balance_preflight",
            "gateway_consent_record_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.collections.payment_plan.create.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Delinquent obligation"},
            {"field": "amount", "label": "Installment amount"},
            {"field": "constraints", "label": "Installments and interval"},
            {"field": "provider", "label": "Schedule provider"},
        ],
        "does_not_establish": [
            "future_installment_payment_success_or_financial_settlement",
            "legal_sufficiency_of_customer_consent_or_disclosures",
            "absence_of_future_provider_or_customer_changes",
        ],
        "risk_tags": ["collections", "recurring_payment", "future_value_movement"],
        "properties": {
            "obligation_reference_commitment": cref(),
            "customer_reference_commitment": cref(),
            "price_reference_commitment": cref(),
            "installment_amount_minor": {"type": "integer", "minimum": 1},
            "installment_count": {"type": "integer", "minimum": 2, "maximum": 24},
            "total_plan_amount_minor": {"type": "integer", "minimum": 2},
            "remaining_balance_minor": {"type": "integer", "minimum": 2},
            "amount_matches_balance": {"const": True},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "billing_interval": {"enum": ["week", "month"]},
            "plan_start_at": tref(),
            "default_payment_method_present": {"const": True},
            "existing_active_plan_count": {"const": 0},
            "schedule_mode": {"const": "finite_subscription_schedule"},
            "collection_method": {"const": "charge_automatically"},
            "customer_consent_record_digest": dref(),
        },
        "sample": {
            "obligation_reference_commitment": commitment("7"),
            "customer_reference_commitment": commitment("8"),
            "price_reference_commitment": commitment("9"),
            "installment_amount_minor": 3000,
            "installment_count": 4,
            "total_plan_amount_minor": 12000,
            "remaining_balance_minor": 12000,
            "amount_matches_balance": True,
            "currency": "USD",
            "billing_interval": "month",
            "plan_start_at": "2026-08-15T12:00:00Z",
            "default_payment_method_present": True,
            "existing_active_plan_count": 0,
            "schedule_mode": "finite_subscription_schedule",
            "collection_method": "charge_automatically",
            "customer_consent_record_digest": digest("a"),
        },
    },
    {
        "consequence_type": "collections.autopay.change.v1",
        "semantic_id": "keel.action.collections_autopay_change.v1",
        "action": "collections.autopay.change",
        "connector_identity": "payments",
        "customer_title": "AI Permit-to-Change-Autopay",
        "type_definition": (
            "Exact authorization to change one provider-observed Stripe test-mode "
            "subscription between automatic charging and invoice collection"
        ),
        "provider_mapping": {
            "provider": "stripe",
            "operation": "subscriptions.update_collection_method",
        },
        "specific_paths": [
            "/plan_reference_commitment",
            "/customer_reference_commitment",
            "/subscription_status",
            "/current_collection_method",
            "/requested_collection_method",
            "/autopay_enabled_before",
            "/autopay_enabled_after",
            "/default_payment_method_present",
            "/effective_at",
            "/days_until_due",
            "/customer_consent_record_digest",
        ],
        "target_paths": [
            "/plan_reference_commitment",
            "/customer_reference_commitment",
        ],
        "material_paths": [
            "/subscription_status",
            "/current_collection_method",
            "/requested_collection_method",
            "/autopay_enabled_before",
            "/autopay_enabled_after",
            "/default_payment_method_present",
            "/effective_at",
            "/days_until_due",
            "/customer_consent_record_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_plan_allowlist",
            "provider_subscription_preflight",
            "provider_default_payment_method_preflight",
            "gateway_consent_record_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.collections.autopay.change.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Payment plan"},
            {"field": "constraints", "label": "Autopay change"},
            {"field": "effective_at", "label": "Effective at"},
            {"field": "provider", "label": "Schedule provider"},
        ],
        "does_not_establish": [
            "future_charge_or_invoice_payment_success",
            "legal_sufficiency_of_customer_consent_or_notice",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["collections", "recurring_payment", "account_change"],
        "properties": {
            "plan_reference_commitment": cref(),
            "customer_reference_commitment": cref(),
            "subscription_status": {"enum": ["active", "trialing", "past_due"]},
            "current_collection_method": {"enum": ["charge_automatically", "send_invoice"]},
            "requested_collection_method": {"enum": ["charge_automatically", "send_invoice"]},
            "autopay_enabled_before": {"type": "boolean"},
            "autopay_enabled_after": {"type": "boolean"},
            "default_payment_method_present": {"const": True},
            "effective_at": tref(),
            "days_until_due": {"type": "integer", "minimum": 0, "maximum": 30},
            "customer_consent_record_digest": dref(),
        },
        "sample": {
            "plan_reference_commitment": commitment("7"),
            "customer_reference_commitment": commitment("8"),
            "subscription_status": "active",
            "current_collection_method": "send_invoice",
            "requested_collection_method": "charge_automatically",
            "autopay_enabled_before": False,
            "autopay_enabled_after": True,
            "default_payment_method_present": True,
            "effective_at": "2026-08-10T12:05:00Z",
            "days_until_due": 0,
            "customer_consent_record_digest": digest("9"),
        },
    },
    {
        "consequence_type": "collections.notice.send.v1",
        "semantic_id": "keel.action.collections_notice_send.v1",
        "action": "collections.notice.send",
        "connector_identity": "notification.email",
        "customer_title": "AI Permit-to-Send-Collections-Notice",
        "type_definition": (
            "Exact authorization to send one operator-approved, versioned "
            "collections notice to one dedicated demo recipient"
        ),
        "provider_mapping": {"provider": "resend", "operation": "emails.send"},
        "specific_paths": [
            "/obligation_reference_commitment",
            "/recipient_reference_commitment",
            "/recipient_is_dedicated_demo",
            "/channel",
            "/template_id",
            "/template_version",
            "/template_digest",
            "/rendered_subject_digest",
            "/rendered_content_digest",
            "/amount_due_minor",
            "/currency",
            "/due_at",
            "/jurisdiction",
            "/notice_reason",
            "/prior_notice_count",
            "/delivery_mode",
        ],
        "target_paths": [
            "/obligation_reference_commitment",
            "/recipient_reference_commitment",
            "/template_id",
        ],
        "material_paths": [
            "/recipient_is_dedicated_demo",
            "/channel",
            "/template_version",
            "/template_digest",
            "/rendered_subject_digest",
            "/rendered_content_digest",
            "/amount_due_minor",
            "/currency",
            "/due_at",
            "/jurisdiction",
            "/notice_reason",
            "/prior_notice_count",
            "/delivery_mode",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_recipient_allowlist",
            "gateway_template_allowlist",
            "gateway_obligation_preflight",
            "gateway_rendered_message_derivation",
            "provider_sender_identity_configuration",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.collections.notice.send.canonical.v1",
        "leading_fields": [
            {"field": "recipient", "label": "Dedicated demo recipient"},
            {"field": "resource", "label": "Notice template"},
            {"field": "amount", "label": "Amount due"},
            {"field": "effective_at", "label": "Due at"},
        ],
        "does_not_establish": [
            "email_delivery_receipt_or_recipient_read_confirmation",
            "legal_sufficiency_or_regulatory_compliance_of_the_notice",
            "identity_of_a_real_debtor_or_validity_of_a_real_debt",
        ],
        "risk_tags": ["external_communication", "collections", "regulated_notice"],
        "properties": {
            "obligation_reference_commitment": cref(),
            "recipient_reference_commitment": cref(),
            "recipient_is_dedicated_demo": {"const": True},
            "channel": {"const": "email"},
            "template_id": {"const": "collections-friendly-reminder"},
            "template_version": {"const": "v1"},
            "template_digest": dref(),
            "rendered_subject_digest": dref(),
            "rendered_content_digest": dref(),
            "amount_due_minor": {"type": "integer", "minimum": 1},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "due_at": tref(),
            "jurisdiction": {"const": "DEMO-NOT-A-REAL-JURISDICTION"},
            "notice_reason": {"const": "delinquency_friendly_reminder"},
            "prior_notice_count": {"type": "integer", "minimum": 0, "maximum": 10},
            "delivery_mode": {"const": "provider_email"},
        },
        "sample": {
            "obligation_reference_commitment": commitment("7"),
            "recipient_reference_commitment": commitment("8"),
            "recipient_is_dedicated_demo": True,
            "channel": "email",
            "template_id": "collections-friendly-reminder",
            "template_version": "v1",
            "template_digest": digest("9"),
            "rendered_subject_digest": digest("a"),
            "rendered_content_digest": digest("b"),
            "amount_due_minor": 12000,
            "currency": "USD",
            "due_at": "2026-08-20T12:00:00Z",
            "jurisdiction": "DEMO-NOT-A-REAL-JURISDICTION",
            "notice_reason": "delinquency_friendly_reminder",
            "prior_notice_count": 0,
            "delivery_mode": "provider_email",
        },
    },
]


INTEGER_FIELDS = {
    "amount_minor",
    "remaining_balance_minor",
    "installment_amount_minor",
    "installment_count",
    "total_plan_amount_minor",
    "existing_active_plan_count",
    "days_until_due",
    "amount_due_minor",
    "prior_notice_count",
    "max_uses",
}
BOOLEAN_FIELDS = {
    "amount_within_balance",
    "payment_method_attached",
    "amount_matches_balance",
    "default_payment_method_present",
    "autopay_enabled_before",
    "autopay_enabled_after",
    "recipient_is_dedicated_demo",
}
TIMESTAMP_FIELDS = {
    "preflight_observed_at",
    "preflight_expires_at",
    "plan_start_at",
    "effective_at",
    "due_at",
}


def profile_id(action_def: dict[str, Any]) -> str:
    return "keel.facts." + action_def["action"].replace(".", "_") + "_exact.v1"


def semantic_entry(action_def: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_id": action_def["semantic_id"],
        "semantic_kind": "exact_action",
        "trusted_source_kinds": ["action_verb_execute"],
        "match": {
            "action_names": [action_def["action"]],
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
        "fact_profile_id": profile_id(action_def),
    }


def presentation_profile(action_def: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_id": action_def["semantic_id"],
        "presentation_profile_id": (
            action_def["consequence_type"].removesuffix(".v1").replace(".", "_")
            + ".r1"
        ),
        "customer_title": action_def["customer_title"],
        "type_definition": action_def["type_definition"],
        "leading_fields": action_def["leading_fields"],
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
        "does_not_establish": action_def["does_not_establish"],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    }


def fact_field(path: str) -> dict[str, Any]:
    name = path.removeprefix("/")
    is_commitment = name.endswith("_commitment")
    is_digest = name.endswith("_digest") or name.endswith("_hash")
    value_type = (
        "commitment"
        if is_commitment
        else "digest"
        if is_digest
        else "integer"
        if name in INTEGER_FIELDS
        else "boolean"
        if name in BOOLEAN_FIELDS
        else "timestamp"
        if name in TIMESTAMP_FIELDS
        else "string"
    )
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": (
            "financial"
            if "amount" in name or name == "currency"
            else "personal_data"
            if is_commitment
            else "operational"
        ),
        "low_entropy_possible": not is_digest,
        "disclosure": {
            "verifier_safe": "commitment" if is_commitment else "cleartext",
            "authorized": (
                "commitment_with_optional_opening" if is_commitment else "cleartext"
            ),
            "private": (
                "commitment_with_optional_opening" if is_commitment else "cleartext"
            ),
        },
        "retention": {
            "class": "deletable_identity" if is_commitment else "permit_evidence",
            "max_days": None,
            "erasable": is_commitment,
            "erasure_action": "erase_opening" if is_commitment else "retain_signed_value",
        },
        "commitment_method": (
            "keel.salted_sha256_jcs.v1" if is_commitment else "signed_cleartext"
        ),
    }


def fact_profile(action_def: dict[str, Any], schema_digest: str) -> dict[str, Any]:
    paths = list(dict.fromkeys([*COMMON_PATHS, *action_def["specific_paths"]]))
    return {
        "fact_profile_id": profile_id(action_def),
        "semantic_ids": [action_def["semantic_id"]],
        "authorized_action": action_def["action"],
        "facts_schema": FACT_SCHEMA,
        "facts_schema_digest": f"sha256:{schema_digest}",
        "target_fact_paths": action_def["target_paths"],
        "material_request_fact_paths": [
            *action_def["material_paths"],
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "fields": [fact_field(path) for path in paths],
        "release_state": "eligible",
    }


def consequence(action_def: dict[str, Any]) -> dict[str, Any]:
    fields = list(
        dict.fromkeys(
            path.removeprefix("/")
            for path in [*action_def["target_paths"], *action_def["material_paths"]]
        )
    )
    return {
        "consequence_type": action_def["consequence_type"],
        "semantic_id": action_def["semantic_id"],
        "tool_names": [action_def["action"]],
        "customer_title": action_def["customer_title"],
        "type_definition": action_def["type_definition"],
        "required_material_fields": fields,
        "trusted_fact_requirements": action_def["trusted_facts"],
        "canonicalizer": action_def["canonicalizer"],
        "provider_mappings": [action_def["provider_mapping"]],
        "leading_fields": action_def["leading_fields"],
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
        "does_not_establish": action_def["does_not_establish"],
        "risk_tags": action_def["risk_tags"],
    }


def build_schema() -> dict[str, Any]:
    common: dict[str, Any] = {
        "version": {"const": "keel.collections_exact_facts.v1"},
        "fact_profile_id": {"type": "string"},
        "action": {"type": "string"},
        "operation": {"const": "call.tools"},
        "connector_identity": {"enum": ["payments", "notification.email"]},
        "connector_contract_hash": {"$ref": "#/$defs/rawDigest"},
        "tool_schema_hash": {"$ref": "#/$defs/rawDigest"},
        "decision_trace_hash": {"$ref": "#/$defs/rawDigest"},
        "tool_arguments_hash": {"$ref": "#/$defs/rawDigest"},
        "request_digest": dref(),
        "enforcement_mode": {"const": "enforced_in_path"},
        "provider_environment": {"const": "sandbox"},
        "provider_api_version": {"type": "string", "minLength": 1, "maxLength": 128},
        "preflight_observed_at": tref(),
        "preflight_expires_at": tref(),
        "preflight_snapshot_digest": dref(),
        "idempotency_digest": dref(),
        "max_uses": {"const": 1},
    }
    definitions: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    for action_def in ACTION_DEFS:
        name = action_def["action"].replace(".", "_")
        properties = copy.deepcopy(common)
        properties.update(
            {
                "fact_profile_id": {"const": profile_id(action_def)},
                "action": {"const": action_def["action"]},
                "connector_identity": {"const": action_def["connector_identity"]},
                **copy.deepcopy(action_def["properties"]),
            }
        )
        definitions[name] = {
            "type": "object",
            "additionalProperties": False,
            "required": list(properties),
            "properties": properties,
        }
        refs.append({"$ref": f"#/$defs/{name}"})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/keelapi/keel-permit/schemas/"
            "collections-exact-facts-v1.schema.json"
        ),
        "title": "Keel exact Collections Arrangement authorization facts v1",
        "oneOf": refs,
        "$defs": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "rawDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "pattern": (
                    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
                    "[0-9]{2}(?:\\.[0-9]{1,9})?Z$"
                ),
            },
            "saltedCommitment": {
                "type": "object",
                "additionalProperties": False,
                "required": ["method", "digest"],
                "properties": {
                    "method": {"const": "keel.salted_sha256_jcs.v1"},
                    "digest": dref(),
                },
            },
            **definitions,
        },
    }


def fact_vector(action_def: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "keel.collections_exact_facts.v1",
        "fact_profile_id": profile_id(action_def),
        "action": action_def["action"],
        "operation": "call.tools",
        "connector_identity": action_def["connector_identity"],
        "connector_contract_hash": "0" * 64,
        "tool_schema_hash": "1" * 64,
        "decision_trace_hash": "2" * 64,
        "tool_arguments_hash": "3" * 64,
        "request_digest": digest("4"),
        "enforcement_mode": "enforced_in_path",
        "provider_environment": "sandbox",
        "provider_api_version": (
            "2026-07-30.basil"
            if action_def["connector_identity"] == "payments"
            else "resend-v1"
        ),
        "preflight_observed_at": "2026-08-10T12:00:00Z",
        "preflight_expires_at": "2026-08-10T12:05:00Z",
        "preflight_snapshot_digest": digest("5"),
        "idempotency_digest": digest("6"),
        "max_uses": 1,
        **copy.deepcopy(action_def["sample"]),
    }


def main() -> None:
    write(FACT_SCHEMA, build_schema())

    consequence_v7 = copy.deepcopy(load("consequence_registry/v6.json"))
    consequence_v7["$schema"] = "./v7.schema.json"
    consequence_v7["version"] = "keel.consequence_registry.v7"
    consequence_v7["consequences"].extend(consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v7.json", consequence_v7)

    consequence_schema = copy.deepcopy(load("consequence_registry/v6.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v7.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v7"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v7"
    )
    write("consequence_registry/v7.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v10 = copy.deepcopy(load("fact_profiles/v9.json"))
    facts_v10["$schema"] = "./v10.schema.json"
    facts_v10["version"] = "keel.fact_profile_registry.v10"
    facts_v10["profiles"].extend(
        fact_profile(item, facts_digest) for item in ACTION_DEFS
    )
    write("fact_profiles/v10.json", facts_v10)

    facts_schema = copy.deepcopy(load("fact_profiles/v9.schema.json"))
    facts_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v10.schema.json"
    )
    facts_schema["title"] = "Keel Permit fact profile registry v10"
    facts_schema["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v10"
    )
    write("fact_profiles/v10.schema.json", facts_schema)

    semantics_v12 = copy.deepcopy(load("semantic_registry/v11.json"))
    semantics_v12["$schema"] = "./v12.schema.json"
    semantics_v12["version"] = "keel.semantic_selector_registry.v12"
    semantics_v12["entries"].extend(semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v12.json", semantics_v12)

    semantic_schema = copy.deepcopy(load("semantic_registry/v11.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v12.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v12"
    semantic_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v12"
    )
    write("semantic_registry/v12.schema.json", semantic_schema)

    presentation_v11 = copy.deepcopy(load("presentation_registry/v10.json"))
    presentation_v11["$schema"] = "./v11.schema.json"
    presentation_v11["version"] = "keel.presentation_registry.v11"
    presentation_v11["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v12"
    )
    presentation_v11["profiles"].extend(
        presentation_profile(item) for item in ACTION_DEFS
    )
    write("presentation_registry/v11.json", presentation_v11)

    presentation_schema = copy.deepcopy(load("presentation_registry/v10.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "presentation_registry/v11.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v11"
    presentation_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v11"
    )
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v12"
    )
    write("presentation_registry/v11.schema.json", presentation_schema)

    vectors_v8 = copy.deepcopy(load("consequence_registry/test-vectors/v7.json"))
    vectors_v8["version"] = "keel.consequence_registry.test_vectors.v8"
    vectors_v8["consequence_registry_version"] = consequence_v7["version"]
    vectors_v8["semantic_registry_version"] = semantics_v12["version"]
    vectors_v8["presentation_registry_version"] = presentation_v11["version"]
    for action_def in ACTION_DEFS:
        vectors_v8["vectors"].append(
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
    write("consequence_registry/test-vectors/v8.json", vectors_v8)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v7", "consequence_registry/v7.json"),
        (
            "keel.permit.consequence_registry.v7.schema",
            "consequence_registry/v7.schema.json",
        ),
        ("keel.permit.collections_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v10", "fact_profiles/v10.json"),
        (
            "keel.permit.fact_profile_registry.v10.schema",
            "fact_profiles/v10.schema.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v12",
            "semantic_registry/v12.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v12.schema",
            "semantic_registry/v12.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v11",
            "presentation_registry/v11.json",
        ),
        (
            "keel.permit.presentation_registry.v11.schema",
            "presentation_registry/v11.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v8",
            "consequence_registry/test-vectors/v8.json",
        ),
        (
            "keel.permit.collections_exact_action_contract.v1.spec",
            "spec/collections-exact-action-contract-v1.md",
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
