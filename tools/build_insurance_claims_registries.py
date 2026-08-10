#!/usr/bin/env python3
"""Build additive exact-action artifacts for Insurance Claims."""

from __future__ import annotations

import copy
from typing import Any

import build_collections_registries as base
from build_transactional_cx_registries import load, sha256, write


FACT_SCHEMA = "schemas/insurance-claims-exact-facts-v1.schema.json"
FACT_VERSION = "keel.insurance_claims_exact_facts.v1"


ACTION_DEFS: list[dict[str, Any]] = [
    {
        "consequence_type": "insurance.claim.decision.record.v1",
        "semantic_id": "keel.action.insurance_claim_decision_record.v1",
        "action": "insurance.claim.decision.record",
        "connector_identity": "claims.system",
        "customer_title": "AI Permit-to-Decide-Claim",
        "type_definition": (
            "Exact authorization to append one human-co-signed approve-or-deny "
            "determination to one synthetic insurance claim"
        ),
        "provider_mapping": {
            "provider": "keel-synthetic-claims",
            "operation": "claim_decisions.append",
        },
        "specific_paths": [
            "/claim_reference_commitment",
            "/policy_reference_commitment",
            "/claimant_reference_commitment",
            "/claim_status_before",
            "/requested_outcome",
            "/decision_reason_code",
            "/coverage_evaluation_digest",
            "/evidence_bundle_digest",
            "/criteria_pack_id",
            "/criteria_pack_version",
            "/criteria_pack_digest",
            "/decision_record_count_before",
            "/human_review_required",
            "/required_approver_role",
            "/separation_of_duties_required",
            "/co_signature_requirement_digest",
            "/appeal_path_included",
            "/jurisdiction",
        ],
        "target_paths": [
            "/claim_reference_commitment",
            "/policy_reference_commitment",
            "/claimant_reference_commitment",
        ],
        "material_paths": [
            "/claim_status_before",
            "/requested_outcome",
            "/decision_reason_code",
            "/coverage_evaluation_digest",
            "/evidence_bundle_digest",
            "/criteria_pack_id",
            "/criteria_pack_version",
            "/criteria_pack_digest",
            "/decision_record_count_before",
            "/human_review_required",
            "/required_approver_role",
            "/separation_of_duties_required",
            "/co_signature_requirement_digest",
            "/appeal_path_included",
            "/jurisdiction",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_claim_policy_allowlist",
            "claims_system_current_state_preflight",
            "gateway_criteria_pack_allowlist",
            "keel_signed_co_signature_requirement",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.insurance.claim.decision.record.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Insurance claim"},
            {"field": "linked_to", "label": "Determination and reason"},
            {"field": "recipient", "label": "Human adjuster approver"},
            {"field": "provider", "label": "Claims system"},
        ],
        "does_not_establish": [
            "human_approval_without_separately_verified_co_signature_evidence",
            "legal_correctness_or_regulatory_compliance_of_the_determination",
            "real_claimant_identity_adjuster_licensure_or_real_policy_coverage",
        ],
        "risk_tags": [
            "regulated_decision",
            "insurance_claim",
            "human_co_signature",
        ],
        "properties": {
            "claim_reference_commitment": base.cref(),
            "policy_reference_commitment": base.cref(),
            "claimant_reference_commitment": base.cref(),
            "claim_status_before": {"const": "under_review"},
            "requested_outcome": {"enum": ["approved", "denied"]},
            "decision_reason_code": {
                "enum": [
                    "covered_loss_verified",
                    "partial_coverage_verified",
                    "coverage_exclusion_applies",
                    "insufficient_documentation",
                ]
            },
            "coverage_evaluation_digest": base.dref(),
            "evidence_bundle_digest": base.dref(),
            "criteria_pack_id": {"const": "demo-auto-claims"},
            "criteria_pack_version": {"const": "v1"},
            "criteria_pack_digest": base.dref(),
            "decision_record_count_before": {"const": 0},
            "human_review_required": {"const": True},
            "required_approver_role": {"const": "licensed_claims_adjuster"},
            "separation_of_duties_required": {"const": True},
            "co_signature_requirement_digest": base.dref(),
            "appeal_path_included": {"const": True},
            "jurisdiction": {"const": "DEMO-NOT-A-REAL-JURISDICTION"},
        },
        "sample": {
            "claim_reference_commitment": base.commitment("7"),
            "policy_reference_commitment": base.commitment("8"),
            "claimant_reference_commitment": base.commitment("9"),
            "claim_status_before": "under_review",
            "requested_outcome": "approved",
            "decision_reason_code": "covered_loss_verified",
            "coverage_evaluation_digest": base.digest("a"),
            "evidence_bundle_digest": base.digest("b"),
            "criteria_pack_id": "demo-auto-claims",
            "criteria_pack_version": "v1",
            "criteria_pack_digest": base.digest("c"),
            "decision_record_count_before": 0,
            "human_review_required": True,
            "required_approver_role": "licensed_claims_adjuster",
            "separation_of_duties_required": True,
            "co_signature_requirement_digest": base.digest("d"),
            "appeal_path_included": True,
            "jurisdiction": "DEMO-NOT-A-REAL-JURISDICTION",
        },
    },
    {
        "consequence_type": "insurance.claim.settlement.set.v1",
        "semantic_id": "keel.action.insurance_claim_settlement_set.v1",
        "action": "insurance.claim.settlement.set",
        "connector_identity": "claims.system",
        "customer_title": "AI Permit-to-Settle-Claim",
        "type_definition": (
            "Exact authorization to create one bounded settlement record for "
            "one approved synthetic insurance claim"
        ),
        "provider_mapping": {
            "provider": "keel-synthetic-claims",
            "operation": "claim_settlements.create",
        },
        "specific_paths": [
            "/claim_reference_commitment",
            "/decision_reference_commitment",
            "/policy_reference_commitment",
            "/claim_status_before",
            "/decision_outcome",
            "/decision_record_digest",
            "/settlement_record_count_before",
            "/claimed_amount_minor",
            "/covered_amount_minor",
            "/policy_limit_minor",
            "/settlement_amount_minor",
            "/currency",
            "/amount_within_covered_amount",
            "/amount_within_policy_limit",
            "/terms_template_id",
            "/terms_template_version",
            "/terms_template_digest",
            "/co_signature_requirement_digest",
        ],
        "target_paths": [
            "/claim_reference_commitment",
            "/decision_reference_commitment",
            "/policy_reference_commitment",
        ],
        "material_paths": [
            "/claim_status_before",
            "/decision_outcome",
            "/decision_record_digest",
            "/settlement_record_count_before",
            "/claimed_amount_minor",
            "/covered_amount_minor",
            "/policy_limit_minor",
            "/settlement_amount_minor",
            "/currency",
            "/amount_within_covered_amount",
            "/amount_within_policy_limit",
            "/terms_template_id",
            "/terms_template_version",
            "/terms_template_digest",
            "/co_signature_requirement_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_claim_policy_allowlist",
            "claims_system_approved_decision_preflight",
            "claims_system_settlement_absence_preflight",
            "gateway_terms_template_allowlist",
            "keel_signed_co_signature_requirement",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.insurance.claim.settlement.set.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Approved insurance claim"},
            {"field": "amount", "label": "Settlement amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "recipient", "label": "Human adjuster approver"},
        ],
        "does_not_establish": [
            "claim_payment_dispatch_or_financial_settlement",
            "claimant_acceptance_or_release_of_claim",
            "legal_sufficiency_of_the_settlement_terms",
        ],
        "risk_tags": ["financial_record", "insurance_claim", "settlement"],
        "properties": {
            "claim_reference_commitment": base.cref(),
            "decision_reference_commitment": base.cref(),
            "policy_reference_commitment": base.cref(),
            "claim_status_before": {"const": "approved"},
            "decision_outcome": {"const": "approved"},
            "decision_record_digest": base.dref(),
            "settlement_record_count_before": {"const": 0},
            "claimed_amount_minor": {"type": "integer", "minimum": 1},
            "covered_amount_minor": {"type": "integer", "minimum": 1},
            "policy_limit_minor": {"type": "integer", "minimum": 1},
            "settlement_amount_minor": {"type": "integer", "minimum": 1},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "amount_within_covered_amount": {"const": True},
            "amount_within_policy_limit": {"const": True},
            "terms_template_id": {"const": "demo-claim-settlement"},
            "terms_template_version": {"const": "v1"},
            "terms_template_digest": base.dref(),
            "co_signature_requirement_digest": base.dref(),
        },
        "sample": {
            "claim_reference_commitment": base.commitment("7"),
            "decision_reference_commitment": base.commitment("8"),
            "policy_reference_commitment": base.commitment("9"),
            "claim_status_before": "approved",
            "decision_outcome": "approved",
            "decision_record_digest": base.digest("a"),
            "settlement_record_count_before": 0,
            "claimed_amount_minor": 180000,
            "covered_amount_minor": 150000,
            "policy_limit_minor": 250000,
            "settlement_amount_minor": 150000,
            "currency": "USD",
            "amount_within_covered_amount": True,
            "amount_within_policy_limit": True,
            "terms_template_id": "demo-claim-settlement",
            "terms_template_version": "v1",
            "terms_template_digest": base.digest("b"),
            "co_signature_requirement_digest": base.digest("c"),
        },
    },
    {
        "consequence_type": "insurance.claim.payment.send.v1",
        "semantic_id": "keel.action.insurance_claim_payment_send.v1",
        "action": "insurance.claim.payment.send",
        "connector_identity": "payments",
        "customer_title": "AI Permit-to-Pay-Claim",
        "type_definition": (
            "Exact authorization to create one Stripe test-mode Connect transfer "
            "for the unpaid amount of one approved synthetic claim settlement"
        ),
        "provider_mapping": {"provider": "stripe", "operation": "transfers.create"},
        "specific_paths": [
            "/claim_reference_commitment",
            "/settlement_reference_commitment",
            "/claimant_reference_commitment",
            "/destination_account_reference_commitment",
            "/claim_status_before",
            "/settlement_status_before",
            "/settlement_record_digest",
            "/settlement_amount_minor",
            "/paid_amount_minor_before",
            "/remaining_payable_minor",
            "/payment_amount_minor",
            "/currency",
            "/amount_matches_remaining_payable",
            "/destination_allowlisted",
            "/transfer_status_before",
            "/transfer_group",
        ],
        "target_paths": [
            "/claim_reference_commitment",
            "/settlement_reference_commitment",
            "/claimant_reference_commitment",
            "/destination_account_reference_commitment",
        ],
        "material_paths": [
            "/claim_status_before",
            "/settlement_status_before",
            "/settlement_record_digest",
            "/settlement_amount_minor",
            "/paid_amount_minor_before",
            "/remaining_payable_minor",
            "/payment_amount_minor",
            "/currency",
            "/amount_matches_remaining_payable",
            "/destination_allowlisted",
            "/transfer_status_before",
            "/transfer_group",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_claim_and_destination_allowlist",
            "claims_system_approved_settlement_preflight",
            "claims_system_remaining_payable_preflight",
            "provider_destination_preflight",
            "provider_transfer_absence_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.insurance.claim.payment.send.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Claim settlement"},
            {"field": "amount", "label": "Claim payment"},
            {"field": "currency", "label": "Currency"},
            {"field": "recipient", "label": "Demo claimant destination"},
        ],
        "does_not_establish": [
            "stripe_acceptance_or_transfer_creation_without_provider_readback",
            "bank_settlement_recipient_receipt_or_payment_finality",
            "validity_of_a_real_claim_or_entitlement_to_real_funds",
        ],
        "risk_tags": ["value_movement", "insurance_claim", "claim_payment"],
        "properties": {
            "claim_reference_commitment": base.cref(),
            "settlement_reference_commitment": base.cref(),
            "claimant_reference_commitment": base.cref(),
            "destination_account_reference_commitment": base.cref(),
            "claim_status_before": {"const": "settled"},
            "settlement_status_before": {"const": "approved_for_payment"},
            "settlement_record_digest": base.dref(),
            "settlement_amount_minor": {"type": "integer", "minimum": 1},
            "paid_amount_minor_before": {"type": "integer", "minimum": 0},
            "remaining_payable_minor": {"type": "integer", "minimum": 1},
            "payment_amount_minor": {"type": "integer", "minimum": 1},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "amount_matches_remaining_payable": {"const": True},
            "destination_allowlisted": {"const": True},
            "transfer_status_before": {"const": "absent"},
            "transfer_group": {"type": "string", "pattern": "^claim_[a-z0-9_]{1,64}$"},
        },
        "sample": {
            "claim_reference_commitment": base.commitment("7"),
            "settlement_reference_commitment": base.commitment("8"),
            "claimant_reference_commitment": base.commitment("9"),
            "destination_account_reference_commitment": base.commitment("a"),
            "claim_status_before": "settled",
            "settlement_status_before": "approved_for_payment",
            "settlement_record_digest": base.digest("b"),
            "settlement_amount_minor": 150000,
            "paid_amount_minor_before": 0,
            "remaining_payable_minor": 150000,
            "payment_amount_minor": 150000,
            "currency": "USD",
            "amount_matches_remaining_payable": True,
            "destination_allowlisted": True,
            "transfer_status_before": "absent",
            "transfer_group": "claim_demo_1001",
        },
    },
    {
        "consequence_type": "insurance.claim.notice.send.v1",
        "semantic_id": "keel.action.insurance_claim_notice_send.v1",
        "action": "insurance.claim.notice.send",
        "connector_identity": "notification.email",
        "customer_title": "AI Permit-to-Send-Claim-Determination-Notice",
        "type_definition": (
            "Exact authorization to send one operator-approved claim "
            "determination notice to one dedicated demo recipient"
        ),
        "provider_mapping": {"provider": "resend", "operation": "emails.send"},
        "specific_paths": [
            "/claim_reference_commitment",
            "/decision_reference_commitment",
            "/recipient_reference_commitment",
            "/recipient_is_dedicated_demo",
            "/recorded_decision_outcome",
            "/decision_record_digest",
            "/channel",
            "/template_id",
            "/template_version",
            "/template_digest",
            "/rendered_subject_digest",
            "/rendered_content_digest",
            "/settlement_amount_minor",
            "/currency",
            "/appeal_instructions_included",
            "/jurisdiction",
            "/notice_record_count_before",
            "/delivery_mode",
        ],
        "target_paths": [
            "/claim_reference_commitment",
            "/decision_reference_commitment",
            "/recipient_reference_commitment",
            "/template_id",
        ],
        "material_paths": [
            "/recipient_is_dedicated_demo",
            "/recorded_decision_outcome",
            "/decision_record_digest",
            "/channel",
            "/template_version",
            "/template_digest",
            "/rendered_subject_digest",
            "/rendered_content_digest",
            "/settlement_amount_minor",
            "/currency",
            "/appeal_instructions_included",
            "/jurisdiction",
            "/notice_record_count_before",
            "/delivery_mode",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_recipient_allowlist",
            "gateway_template_allowlist",
            "claims_system_recorded_decision_preflight",
            "gateway_rendered_message_derivation",
            "provider_sender_identity_configuration",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.insurance.claim.notice.send.canonical.v1",
        "leading_fields": [
            {"field": "recipient", "label": "Dedicated demo recipient"},
            {"field": "resource", "label": "Insurance claim"},
            {"field": "linked_to", "label": "Determination and template"},
            {"field": "provider", "label": "Notification provider"},
        ],
        "does_not_establish": [
            "email_delivery_receipt_or_recipient_read_confirmation",
            "legal_sufficiency_or_regulatory_compliance_of_the_notice",
            "identity_of_a_real_claimant_or_validity_of_a_real_claim",
        ],
        "risk_tags": [
            "external_communication",
            "insurance_claim",
            "regulated_notice",
        ],
        "properties": {
            "claim_reference_commitment": base.cref(),
            "decision_reference_commitment": base.cref(),
            "recipient_reference_commitment": base.cref(),
            "recipient_is_dedicated_demo": {"const": True},
            "recorded_decision_outcome": {"enum": ["approved", "denied"]},
            "decision_record_digest": base.dref(),
            "channel": {"const": "email"},
            "template_id": {
                "enum": ["claim-approval-notice", "claim-denial-notice"]
            },
            "template_version": {"const": "v1"},
            "template_digest": base.dref(),
            "rendered_subject_digest": base.dref(),
            "rendered_content_digest": base.dref(),
            "settlement_amount_minor": {"type": "integer", "minimum": 0},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "appeal_instructions_included": {"const": True},
            "jurisdiction": {"const": "DEMO-NOT-A-REAL-JURISDICTION"},
            "notice_record_count_before": {"const": 0},
            "delivery_mode": {"const": "provider_email"},
        },
        "sample": {
            "claim_reference_commitment": base.commitment("7"),
            "decision_reference_commitment": base.commitment("8"),
            "recipient_reference_commitment": base.commitment("9"),
            "recipient_is_dedicated_demo": True,
            "recorded_decision_outcome": "approved",
            "decision_record_digest": base.digest("a"),
            "channel": "email",
            "template_id": "claim-approval-notice",
            "template_version": "v1",
            "template_digest": base.digest("b"),
            "rendered_subject_digest": base.digest("c"),
            "rendered_content_digest": base.digest("d"),
            "settlement_amount_minor": 150000,
            "currency": "USD",
            "appeal_instructions_included": True,
            "jurisdiction": "DEMO-NOT-A-REAL-JURISDICTION",
            "notice_record_count_before": 0,
            "delivery_mode": "provider_email",
        },
    },
]


INTEGER_FIELDS = {
    "decision_record_count_before",
    "settlement_record_count_before",
    "claimed_amount_minor",
    "covered_amount_minor",
    "policy_limit_minor",
    "settlement_amount_minor",
    "paid_amount_minor_before",
    "remaining_payable_minor",
    "payment_amount_minor",
    "notice_record_count_before",
}
BOOLEAN_FIELDS = {
    "human_review_required",
    "separation_of_duties_required",
    "appeal_path_included",
    "amount_within_covered_amount",
    "amount_within_policy_limit",
    "amount_matches_remaining_payable",
    "destination_allowlisted",
    "recipient_is_dedicated_demo",
    "appeal_instructions_included",
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
        "insurance-claims-exact-facts-v1.schema.json"
    )
    schema["title"] = "Keel exact Insurance Claims authorization facts v1"
    for action_def in ACTION_DEFS:
        definition = schema["$defs"][action_def["action"].replace(".", "_")]
        definition["properties"]["version"] = {"const": FACT_VERSION}
    return schema


def fact_vector(action_def: dict[str, Any]) -> dict[str, Any]:
    configure_base()
    value = base.fact_vector(action_def)
    value["version"] = FACT_VERSION
    value["provider_api_version"] = {
        "claims.system": "keel-synthetic-claims-v1",
        "payments": "2026-07-30.basil",
        "notification.email": "resend-v1",
    }[action_def["connector_identity"]]
    return value


def main() -> None:
    configure_base()
    write(FACT_SCHEMA, build_schema())

    consequence_v8 = copy.deepcopy(load("consequence_registry/v7.json"))
    consequence_v8["$schema"] = "./v8.schema.json"
    consequence_v8["version"] = "keel.consequence_registry.v8"
    consequence_v8["consequences"].extend(base.consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v8.json", consequence_v8)

    consequence_schema = copy.deepcopy(load("consequence_registry/v7.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v8.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v8"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v8"
    )
    write("consequence_registry/v8.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v11 = copy.deepcopy(load("fact_profiles/v10.json"))
    facts_v11["$schema"] = "./v11.schema.json"
    facts_v11["version"] = "keel.fact_profile_registry.v11"
    facts_v11["profiles"].extend(
        base.fact_profile(item, facts_digest) for item in ACTION_DEFS
    )
    write("fact_profiles/v11.json", facts_v11)

    facts_schema = copy.deepcopy(load("fact_profiles/v10.schema.json"))
    facts_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v11.schema.json"
    )
    facts_schema["title"] = "Keel Permit fact profile registry v11"
    facts_schema["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v11"
    )
    write("fact_profiles/v11.schema.json", facts_schema)

    semantics_v13 = copy.deepcopy(load("semantic_registry/v12.json"))
    semantics_v13["$schema"] = "./v13.schema.json"
    semantics_v13["version"] = "keel.semantic_selector_registry.v13"
    semantics_v13["entries"].extend(base.semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v13.json", semantics_v13)

    semantic_schema = copy.deepcopy(load("semantic_registry/v12.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v13.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v13"
    semantic_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v13"
    )
    write("semantic_registry/v13.schema.json", semantic_schema)

    presentation_v12 = copy.deepcopy(load("presentation_registry/v11.json"))
    presentation_v12["$schema"] = "./v12.schema.json"
    presentation_v12["version"] = "keel.presentation_registry.v12"
    presentation_v12["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v13"
    )
    presentation_v12["profiles"].extend(
        base.presentation_profile(item) for item in ACTION_DEFS
    )
    write("presentation_registry/v12.json", presentation_v12)

    presentation_schema = copy.deepcopy(load("presentation_registry/v11.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "presentation_registry/v12.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v12"
    presentation_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v12"
    )
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v13"
    )
    write("presentation_registry/v12.schema.json", presentation_schema)

    vectors_v9 = copy.deepcopy(load("consequence_registry/test-vectors/v8.json"))
    vectors_v9["version"] = "keel.consequence_registry.test_vectors.v9"
    vectors_v9["consequence_registry_version"] = consequence_v8["version"]
    vectors_v9["semantic_registry_version"] = semantics_v13["version"]
    vectors_v9["presentation_registry_version"] = presentation_v12["version"]
    for action_def in ACTION_DEFS:
        vectors_v9["vectors"].append(
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
    write("consequence_registry/test-vectors/v9.json", vectors_v9)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v8", "consequence_registry/v8.json"),
        (
            "keel.permit.consequence_registry.v8.schema",
            "consequence_registry/v8.schema.json",
        ),
        ("keel.permit.insurance_claims_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v11", "fact_profiles/v11.json"),
        (
            "keel.permit.fact_profile_registry.v11.schema",
            "fact_profiles/v11.schema.json",
        ),
        ("keel.permit.semantic_selector_registry.v13", "semantic_registry/v13.json"),
        (
            "keel.permit.semantic_selector_registry.v13.schema",
            "semantic_registry/v13.schema.json",
        ),
        ("keel.permit.presentation_registry.v12", "presentation_registry/v12.json"),
        (
            "keel.permit.presentation_registry.v12.schema",
            "presentation_registry/v12.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v9",
            "consequence_registry/test-vectors/v9.json",
        ),
        (
            "keel.permit.insurance_claims_exact_action_contract.v1.spec",
            "spec/insurance-claims-exact-action-contract-v1.md",
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
