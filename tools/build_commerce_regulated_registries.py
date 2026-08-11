#!/usr/bin/env python3
"""Build exact-action artifacts for commerce and regulated workflows."""

from __future__ import annotations

import copy
from typing import Any

import build_procurement_ap_registries as base
from build_transactional_cx_registries import load, sha256, write


FACT_SCHEMA = "schemas/commerce-regulated-exact-facts-v1.schema.json"
FACT_VERSION = "keel.commerce_regulated_exact_facts.v1"


def currency() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[A-Z]{3}$"}


def enum(*values: str) -> dict[str, Any]:
    return {"enum": list(values)}


def integer(minimum: int = 0, maximum: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "integer", "minimum": minimum}
    if maximum is not None:
        result["maximum"] = maximum
    return result


def action(
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
    properties: dict[str, Any],
    sample: dict[str, Any],
    targets: list[str],
    trusted: list[str],
    leading: list[dict[str, str]],
    limits: list[str],
    risks: list[str],
) -> dict[str, Any]:
    paths = [f"/{field}" for field in properties]
    target_paths = [f"/{field}" for field in targets]
    return {
        "consequence_type": consequence_type,
        "semantic_id": semantic_id,
        "action": name,
        "connector_identity": connector,
        "environment": environment,
        "provider_api_version": api_version,
        "customer_title": title,
        "type_definition": definition,
        "provider_mapping": {"provider": provider, "operation": operation},
        "specific_paths": paths,
        "target_paths": target_paths,
        "material_paths": [path for path in paths if path not in target_paths],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_exact_provider_preflight",
            "gateway_argument_and_state_binding",
            "gateway_synthetic_record_constraint",
            "gateway_preflight_hmac",
            *trusted,
        ],
        "canonicalizer": f"keel.{name}.canonical.v1",
        "leading_fields": leading,
        "does_not_establish": limits,
        "risk_tags": risks,
        "properties": properties,
        "sample": sample,
    }


C = base.base.cref
D = base.base.dref
T = base.base.tref
SYNTHETIC = {"const": True}


ACTION_DEFS: list[dict[str, Any]] = [
    action(
        consequence_type="commerce.order.place.v1",
        semantic_id="keel.action.commerce_order_place.v1",
        name="commerce.order.place",
        connector="test-storefront",
        environment="self_hosted_synthetic",
        api_version="keel-test-storefront-v1",
        title="AI Permit-to-Place-Order",
        definition="Exact authorization to place one bounded synthetic order in one pinned test storefront",
        provider="keel-test-storefront",
        operation="orders.place",
        properties={
            "provider_instance_reference_commitment": C(),
            "record_is_synthetic": SYNTHETIC,
            "cart_reference_commitment": C(),
            "customer_reference_commitment": C(),
            "merchant_reference_commitment": C(),
            "line_item_set_commitment": C(),
            "line_item_count": integer(1, 25),
            "total_amount_minor": integer(1),
            "currency": currency(),
            "inventory_checked": {"const": True},
            "order_status_before": {"const": "absent"},
            "requested_order_status": {"const": "placed"},
            "payment_collected": {"const": False},
            "order_state_digest": D(),
        },
        sample={
            "provider_instance_reference_commitment": base.base.commitment("7"),
            "record_is_synthetic": True,
            "cart_reference_commitment": base.base.commitment("8"),
            "customer_reference_commitment": base.base.commitment("9"),
            "merchant_reference_commitment": base.base.commitment("a"),
            "line_item_set_commitment": base.base.commitment("b"),
            "line_item_count": 2,
            "total_amount_minor": 12900,
            "currency": "USD",
            "inventory_checked": True,
            "order_status_before": "absent",
            "requested_order_status": "placed",
            "payment_collected": False,
            "order_state_digest": base.base.digest("c"),
        },
        targets=["provider_instance_reference_commitment", "cart_reference_commitment", "customer_reference_commitment", "merchant_reference_commitment", "line_item_set_commitment"],
        trusted=["storefront_cart_and_inventory_preflight", "storefront_order_absence_preflight"],
        leading=[{"field": "resource", "label": "Synthetic order"}, {"field": "amount", "label": "Order total"}, {"field": "currency", "label": "Currency"}, {"field": "provider", "label": "Test storefront"}],
        limits=["merchant_payment_inventory_reservation_or_fulfillment", "a_real_purchase_or_commercial_obligation", "provider_state_after_the_immediate_readback"],
        risks=["commerce", "external_state_change", "order"],
    ),
    action(
        consequence_type="commerce.merchant.pay.v1",
        semantic_id="keel.action.commerce_merchant_pay.v1",
        name="commerce.merchant.pay",
        connector="stripe",
        environment="provider_sandbox",
        api_version="2026-07-30.basil",
        title="AI Permit-to-Pay-Merchant",
        definition="Exact authorization to create one Stripe test-mode merchant payment for one placed synthetic order",
        provider="stripe",
        operation="payment_intents.create_and_confirm",
        properties={
            "provider_instance_reference_commitment": C(),
            "record_is_synthetic": SYNTHETIC,
            "order_reference_commitment": C(),
            "merchant_destination_reference_commitment": C(),
            "payment_method_reference_commitment": C(),
            "total_amount_minor": integer(1),
            "currency": currency(),
            "order_status": {"const": "placed"},
            "inventory_reservation_status": {"const": "active"},
            "payment_status_before": {"const": "unpaid"},
            "stripe_livemode": {"const": False},
            "existing_payment_count": {"const": 0},
            "value_conservation_valid": {"const": True},
            "payment_state_digest": D(),
        },
        sample={
            "provider_instance_reference_commitment": base.base.commitment("7"),
            "record_is_synthetic": True,
            "order_reference_commitment": base.base.commitment("8"),
            "merchant_destination_reference_commitment": base.base.commitment("9"),
            "payment_method_reference_commitment": base.base.commitment("a"),
            "total_amount_minor": 12900,
            "currency": "USD",
            "order_status": "placed",
            "inventory_reservation_status": "active",
            "payment_status_before": "unpaid",
            "stripe_livemode": False,
            "existing_payment_count": 0,
            "value_conservation_valid": True,
            "payment_state_digest": base.base.digest("b"),
        },
        targets=["provider_instance_reference_commitment", "order_reference_commitment", "merchant_destination_reference_commitment", "payment_method_reference_commitment"],
        trusted=["stripe_test_mode_preflight", "storefront_order_and_reservation_preflight", "stripe_payment_absence_preflight"],
        leading=[{"field": "resource", "label": "Synthetic order"}, {"field": "amount", "label": "Merchant payment"}, {"field": "currency", "label": "Currency"}, {"field": "recipient", "label": "Test merchant"}],
        limits=["bank_settlement_merchant_receipt_or_payment_finality", "delivery_or_acceptance_of_goods", "a_real_purchase_or_commercial_obligation"],
        risks=["commerce", "payment", "value_movement"],
    ),
    action(
        consequence_type="commerce.inventory.reserve.v1",
        semantic_id="keel.action.commerce_inventory_reserve.v1",
        name="commerce.inventory.reserve",
        connector="inventory-postgres",
        environment="self_hosted_synthetic",
        api_version="keel-inventory-schema-v1",
        title="AI Permit-to-Reserve-Inventory",
        definition="Exact authorization to reserve one bounded synthetic inventory set for one order",
        provider="postgresql",
        operation="inventory.reserve",
        properties={
            "provider_instance_reference_commitment": C(),
            "record_is_synthetic": SYNTHETIC,
            "order_reference_commitment": C(),
            "warehouse_reference_commitment": C(),
            "inventory_item_set_commitment": C(),
            "line_item_count": integer(1, 25),
            "requested_unit_count": integer(1, 250),
            "available_unit_count": integer(1),
            "inventory_sufficient": {"const": True},
            "reservation_status_before": {"const": "absent"},
            "requested_reservation_status": {"const": "active"},
            "reservation_ttl_seconds": integer(60, 86400),
            "inventory_state_digest": D(),
        },
        sample={
            "provider_instance_reference_commitment": base.base.commitment("7"),
            "record_is_synthetic": True,
            "order_reference_commitment": base.base.commitment("8"),
            "warehouse_reference_commitment": base.base.commitment("9"),
            "inventory_item_set_commitment": base.base.commitment("a"),
            "line_item_count": 2,
            "requested_unit_count": 3,
            "available_unit_count": 50,
            "inventory_sufficient": True,
            "reservation_status_before": "absent",
            "requested_reservation_status": "active",
            "reservation_ttl_seconds": 900,
            "inventory_state_digest": base.base.digest("b"),
        },
        targets=["provider_instance_reference_commitment", "order_reference_commitment", "warehouse_reference_commitment", "inventory_item_set_commitment"],
        trusted=["inventory_provider_quantity_preflight", "inventory_reservation_absence_preflight"],
        leading=[{"field": "resource", "label": "Inventory reservation"}, {"field": "linked_to", "label": "Synthetic order"}, {"field": "provider", "label": "Inventory database"}, {"field": "request_digest", "label": "Bound request"}],
        limits=["order_placement_payment_or_fulfillment", "inventory_availability_after_the_bound_snapshot", "a_real_sale_or_inventory_commitment"],
        risks=["commerce", "database_write", "inventory"],
    ),
]


def benefit_case_action(*, decision: str, verb: str, title: str) -> dict[str, Any]:
    return action(
        consequence_type=f"benefits.case.{verb}.v1",
        semantic_id=f"keel.action.benefits_case_{verb}.v1",
        name=f"benefits.case.{verb}",
        connector="benefits-postgres",
        environment="self_hosted_synthetic",
        api_version="keel-benefits-schema-v1",
        title=title,
        definition=f"Exact authorization to {verb} one synthetic benefits case after a complete provider-observed review record",
        provider="postgresql",
        operation=f"benefits.case.{decision}",
        properties={
            "provider_instance_reference_commitment": C(),
            "record_is_synthetic": SYNTHETIC,
            "case_reference_commitment": C(),
            "applicant_reference_commitment": C(),
            "benefit_program_reference_commitment": C(),
            "current_determination_status": {"const": "pending"},
            "requested_determination_status": {"const": decision},
            "eligibility_evidence_complete": {"const": True},
            "decision_reason_code": {"type": "string", "minLength": 1, "maxLength": 128},
            "case_version_precondition_matches": {"const": True},
            "case_state_digest": D(),
        },
        sample={
            "provider_instance_reference_commitment": base.base.commitment("7"),
            "record_is_synthetic": True,
            "case_reference_commitment": base.base.commitment("8"),
            "applicant_reference_commitment": base.base.commitment("9"),
            "benefit_program_reference_commitment": base.base.commitment("a"),
            "current_determination_status": "pending",
            "requested_determination_status": decision,
            "eligibility_evidence_complete": True,
            "decision_reason_code": f"demo-{decision}-reason",
            "case_version_precondition_matches": True,
            "case_state_digest": base.base.digest("b"),
        },
        targets=["provider_instance_reference_commitment", "case_reference_commitment", "applicant_reference_commitment", "benefit_program_reference_commitment"],
        trusted=["benefits_case_state_preflight", "benefits_evidence_completeness_preflight"],
        leading=[{"field": "resource", "label": "Synthetic benefits case"}, {"field": "recipient", "label": "Synthetic applicant"}, {"field": "provider", "label": "Benefits case system"}, {"field": "request_digest", "label": "Bound decision"}],
        limits=["legal_correctness_due_process_or_final_appeal_rights", "identity_or_real_eligibility_of_any_person", "benefit_payment_or_delivery_of_a_determination_notice"],
        risks=["benefits", "regulated_decision", "eligibility"],
    )


ACTION_DEFS.extend(
    [
        benefit_case_action(decision="granted", verb="grant", title="AI Permit-to-Grant-Benefit"),
        benefit_case_action(decision="denied", verb="deny", title="AI Permit-to-Deny-Benefit"),
        action(
            consequence_type="benefits.eligibility.change.v1",
            semantic_id="keel.action.benefits_eligibility_change.v1",
            name="benefits.eligibility.change",
            connector="benefits-postgres",
            environment="self_hosted_synthetic",
            api_version="keel-benefits-schema-v1",
            title="AI Permit-to-Change-Benefit-Eligibility",
            definition="Exact authorization to change one synthetic applicant eligibility record with an exact effective date and reason",
            provider="postgresql",
            operation="benefits.eligibility.change",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "case_reference_commitment": C(), "applicant_reference_commitment": C(),
                "benefit_program_reference_commitment": C(),
                "current_eligibility_status": enum("eligible", "ineligible"),
                "requested_eligibility_status": enum("eligible", "ineligible"),
                "eligibility_change_reason_code": {"type": "string", "minLength": 1, "maxLength": 128},
                "effective_at": T(), "eligibility_evidence_complete": {"const": True},
                "case_version_precondition_matches": {"const": True}, "eligibility_state_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "case_reference_commitment": base.base.commitment("8"), "applicant_reference_commitment": base.base.commitment("9"),
                "benefit_program_reference_commitment": base.base.commitment("a"), "current_eligibility_status": "ineligible",
                "requested_eligibility_status": "eligible", "eligibility_change_reason_code": "demo-evidence-complete",
                "effective_at": "2026-08-15T00:00:00Z", "eligibility_evidence_complete": True,
                "case_version_precondition_matches": True, "eligibility_state_digest": base.base.digest("b"),
            },
            targets=["provider_instance_reference_commitment", "case_reference_commitment", "applicant_reference_commitment", "benefit_program_reference_commitment"],
            trusted=["benefits_eligibility_state_preflight", "benefits_evidence_completeness_preflight"],
            leading=[{"field": "resource", "label": "Eligibility record"}, {"field": "recipient", "label": "Synthetic applicant"}, {"field": "provider", "label": "Benefits case system"}, {"field": "request_digest", "label": "Bound change"}],
            limits=["legal_correctness_due_process_or_final_appeal_rights", "identity_or_real_eligibility_of_any_person", "a_benefit_determination_payment_or_notice"],
            risks=["benefits", "regulated_decision", "eligibility"],
        ),
        action(
            consequence_type="benefits.payment.issue.v1",
            semantic_id="keel.action.benefits_payment_issue.v1",
            name="benefits.payment.issue",
            connector="stripe",
            environment="provider_sandbox",
            api_version="2026-07-30.basil",
            title="AI Permit-to-Issue-Benefit-Payment",
            definition="Exact authorization to issue one Stripe test-mode payment for one granted synthetic benefits case",
            provider="stripe", operation="transfers.create",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "case_reference_commitment": C(), "recipient_reference_commitment": C(),
                "payment_destination_reference_commitment": C(), "amount_minor": integer(1), "currency": currency(),
                "determination_status": {"const": "granted"}, "eligibility_status": {"const": "eligible"},
                "stripe_livemode": {"const": False}, "existing_payment_count": {"const": 0},
                "value_conservation_valid": {"const": True}, "payment_state_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "case_reference_commitment": base.base.commitment("8"), "recipient_reference_commitment": base.base.commitment("9"),
                "payment_destination_reference_commitment": base.base.commitment("a"), "amount_minor": 85000, "currency": "USD",
                "determination_status": "granted", "eligibility_status": "eligible", "stripe_livemode": False,
                "existing_payment_count": 0, "value_conservation_valid": True, "payment_state_digest": base.base.digest("b"),
            },
            targets=["provider_instance_reference_commitment", "case_reference_commitment", "recipient_reference_commitment", "payment_destination_reference_commitment"],
            trusted=["benefits_grant_and_eligibility_preflight", "stripe_test_destination_preflight", "stripe_payment_absence_preflight"],
            leading=[{"field": "resource", "label": "Granted benefits case"}, {"field": "amount", "label": "Benefit payment"}, {"field": "currency", "label": "Currency"}, {"field": "recipient", "label": "Synthetic recipient"}],
            limits=["bank_settlement_recipient_receipt_or_payment_finality", "legal_entitlement_or_identity_of_a_real_person", "delivery_of_a_determination_notice"],
            risks=["benefits", "payment", "value_movement"],
        ),
        action(
            consequence_type="benefits.determination.notice.send.v1",
            semantic_id="keel.action.benefits_determination_notice_send.v1",
            name="benefits.determination.notice.send",
            connector="notification.email",
            environment="self_hosted_synthetic",
            api_version="mailpit-v1",
            title="AI Permit-to-Send-Benefit-Determination-Notice",
            definition="Exact authorization to send one templated determination notice to one dedicated synthetic recipient",
            provider="mailpit", operation="email.send",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "case_reference_commitment": C(), "recipient_reference_commitment": C(),
                "recipient_is_dedicated_demo": {"const": True}, "determination_status": enum("granted", "denied"),
                "channel": {"const": "email"}, "template_id": {"const": "benefits-determination-demo"},
                "template_version": {"const": "v1"}, "template_digest": D(),
                "rendered_subject_digest": D(), "rendered_content_digest": D(),
                "delivery_mode": {"const": "self_hosted_mail_sink"}, "prior_notice_count": {"const": 0},
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "case_reference_commitment": base.base.commitment("8"), "recipient_reference_commitment": base.base.commitment("9"),
                "recipient_is_dedicated_demo": True, "determination_status": "granted", "channel": "email",
                "template_id": "benefits-determination-demo", "template_version": "v1", "template_digest": base.base.digest("a"),
                "rendered_subject_digest": base.base.digest("b"), "rendered_content_digest": base.base.digest("c"),
                "delivery_mode": "self_hosted_mail_sink", "prior_notice_count": 0,
            },
            targets=["provider_instance_reference_commitment", "case_reference_commitment", "recipient_reference_commitment"],
            trusted=["benefits_determination_state_preflight", "gateway_pinned_demo_recipient", "gateway_template_digest"],
            leading=[{"field": "resource", "label": "Determination notice"}, {"field": "recipient", "label": "Dedicated demo recipient"}, {"field": "provider", "label": "Self-hosted mail sink"}, {"field": "request_digest", "label": "Bound notice"}],
            limits=["legal_sufficiency_service_or_proof_of_receipt", "identity_or_notice_to_a_real_person", "correctness_or_finality_of_the_benefit_determination"],
            risks=["benefits", "external_communication", "regulated_notice"],
        ),
    ]
)


def prior_auth_action(*, decision: str) -> dict[str, Any]:
    title = "AI Permit-to-Approve-Prior-Authorization" if decision == "approved" else "AI Permit-to-Deny-Prior-Authorization"
    verb = "approve" if decision == "approved" else "deny"
    return action(
        consequence_type=f"healthcare.prior_authorization.{verb}.v1",
        semantic_id=f"keel.action.healthcare_prior_authorization_{verb}.v1",
        name=f"healthcare.prior_authorization.{verb}", connector="hapi-fhir",
        environment="self_hosted_synthetic", api_version="FHIR-R4",
        title=title,
        definition=f"Exact authorization to {verb} one synthetic FHIR prior-authorization request after a complete review snapshot",
        provider="hapi-fhir", operation=f"ClaimResponse.{verb}",
        properties={
            "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
            "prior_authorization_reference_commitment": C(), "patient_reference_commitment": C(),
            "payer_reference_commitment": C(), "current_authorization_status": {"const": "active"},
            "requested_authorization_status": {"const": decision}, "clinical_review_complete": {"const": True},
            "decision_reason_code": {"type": "string", "minLength": 1, "maxLength": 128},
            "version_precondition_matches": {"const": True}, "authorization_state_digest": D(),
        },
        sample={
            "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
            "prior_authorization_reference_commitment": base.base.commitment("8"), "patient_reference_commitment": base.base.commitment("9"),
            "payer_reference_commitment": base.base.commitment("a"), "current_authorization_status": "active",
            "requested_authorization_status": decision, "clinical_review_complete": True,
            "decision_reason_code": f"demo-{decision}-criteria", "version_precondition_matches": True,
            "authorization_state_digest": base.base.digest("b"),
        },
        targets=["provider_instance_reference_commitment", "prior_authorization_reference_commitment", "patient_reference_commitment", "payer_reference_commitment"],
        trusted=["fhir_prior_authorization_state_preflight", "fhir_clinical_review_preflight"],
        leading=[{"field": "resource", "label": "Synthetic prior authorization"}, {"field": "recipient", "label": "Synthetic patient"}, {"field": "provider", "label": "Self-hosted FHIR"}, {"field": "request_digest", "label": "Bound decision"}],
        limits=["medical_necessity_legal_compliance_or_clinical_correctness", "identity_coverage_or_care_of_a_real_patient", "payment_claim_adjudication_or_provider_notification"],
        risks=["healthcare", "regulated_decision", "prior_authorization"],
    )


ACTION_DEFS.extend(
    [
        action(
            consequence_type="healthcare.prior_authorization.submit.v1", semantic_id="keel.action.healthcare_prior_authorization_submit.v1",
            name="healthcare.prior_authorization.submit", connector="hapi-fhir", environment="self_hosted_synthetic", api_version="FHIR-R4",
            title="AI Permit-to-Submit-Prior-Authorization",
            definition="Exact authorization to submit one complete synthetic FHIR prior-authorization request",
            provider="hapi-fhir", operation="Claim.create_prior_authorization",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "patient_reference_commitment": C(), "practitioner_reference_commitment": C(), "payer_reference_commitment": C(),
                "service_request_reference_commitment": C(), "coverage_reference_commitment": C(), "clinical_bundle_digest": D(),
                "required_fields_complete": {"const": True}, "authorization_status_before": {"const": "absent"},
                "requested_authorization_status": {"const": "active"}, "duplicate_authorization_count": {"const": 0},
                "coverage_active": {"const": True}, "clinical_state_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "patient_reference_commitment": base.base.commitment("8"), "practitioner_reference_commitment": base.base.commitment("9"),
                "payer_reference_commitment": base.base.commitment("a"), "service_request_reference_commitment": base.base.commitment("b"),
                "coverage_reference_commitment": base.base.commitment("c"), "clinical_bundle_digest": base.base.digest("d"),
                "required_fields_complete": True, "authorization_status_before": "absent", "requested_authorization_status": "active",
                "duplicate_authorization_count": 0, "coverage_active": True, "clinical_state_digest": base.base.digest("e"),
            },
            targets=["provider_instance_reference_commitment", "patient_reference_commitment", "practitioner_reference_commitment", "payer_reference_commitment", "service_request_reference_commitment", "coverage_reference_commitment"],
            trusted=["fhir_patient_practitioner_coverage_preflight", "fhir_duplicate_authorization_preflight", "fhir_clinical_bundle_preflight"],
            leading=[{"field": "resource", "label": "Prior-authorization request"}, {"field": "recipient", "label": "Synthetic patient"}, {"field": "provider", "label": "Self-hosted FHIR"}, {"field": "request_digest", "label": "Bound submission"}],
            limits=["payer_receipt_adjudication_or_coverage", "medical_necessity_or_clinical_correctness", "identity_coverage_or_care_of_a_real_patient"],
            risks=["healthcare", "external_submission", "prior_authorization"],
        ),
        action(
            consequence_type="healthcare.prior_authorization.clinical_information.request.v1",
            semantic_id="keel.action.healthcare_prior_authorization_clinical_information_request.v1",
            name="healthcare.prior_authorization.clinical_information.request", connector="hapi-fhir",
            environment="self_hosted_synthetic", api_version="FHIR-R4",
            title="AI Permit-to-Request-Clinical-Information",
            definition="Exact authorization to create one synthetic FHIR Task requesting a bounded clinical-information set",
            provider="hapi-fhir", operation="Task.create_information_request",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "prior_authorization_reference_commitment": C(), "patient_reference_commitment": C(),
                "practitioner_reference_commitment": C(), "requested_information_set_commitment": C(),
                "current_authorization_status": {"const": "active"}, "request_reason_code": {"type": "string", "minLength": 1, "maxLength": 128},
                "delivery_channel": {"const": "fhir_task"}, "existing_open_request_count": {"const": 0},
                "information_request_state_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "prior_authorization_reference_commitment": base.base.commitment("8"), "patient_reference_commitment": base.base.commitment("9"),
                "practitioner_reference_commitment": base.base.commitment("a"), "requested_information_set_commitment": base.base.commitment("b"),
                "current_authorization_status": "active", "request_reason_code": "demo-missing-imaging-report",
                "delivery_channel": "fhir_task", "existing_open_request_count": 0, "information_request_state_digest": base.base.digest("c"),
            },
            targets=["provider_instance_reference_commitment", "prior_authorization_reference_commitment", "patient_reference_commitment", "practitioner_reference_commitment", "requested_information_set_commitment"],
            trusted=["fhir_prior_authorization_state_preflight", "fhir_open_information_request_preflight"],
            leading=[{"field": "resource", "label": "Clinical-information request"}, {"field": "recipient", "label": "Synthetic practitioner"}, {"field": "provider", "label": "Self-hosted FHIR"}, {"field": "request_digest", "label": "Bound request"}],
            limits=["delivery_receipt_or_response_from_a_real_clinician", "medical_necessity_or_clinical_correctness", "identity_or_care_of_a_real_patient"],
            risks=["healthcare", "external_request", "clinical_information"],
        ),
        prior_auth_action(decision="approved"),
        prior_auth_action(decision="denied"),
        action(
            consequence_type="healthcare.appointment.schedule.v1", semantic_id="keel.action.healthcare_appointment_schedule.v1",
            name="healthcare.appointment.schedule", connector="hapi-fhir", environment="self_hosted_synthetic", api_version="FHIR-R4",
            title="AI Permit-to-Schedule-Appointment",
            definition="Exact authorization to book one available synthetic FHIR appointment slot",
            provider="hapi-fhir", operation="Appointment.create",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "patient_reference_commitment": C(), "practitioner_reference_commitment": C(), "location_reference_commitment": C(),
                "slot_reference_commitment": C(), "appointment_start_at": T(), "appointment_end_at": T(),
                "slot_status": {"const": "free"}, "requested_appointment_status": {"const": "booked"},
                "schedule_conflict_count": {"const": 0}, "appointment_state_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "patient_reference_commitment": base.base.commitment("8"), "practitioner_reference_commitment": base.base.commitment("9"),
                "location_reference_commitment": base.base.commitment("a"), "slot_reference_commitment": base.base.commitment("b"),
                "appointment_start_at": "2026-08-20T16:00:00Z", "appointment_end_at": "2026-08-20T16:30:00Z",
                "slot_status": "free", "requested_appointment_status": "booked", "schedule_conflict_count": 0,
                "appointment_state_digest": base.base.digest("c"),
            },
            targets=["provider_instance_reference_commitment", "patient_reference_commitment", "practitioner_reference_commitment", "location_reference_commitment", "slot_reference_commitment"],
            trusted=["fhir_slot_availability_preflight", "fhir_schedule_conflict_preflight"],
            leading=[{"field": "resource", "label": "Synthetic appointment"}, {"field": "recipient", "label": "Synthetic patient"}, {"field": "provider", "label": "Self-hosted FHIR"}, {"field": "request_digest", "label": "Bound booking"}],
            limits=["attendance_clinical_care_or_provider_acceptance", "identity_or_scheduling_of_a_real_patient", "availability_after_the_bound_snapshot"],
            risks=["healthcare", "scheduling", "external_state_change"],
        ),
        action(
            consequence_type="healthcare.claim.submit.v1", semantic_id="keel.action.healthcare_claim_submit.v1",
            name="healthcare.claim.submit", connector="hapi-fhir", environment="self_hosted_synthetic", api_version="FHIR-R4",
            title="AI Permit-to-Submit-Healthcare-Claim",
            definition="Exact authorization to submit one bounded synthetic FHIR claim with provider-observed coverage and coding checks",
            provider="hapi-fhir", operation="Claim.create",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "patient_reference_commitment": C(), "coverage_reference_commitment": C(), "service_reference_commitment": C(),
                "claim_bundle_digest": D(), "total_amount_minor": integer(1), "currency": currency(),
                "coverage_active": {"const": True}, "coding_validated": {"const": True},
                "claim_status_before": {"const": "absent"}, "requested_claim_status": {"const": "active"},
                "duplicate_claim_count": {"const": 0}, "claim_state_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "patient_reference_commitment": base.base.commitment("8"), "coverage_reference_commitment": base.base.commitment("9"),
                "service_reference_commitment": base.base.commitment("a"), "claim_bundle_digest": base.base.digest("b"),
                "total_amount_minor": 42000, "currency": "USD", "coverage_active": True, "coding_validated": True,
                "claim_status_before": "absent", "requested_claim_status": "active", "duplicate_claim_count": 0,
                "claim_state_digest": base.base.digest("c"),
            },
            targets=["provider_instance_reference_commitment", "patient_reference_commitment", "coverage_reference_commitment", "service_reference_commitment"],
            trusted=["fhir_coverage_and_service_preflight", "fhir_claim_coding_preflight", "fhir_duplicate_claim_preflight"],
            leading=[{"field": "resource", "label": "Synthetic healthcare claim"}, {"field": "amount", "label": "Claim total"}, {"field": "currency", "label": "Currency"}, {"field": "provider", "label": "Self-hosted FHIR"}],
            limits=["payer_receipt_adjudication_payment_or_reimbursement", "medical_coding_or_legal_correctness", "identity_coverage_or_care_of_a_real_patient"],
            risks=["healthcare", "claim", "external_submission"],
        ),
        action(
            consequence_type="healthcare.patient_administrative_record.update.v1",
            semantic_id="keel.action.healthcare_patient_administrative_record_update.v1",
            name="healthcare.patient_administrative_record.update", connector="hapi-fhir",
            environment="self_hosted_synthetic", api_version="FHIR-R4",
            title="AI Permit-to-Update-Patient-Administrative-Record",
            definition="Exact authorization to update one allowlisted administrative field set on one synthetic FHIR patient record",
            provider="hapi-fhir", operation="Patient.update_administrative_fields",
            properties={
                "provider_instance_reference_commitment": C(), "record_is_synthetic": SYNTHETIC,
                "patient_reference_commitment": C(), "administrative_field_set_commitment": C(),
                "record_version_before": integer(1), "requested_record_version": integer(2),
                "version_precondition_matches": {"const": True}, "administrative_fields_allowlisted": {"const": True},
                "clinical_field_mutation_requested": {"const": False}, "record_before_digest": D(), "record_after_digest": D(),
            },
            sample={
                "provider_instance_reference_commitment": base.base.commitment("7"), "record_is_synthetic": True,
                "patient_reference_commitment": base.base.commitment("8"), "administrative_field_set_commitment": base.base.commitment("9"),
                "record_version_before": 1, "requested_record_version": 2, "version_precondition_matches": True,
                "administrative_fields_allowlisted": True, "clinical_field_mutation_requested": False,
                "record_before_digest": base.base.digest("a"), "record_after_digest": base.base.digest("b"),
            },
            targets=["provider_instance_reference_commitment", "patient_reference_commitment", "administrative_field_set_commitment"],
            trusted=["fhir_patient_version_preflight", "gateway_administrative_field_allowlist", "gateway_clinical_field_exclusion"],
            leading=[{"field": "resource", "label": "Synthetic patient record"}, {"field": "provider", "label": "Self-hosted FHIR"}, {"field": "request_digest", "label": "Bound update"}, {"field": "linked_to", "label": "Administrative field set"}],
            limits=["clinical_record_change_diagnosis_treatment_or_care", "identity_or_record_of_a_real_patient", "correctness_of_contact_insurance_or_demographic_information"],
            risks=["healthcare", "administrative_record", "database_write"],
        ),
    ]
)


INTEGER_FIELDS = {
    "line_item_count", "total_amount_minor", "requested_unit_count", "available_unit_count",
    "reservation_ttl_seconds", "existing_payment_count", "amount_minor", "prior_notice_count",
    "duplicate_authorization_count", "existing_open_request_count", "schedule_conflict_count",
    "duplicate_claim_count", "record_version_before", "requested_record_version",
}
BOOLEAN_FIELDS = {
    "record_is_synthetic", "inventory_checked", "payment_collected", "stripe_livemode",
    "value_conservation_valid", "inventory_sufficient", "eligibility_evidence_complete",
    "case_version_precondition_matches", "recipient_is_dedicated_demo", "clinical_review_complete",
    "version_precondition_matches", "required_fields_complete", "coverage_active", "coding_validated",
    "administrative_fields_allowlisted", "clinical_field_mutation_requested",
}
TIMESTAMP_FIELDS = {"effective_at", "appointment_start_at", "appointment_end_at"}


def configure_base() -> None:
    base.FACT_SCHEMA = FACT_SCHEMA
    base.FACT_VERSION = FACT_VERSION
    base.ACTION_DEFS = ACTION_DEFS
    base.INTEGER_FIELDS.update(INTEGER_FIELDS)
    base.BOOLEAN_FIELDS.update(BOOLEAN_FIELDS)
    base.base.TIMESTAMP_FIELDS.update(TIMESTAMP_FIELDS)
    base.configure_base()


def profile_id(item: dict[str, Any]) -> str:
    configure_base()
    return base.profile_id(item)


def build_schema() -> dict[str, Any]:
    configure_base()
    schema = base.build_schema()
    schema["$id"] = "https://github.com/keelapi/keel-permit/schemas/commerce-regulated-exact-facts-v1.schema.json"
    schema["title"] = "Keel exact commerce and regulated-workflow facts v1"
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
    value["preflight_observed_at"] = "2026-08-11T04:00:00Z"
    value["preflight_expires_at"] = "2026-08-11T04:05:00Z"
    return value


def main() -> None:
    configure_base()
    write(FACT_SCHEMA, build_schema())

    consequence = copy.deepcopy(load("consequence_registry/v10.json"))
    consequence["$schema"] = "./v11.schema.json"
    consequence["version"] = "keel.consequence_registry.v11"
    consequence["consequences"].extend(base.base.consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v11.json", consequence)

    consequence_schema = copy.deepcopy(load("consequence_registry/v10.schema.json"))
    consequence_schema["$id"] = "https://github.com/keelapi/keel-permit/consequence_registry/v11.schema.json"
    consequence_schema["title"] = "Keel consequence registry v11"
    consequence_schema["properties"]["version"]["const"] = "keel.consequence_registry.v11"
    write("consequence_registry/v11.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts = copy.deepcopy(load("fact_profiles/v13.json"))
    facts["$schema"] = "./v14.schema.json"
    facts["version"] = "keel.fact_profile_registry.v14"
    facts["profiles"].extend(base.base.fact_profile(item, facts_digest) for item in ACTION_DEFS)
    write("fact_profiles/v14.json", facts)
    facts_schema = copy.deepcopy(load("fact_profiles/v13.schema.json"))
    facts_schema["$id"] = "https://github.com/keelapi/keel-permit/fact_profiles/v14.schema.json"
    facts_schema["title"] = "Keel Permit fact profile registry v14"
    facts_schema["properties"]["version"]["const"] = "keel.fact_profile_registry.v14"
    write("fact_profiles/v14.schema.json", facts_schema)

    semantics = copy.deepcopy(load("semantic_registry/v15.json"))
    semantics["$schema"] = "./v16.schema.json"
    semantics["version"] = "keel.semantic_selector_registry.v16"
    semantics["entries"].extend(base.base.semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v16.json", semantics)
    semantic_schema = copy.deepcopy(load("semantic_registry/v15.schema.json"))
    semantic_schema["$id"] = "https://github.com/keelapi/keel-permit/semantic_registry/v16.schema.json"
    semantic_schema["title"] = "Keel Permit semantic selector registry v16"
    semantic_schema["properties"]["version"]["const"] = "keel.semantic_selector_registry.v16"
    write("semantic_registry/v16.schema.json", semantic_schema)

    presentation = copy.deepcopy(load("presentation_registry/v14.json"))
    presentation["$schema"] = "./v15.schema.json"
    presentation["version"] = "keel.presentation_registry.v15"
    presentation["semantic_registry_version"] = "keel.semantic_selector_registry.v16"
    presentation["profiles"].extend(base.base.presentation_profile(item) for item in ACTION_DEFS)
    write("presentation_registry/v15.json", presentation)
    presentation_schema = copy.deepcopy(load("presentation_registry/v14.schema.json"))
    presentation_schema["$id"] = "https://github.com/keelapi/keel-permit/presentation_registry/v15.schema.json"
    presentation_schema["title"] = "Keel Permit presentation registry v15"
    presentation_schema["properties"]["version"]["const"] = "keel.presentation_registry.v15"
    presentation_schema["properties"]["semantic_registry_version"]["const"] = "keel.semantic_selector_registry.v16"
    write("presentation_registry/v15.schema.json", presentation_schema)

    vectors = copy.deepcopy(load("consequence_registry/test-vectors/v11.json"))
    vectors["version"] = "keel.consequence_registry.test_vectors.v12"
    vectors["consequence_registry_version"] = consequence["version"]
    vectors["semantic_registry_version"] = semantics["version"]
    vectors["presentation_registry_version"] = presentation["version"]
    for item in ACTION_DEFS:
        vectors["vectors"].append({
            "id": item["consequence_type"],
            "candidate": {
                "trusted_source_kind": "action_verb_execute", "permit_product": "permit",
                "action_name": item["action"], "operation": "call.tools", "chain_role": "action_child",
                "governed_surface": "mcp_tool", "evidence_capabilities": ["authorization", "dispatch", "provider_outcome"],
            },
            "expected_semantic_id": item["semantic_id"], "expected_title": item["customer_title"],
            "expected_fact_profile_id": profile_id(item), "valid_authorization_facts": fact_vector(item),
        })
    write("consequence_registry/test-vectors/v12.json", vectors)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v11", "consequence_registry/v11.json"),
        ("keel.permit.consequence_registry.v11.schema", "consequence_registry/v11.schema.json"),
        ("keel.permit.commerce_regulated_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v14", "fact_profiles/v14.json"),
        ("keel.permit.fact_profile_registry.v14.schema", "fact_profiles/v14.schema.json"),
        ("keel.permit.semantic_selector_registry.v16", "semantic_registry/v16.json"),
        ("keel.permit.semantic_selector_registry.v16.schema", "semantic_registry/v16.schema.json"),
        ("keel.permit.presentation_registry.v15", "presentation_registry/v15.json"),
        ("keel.permit.presentation_registry.v15.schema", "presentation_registry/v15.schema.json"),
        ("permit-to-x.test-vectors.consequence-registry.v12", "consequence_registry/test-vectors/v12.json"),
        ("keel.permit.commerce_regulated_exact_action_contract.v1.spec", "spec/commerce-regulated-exact-action-contract-v1.md"),
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
