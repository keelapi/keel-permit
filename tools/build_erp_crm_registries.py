#!/usr/bin/env python3
"""Build additive exact-action artifacts for ERP/CRM Operations."""

from __future__ import annotations

import copy
from typing import Any

import build_collections_registries as base
from build_transactional_cx_registries import load, sha256, write


FACT_SCHEMA = "schemas/erp-crm-exact-facts-v1.schema.json"
FACT_VERSION = "keel.erp_crm_exact_facts.v1"


def short_string() -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": 256}


def provider_id() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[A-Za-z0-9_:-]{1,128}$"}


ACTION_DEFS: list[dict[str, Any]] = [
    {
        "consequence_type": "crm.deal.stage.change.v1",
        "semantic_id": "keel.action.crm_deal_stage_change.v1",
        "action": "crm.deal.stage.change",
        "connector_identity": "hubspot",
        "customer_title": "AI Permit-to-Change-Deal-Stage",
        "type_definition": (
            "Exact authorization to move one synthetic HubSpot developer-test "
            "deal from one provider-observed stage to one allowlisted stage"
        ),
        "provider_mapping": {
            "provider": "hubspot",
            "operation": "crm.deals.update_stage",
        },
        "specific_paths": [
            "/provider_portal_reference_commitment",
            "/provider_account_type",
            "/record_is_synthetic",
            "/deal_reference_commitment",
            "/pipeline_reference_commitment",
            "/current_stage_id",
            "/current_stage_label",
            "/requested_stage_id",
            "/requested_stage_label",
            "/transition_allowlisted",
            "/deal_updated_at_before",
            "/pipeline_configuration_digest",
            "/deal_state_digest",
        ],
        "target_paths": [
            "/provider_portal_reference_commitment",
            "/deal_reference_commitment",
            "/pipeline_reference_commitment",
        ],
        "material_paths": [
            "/provider_account_type",
            "/record_is_synthetic",
            "/current_stage_id",
            "/current_stage_label",
            "/requested_stage_id",
            "/requested_stage_label",
            "/transition_allowlisted",
            "/deal_updated_at_before",
            "/pipeline_configuration_digest",
            "/deal_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_developer_test_portal",
            "provider_account_information_preflight",
            "provider_deal_and_pipeline_preflight",
            "gateway_stage_transition_allowlist",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.crm.deal.stage.change.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Synthetic deal"},
            {"field": "linked_to", "label": "Stage transition"},
            {"field": "provider", "label": "CRM provider"},
            {"field": "request_digest", "label": "Bound request"},
        ],
        "does_not_establish": [
            "commercial_validity_or_accuracy_of_the_deal",
            "correctness_under_the_operators_sales_process",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["external_state_change", "crm", "deal_stage"],
        "properties": {
            "provider_portal_reference_commitment": base.cref(),
            "provider_account_type": {"const": "DEVELOPER_TEST"},
            "record_is_synthetic": {"const": True},
            "deal_reference_commitment": base.cref(),
            "pipeline_reference_commitment": base.cref(),
            "current_stage_id": provider_id(),
            "current_stage_label": short_string(),
            "requested_stage_id": provider_id(),
            "requested_stage_label": short_string(),
            "transition_allowlisted": {"const": True},
            "deal_updated_at_before": base.tref(),
            "pipeline_configuration_digest": base.dref(),
            "deal_state_digest": base.dref(),
        },
        "sample": {
            "provider_portal_reference_commitment": base.commitment("7"),
            "provider_account_type": "DEVELOPER_TEST",
            "record_is_synthetic": True,
            "deal_reference_commitment": base.commitment("8"),
            "pipeline_reference_commitment": base.commitment("9"),
            "current_stage_id": "qualifiedtobuy",
            "current_stage_label": "Qualified to buy",
            "requested_stage_id": "presentationscheduled",
            "requested_stage_label": "Presentation scheduled",
            "transition_allowlisted": True,
            "deal_updated_at_before": "2026-08-11T01:00:00Z",
            "pipeline_configuration_digest": base.digest("a"),
            "deal_state_digest": base.digest("b"),
        },
    },
    {
        "consequence_type": "crm.customer.record.update.v1",
        "semantic_id": "keel.action.crm_customer_record_update.v1",
        "action": "crm.customer.record.update",
        "connector_identity": "hubspot",
        "customer_title": "AI Permit-to-Update-Customer-Record",
        "type_definition": (
            "Exact authorization to update one allowlisted property on one "
            "synthetic HubSpot developer-test contact"
        ),
        "provider_mapping": {
            "provider": "hubspot",
            "operation": "crm.contacts.update_property",
        },
        "specific_paths": [
            "/provider_portal_reference_commitment",
            "/provider_account_type",
            "/record_is_synthetic",
            "/customer_record_reference_commitment",
            "/property_name",
            "/property_label",
            "/property_allowlisted",
            "/property_read_only",
            "/value_before_commitment",
            "/value_after_commitment",
            "/contact_updated_at_before",
            "/property_definition_digest",
            "/customer_record_state_digest",
        ],
        "target_paths": [
            "/provider_portal_reference_commitment",
            "/customer_record_reference_commitment",
            "/property_name",
        ],
        "material_paths": [
            "/provider_account_type",
            "/record_is_synthetic",
            "/property_label",
            "/property_allowlisted",
            "/property_read_only",
            "/value_before_commitment",
            "/value_after_commitment",
            "/contact_updated_at_before",
            "/property_definition_digest",
            "/customer_record_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_developer_test_portal",
            "provider_account_information_preflight",
            "provider_contact_preflight",
            "provider_property_definition_preflight",
            "gateway_customer_property_allowlist",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.crm.customer.record.update.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Synthetic customer record"},
            {"field": "linked_to", "label": "One property update"},
            {"field": "provider", "label": "CRM provider"},
            {"field": "request_digest", "label": "Bound request"},
        ],
        "does_not_establish": [
            "truth_or_accuracy_of_the_customer_data",
            "consent_for_downstream_use_of_the_updated_data",
            "absence_of_later_writes_by_other_users_or_integrations",
        ],
        "risk_tags": ["data_mutation", "crm", "customer_record"],
        "properties": {
            "provider_portal_reference_commitment": base.cref(),
            "provider_account_type": {"const": "DEVELOPER_TEST"},
            "record_is_synthetic": {"const": True},
            "customer_record_reference_commitment": base.cref(),
            "property_name": {
                "enum": ["jobtitle", "lifecyclestage", "phone"]
            },
            "property_label": short_string(),
            "property_allowlisted": {"const": True},
            "property_read_only": {"const": False},
            "value_before_commitment": base.cref(),
            "value_after_commitment": base.cref(),
            "contact_updated_at_before": base.tref(),
            "property_definition_digest": base.dref(),
            "customer_record_state_digest": base.dref(),
        },
        "sample": {
            "provider_portal_reference_commitment": base.commitment("7"),
            "provider_account_type": "DEVELOPER_TEST",
            "record_is_synthetic": True,
            "customer_record_reference_commitment": base.commitment("8"),
            "property_name": "lifecyclestage",
            "property_label": "Lifecycle stage",
            "property_allowlisted": True,
            "property_read_only": False,
            "value_before_commitment": base.commitment("9"),
            "value_after_commitment": base.commitment("a"),
            "contact_updated_at_before": "2026-08-11T01:00:00Z",
            "property_definition_digest": base.digest("b"),
            "customer_record_state_digest": base.digest("c"),
        },
    },
    {
        "consequence_type": "crm.quote.create.v1",
        "semantic_id": "keel.action.crm_quote_create.v1",
        "action": "crm.quote.create",
        "connector_identity": "hubspot",
        "customer_title": "AI Permit-to-Create-Quote",
        "type_definition": (
            "Exact authorization to create one unpublished draft quote from one "
            "bounded provider-observed deal and line-item set in HubSpot developer test"
        ),
        "provider_mapping": {
            "provider": "hubspot",
            "operation": "crm.quotes.create_draft",
        },
        "specific_paths": [
            "/provider_portal_reference_commitment",
            "/provider_account_type",
            "/record_is_synthetic",
            "/deal_reference_commitment",
            "/line_item_set_commitment",
            "/quote_title_commitment",
            "/quote_expiration_date",
            "/quote_status",
            "/line_item_count",
            "/subtotal_amount_minor",
            "/discount_amount_minor",
            "/tax_amount_minor",
            "/total_amount_minor",
            "/currency",
            "/total_matches_provider_pricing",
            "/payment_enabled",
            "/e_signature_enabled",
            "/publication_status",
            "/existing_quote_count_for_idempotency_key",
            "/association_types_digest",
            "/pricing_state_digest",
        ],
        "target_paths": [
            "/provider_portal_reference_commitment",
            "/deal_reference_commitment",
            "/line_item_set_commitment",
            "/quote_title_commitment",
        ],
        "material_paths": [
            "/provider_account_type",
            "/record_is_synthetic",
            "/quote_expiration_date",
            "/quote_status",
            "/line_item_count",
            "/subtotal_amount_minor",
            "/discount_amount_minor",
            "/tax_amount_minor",
            "/total_amount_minor",
            "/currency",
            "/total_matches_provider_pricing",
            "/payment_enabled",
            "/e_signature_enabled",
            "/publication_status",
            "/existing_quote_count_for_idempotency_key",
            "/association_types_digest",
            "/pricing_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_pinned_developer_test_portal",
            "provider_account_information_preflight",
            "provider_deal_and_line_item_preflight",
            "provider_association_label_preflight",
            "gateway_quote_draft_only_constraint",
            "gateway_quote_idempotency_ledger",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.crm.quote.create.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Draft quote"},
            {"field": "amount", "label": "Quote total"},
            {"field": "currency", "label": "Currency"},
            {"field": "provider", "label": "CRM provider"},
        ],
        "does_not_establish": [
            "quote_publication_delivery_signature_or_acceptance",
            "payment_order_creation_or_legally_binding_contract",
            "provider_state_after_the_immediate_readback",
        ],
        "risk_tags": ["financial_record", "crm", "quote_creation"],
        "properties": {
            "provider_portal_reference_commitment": base.cref(),
            "provider_account_type": {"const": "DEVELOPER_TEST"},
            "record_is_synthetic": {"const": True},
            "deal_reference_commitment": base.cref(),
            "line_item_set_commitment": base.cref(),
            "quote_title_commitment": base.cref(),
            "quote_expiration_date": {
                "type": "string",
                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
            },
            "quote_status": {"const": "DRAFT"},
            "line_item_count": {"type": "integer", "minimum": 1, "maximum": 10},
            "subtotal_amount_minor": {"type": "integer", "minimum": 1},
            "discount_amount_minor": {"type": "integer", "minimum": 0},
            "tax_amount_minor": {"type": "integer", "minimum": 0},
            "total_amount_minor": {"type": "integer", "minimum": 1},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "total_matches_provider_pricing": {"const": True},
            "payment_enabled": {"const": False},
            "e_signature_enabled": {"const": False},
            "publication_status": {"const": "not_published"},
            "existing_quote_count_for_idempotency_key": {"const": 0},
            "association_types_digest": base.dref(),
            "pricing_state_digest": base.dref(),
        },
        "sample": {
            "provider_portal_reference_commitment": base.commitment("7"),
            "provider_account_type": "DEVELOPER_TEST",
            "record_is_synthetic": True,
            "deal_reference_commitment": base.commitment("8"),
            "line_item_set_commitment": base.commitment("9"),
            "quote_title_commitment": base.commitment("a"),
            "quote_expiration_date": "2026-09-10",
            "quote_status": "DRAFT",
            "line_item_count": 2,
            "subtotal_amount_minor": 125000,
            "discount_amount_minor": 10000,
            "tax_amount_minor": 0,
            "total_amount_minor": 115000,
            "currency": "USD",
            "total_matches_provider_pricing": True,
            "payment_enabled": False,
            "e_signature_enabled": False,
            "publication_status": "not_published",
            "existing_quote_count_for_idempotency_key": 0,
            "association_types_digest": base.digest("b"),
            "pricing_state_digest": base.digest("c"),
        },
    },
]


INTEGER_FIELDS = {
    "line_item_count",
    "subtotal_amount_minor",
    "discount_amount_minor",
    "tax_amount_minor",
    "total_amount_minor",
    "existing_quote_count_for_idempotency_key",
}
BOOLEAN_FIELDS = {
    "record_is_synthetic",
    "transition_allowlisted",
    "property_allowlisted",
    "property_read_only",
    "total_matches_provider_pricing",
    "payment_enabled",
    "e_signature_enabled",
}
TIMESTAMP_FIELDS = {"deal_updated_at_before", "contact_updated_at_before"}


def configure_base() -> None:
    base.FACT_SCHEMA = FACT_SCHEMA
    base.ACTION_DEFS = ACTION_DEFS
    base.INTEGER_FIELDS.update(INTEGER_FIELDS)
    base.BOOLEAN_FIELDS.update(BOOLEAN_FIELDS)
    base.TIMESTAMP_FIELDS.update(TIMESTAMP_FIELDS)


def profile_id(action_def: dict[str, Any]) -> str:
    return base.profile_id(action_def)


def build_schema() -> dict[str, Any]:
    configure_base()
    schema = base.build_schema()
    schema["$id"] = (
        "https://github.com/keelapi/keel-permit/schemas/"
        "erp-crm-exact-facts-v1.schema.json"
    )
    schema["title"] = "Keel exact ERP/CRM authorization facts v1"
    for action_def in ACTION_DEFS:
        definition = schema["$defs"][action_def["action"].replace(".", "_")]
        definition["properties"]["version"] = {"const": FACT_VERSION}
        definition["properties"]["provider_environment"] = {
            "const": "developer_test"
        }
    return schema


def fact_vector(action_def: dict[str, Any]) -> dict[str, Any]:
    configure_base()
    value = base.fact_vector(action_def)
    value["version"] = FACT_VERSION
    value["provider_environment"] = "developer_test"
    value["provider_api_version"] = "2026-03"
    value["preflight_observed_at"] = "2026-08-11T01:00:00Z"
    value["preflight_expires_at"] = "2026-08-11T01:05:00Z"
    return value


def main() -> None:
    configure_base()
    write(FACT_SCHEMA, build_schema())

    consequence_v9 = copy.deepcopy(load("consequence_registry/v8.json"))
    consequence_v9["$schema"] = "./v9.schema.json"
    consequence_v9["version"] = "keel.consequence_registry.v9"
    consequence_v9["consequences"].extend(base.consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v9.json", consequence_v9)

    consequence_schema = copy.deepcopy(load("consequence_registry/v8.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v9.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v9"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v9"
    )
    write("consequence_registry/v9.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v12 = copy.deepcopy(load("fact_profiles/v11.json"))
    facts_v12["$schema"] = "./v12.schema.json"
    facts_v12["version"] = "keel.fact_profile_registry.v12"
    facts_v12["profiles"].extend(
        base.fact_profile(item, facts_digest) for item in ACTION_DEFS
    )
    write("fact_profiles/v12.json", facts_v12)

    facts_schema = copy.deepcopy(load("fact_profiles/v11.schema.json"))
    facts_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v12.schema.json"
    )
    facts_schema["title"] = "Keel Permit fact profile registry v12"
    facts_schema["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v12"
    )
    write("fact_profiles/v12.schema.json", facts_schema)

    semantics_v14 = copy.deepcopy(load("semantic_registry/v13.json"))
    semantics_v14["$schema"] = "./v14.schema.json"
    semantics_v14["version"] = "keel.semantic_selector_registry.v14"
    semantics_v14["entries"].extend(base.semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v14.json", semantics_v14)

    semantic_schema = copy.deepcopy(load("semantic_registry/v13.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v14.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v14"
    semantic_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v14"
    )
    write("semantic_registry/v14.schema.json", semantic_schema)

    presentation_v13 = copy.deepcopy(load("presentation_registry/v12.json"))
    presentation_v13["$schema"] = "./v13.schema.json"
    presentation_v13["version"] = "keel.presentation_registry.v13"
    presentation_v13["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v14"
    )
    presentation_v13["profiles"].extend(
        base.presentation_profile(item) for item in ACTION_DEFS
    )
    write("presentation_registry/v13.json", presentation_v13)

    presentation_schema = copy.deepcopy(load("presentation_registry/v12.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "presentation_registry/v13.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v13"
    presentation_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v13"
    )
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v14"
    )
    write("presentation_registry/v13.schema.json", presentation_schema)

    vectors_v10 = copy.deepcopy(load("consequence_registry/test-vectors/v9.json"))
    vectors_v10["version"] = "keel.consequence_registry.test_vectors.v10"
    vectors_v10["consequence_registry_version"] = consequence_v9["version"]
    vectors_v10["semantic_registry_version"] = semantics_v14["version"]
    vectors_v10["presentation_registry_version"] = presentation_v13["version"]
    for action_def in ACTION_DEFS:
        vectors_v10["vectors"].append(
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
    write("consequence_registry/test-vectors/v10.json", vectors_v10)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v9", "consequence_registry/v9.json"),
        (
            "keel.permit.consequence_registry.v9.schema",
            "consequence_registry/v9.schema.json",
        ),
        ("keel.permit.erp_crm_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v12", "fact_profiles/v12.json"),
        (
            "keel.permit.fact_profile_registry.v12.schema",
            "fact_profiles/v12.schema.json",
        ),
        ("keel.permit.semantic_selector_registry.v14", "semantic_registry/v14.json"),
        (
            "keel.permit.semantic_selector_registry.v14.schema",
            "semantic_registry/v14.schema.json",
        ),
        ("keel.permit.presentation_registry.v13", "presentation_registry/v13.json"),
        (
            "keel.permit.presentation_registry.v13.schema",
            "presentation_registry/v13.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v10",
            "consequence_registry/test-vectors/v10.json",
        ),
        (
            "keel.permit.erp_crm_exact_action_contract.v1.spec",
            "spec/erp-crm-exact-action-contract-v1.md",
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
