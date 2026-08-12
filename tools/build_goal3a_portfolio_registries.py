#!/usr/bin/env python3
"""Build the four additive exact-action contracts required by Goal 3A."""

from __future__ import annotations

import copy

import build_wave5_breadth_registries as base
from build_transactional_cx_registries import load, sha256, write


FACT_SCHEMA = "schemas/goal3a-portfolio-exact-facts-v1.schema.json"
FACT_VERSION = "keel.goal3a_portfolio_exact_facts.v1"


def cloud_action(
    *,
    consequence_type: str,
    semantic_id: str,
    name: str,
    title: str,
    definition: str,
    fields: list,
    operation: str,
    risks: list[str],
):
    return base.exact_action(
        consequence_type=consequence_type,
        semantic_id=semantic_id,
        name=name,
        connector="fly",
        environment="dedicated_demo",
        api_version="fly-machines-api-v1",
        title=title,
        definition=definition,
        provider="fly",
        operation=operation,
        fields=[base.reference("app_reference_commitment", "8"), *fields],
        trusted=[
            "gateway_owned_app_allowlist",
            "preprovisioned_machine_group_allowlist",
            "provider_machine_state_preflight",
        ],
        limits=[
            "production_or_customer_owned_apps",
            "machine_creation_or_deletion",
            "authority_outside_the_named_dedicated_demo_app",
            *base.DEMO_LIMITS,
        ],
        risks=risks,
        leading=[
            {"field": "resource", "label": "Dedicated demo service"},
            {"field": "environment", "label": "Environment"},
            {"field": "provider", "label": "Cloud provider"},
            {"field": "linked_to", "label": "Bound machine state"},
        ],
    )


ACTION_DEFS = [
    cloud_action(
        consequence_type="cloud.machine.restart.v1",
        semantic_id="keel.action.cloud_machine_restart.v1",
        name="cloud.machine.restart",
        title="AI Permit-to-Restart-Machine",
        definition="Exact authorization to restart one allowlisted pre-provisioned Machine in one Keel-owned dedicated demo app",
        operation="machines.restart",
        fields=[
            base.reference("machine_reference_commitment", "9"),
            base.field("environment", {"const": "dedicated_demo"}, "dedicated_demo"),
            base.field("machine_state", {"const": "started"}, "started"),
            base.field("machine_region", base.text(64), "iad"),
            base.digest("machine_config_digest", "a"),
        ],
        risks=["service_availability", "cloud_control", "external_state_change"],
    ),
    cloud_action(
        consequence_type="cloud.machine.stop.v1",
        semantic_id="keel.action.cloud_machine_stop.v1",
        name="cloud.machine.stop",
        title="AI Permit-to-Stop-Machine",
        definition="Exact authorization to stop one allowlisted pre-provisioned Machine in one Keel-owned dedicated demo app",
        operation="machines.stop",
        fields=[
            base.reference("machine_reference_commitment", "9"),
            base.field("environment", {"const": "dedicated_demo"}, "dedicated_demo"),
            base.field("machine_state", {"const": "started"}, "started"),
            base.field("machine_region", base.text(64), "iad"),
            base.digest("machine_config_digest", "a"),
        ],
        risks=["service_availability", "cloud_control", "external_state_change"],
    ),
    cloud_action(
        consequence_type="cloud.service.scale.v1",
        semantic_id="keel.action.cloud_service_scale.v1",
        name="cloud.service.scale",
        title="AI Permit-to-Scale-Service",
        definition="Exact authorization to start or stop only pre-provisioned Machines so one Keel-owned dedicated demo service reaches a bounded count",
        operation="machines.scale_preprovisioned_group",
        fields=[
            base.field("environment", {"const": "dedicated_demo"}, "dedicated_demo"),
            base.field("desired_machine_count", base.integer(1, 3), 2),
            base.field("current_machine_count", base.integer(0, 3), 1),
            base.digest("machine_config_digest", "a"),
            base.digest("scale_group_state_digest", "b"),
        ],
        risks=["service_capacity", "service_availability", "cloud_control"],
    ),
    base.exact_action(
        consequence_type="stripe.connect.transfer.send.v1",
        semantic_id="keel.action.stripe_connect_transfer_send.v1",
        name="stripe.transfer.create",
        connector="stripe",
        environment="provider_sandbox",
        api_version="stripe-2025-12-15.clover",
        title="AI Permit-to-Send-Stripe-Connect-Transfer",
        definition="Exact authorization to send one bounded Stripe test-mode Connect transfer to one preflight-verified test destination",
        provider="stripe",
        operation="transfers.create",
        fields=[
            base.digest("platform_account_digest", "8"),
            base.field("amount_minor", base.integer(1, 999_999_999), 100),
            base.field("currency", {"pattern": "^[A-Z]{3}$", "type": "string"}, "USD"),
            base.reference("destination_account_reference_commitment", "9"),
            base.digest("destination_account_state_digest", "a"),
            base.field("destination_charges_enabled", {"type": "boolean"}, True),
            base.field("destination_payouts_enabled", {"type": "boolean"}, True),
        ],
        trusted=[
            "stripe_test_mode_account_preflight",
            "stripe_connect_destination_preflight",
            "gateway_held_saved_payee_allowlist",
        ],
        leading=[
            {"field": "amount", "label": "Transfer amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "recipient", "label": "Connect destination"},
            {"field": "provider", "label": "Payment provider"},
        ],
        limits=[
            "stripe_live_mode_or_bank_settlement",
            "destination_identity_beyond_the_bound_test_account",
            "authority_to_create_or_change_connected_accounts",
            *base.DEMO_LIMITS,
        ],
        risks=["money_movement", "payment", "external_state_change"],
    ),
]


def configure_base() -> None:
    base.FACT_SCHEMA = FACT_SCHEMA
    base.FACT_VERSION = FACT_VERSION
    base.ACTION_DEFS = ACTION_DEFS
    base.INTEGER_FIELDS.update(
        {
            name
            for item in ACTION_DEFS
            for name, schema in item["properties"].items()
            if schema.get("type") == "integer"
        }
    )
    base.BOOLEAN_FIELDS.update(
        {
            name
            for item in ACTION_DEFS
            for name, schema in item["properties"].items()
            if schema.get("type") == "boolean"
            or isinstance(schema.get("const"), bool)
        }
    )
    base.configure_base()


def build_schema():
    configure_base()
    schema = base.build_schema()
    schema["$id"] = "https://github.com/keelapi/keel-permit/" + FACT_SCHEMA
    schema["title"] = "Keel exact Goal 3A portfolio facts v1"
    for item in ACTION_DEFS:
        definition = schema["$defs"][item["action"].replace(".", "_")]
        definition["properties"]["version"] = {"const": FACT_VERSION}
        definition["properties"]["provider_environment"] = {
            "const": item["environment"]
        }
    return schema


def fact_vector(item):
    configure_base()
    value = base.fact_vector(item)
    value["version"] = FACT_VERSION
    value["provider_environment"] = item["environment"]
    value["provider_api_version"] = item["provider_api_version"]
    value["preflight_observed_at"] = "2026-08-12T12:00:00Z"
    value["preflight_expires_at"] = "2026-08-12T12:05:00Z"
    return value


def main() -> None:
    configure_base()
    write(FACT_SCHEMA, build_schema())

    consequence = copy.deepcopy(load("consequence_registry/v12.json"))
    consequence["$schema"] = "./v13.schema.json"
    consequence["version"] = "keel.consequence_registry.v13"
    consequence["consequences"].extend(
        base.base.base.base.consequence(item) for item in ACTION_DEFS
    )
    write("consequence_registry/v13.json", consequence)
    consequence_schema = copy.deepcopy(load("consequence_registry/v12.schema.json"))
    consequence_schema["$id"] = "https://github.com/keelapi/keel-permit/consequence_registry/v13.schema.json"
    consequence_schema["title"] = "Keel consequence registry v13"
    consequence_schema["properties"]["version"]["const"] = consequence["version"]
    write("consequence_registry/v13.schema.json", consequence_schema)

    schema_digest = sha256(FACT_SCHEMA)
    facts = copy.deepcopy(load("fact_profiles/v15.json"))
    facts["$schema"] = "./v16.schema.json"
    facts["version"] = "keel.fact_profile_registry.v16"
    facts["profiles"].extend(
        base.base.base.base.fact_profile(item, schema_digest) for item in ACTION_DEFS
    )
    write("fact_profiles/v16.json", facts)
    facts_schema = copy.deepcopy(load("fact_profiles/v15.schema.json"))
    facts_schema["$id"] = "https://github.com/keelapi/keel-permit/fact_profiles/v16.schema.json"
    facts_schema["title"] = "Keel Permit fact profile registry v16"
    facts_schema["properties"]["version"]["const"] = facts["version"]
    write("fact_profiles/v16.schema.json", facts_schema)

    semantics = copy.deepcopy(load("semantic_registry/v17.json"))
    semantics["$schema"] = "./v18.schema.json"
    semantics["version"] = "keel.semantic_selector_registry.v18"
    # Great Bank uses provider-shaped MCP tool names, but the authorized
    # consequences are the already-settled pay and refund semantics.  Extend
    # selector aliases in the new registry only; do not mint duplicate payment
    # or refund semantics and do not alter any historical registry bytes.
    for entry in semantics["entries"]:
        if entry.get("semantic_id") == "keel.action.payment_execute.v1":
            entry["match"]["action_names"].append("stripe.payment_intent.create")
            if "call.tools" not in entry["match"]["operations"]:
                entry["match"]["operations"].append("call.tools")
        elif entry.get("semantic_id") == "keel.action.payment_refund.v2":
            entry["match"]["action_names"].append("stripe.refund.create")
    semantics["entries"].extend(
        base.base.base.base.semantic_entry(item) for item in ACTION_DEFS
    )
    write("semantic_registry/v18.json", semantics)
    semantic_schema = copy.deepcopy(load("semantic_registry/v17.schema.json"))
    semantic_schema["$id"] = "https://github.com/keelapi/keel-permit/semantic_registry/v18.schema.json"
    semantic_schema["title"] = "Keel Permit semantic selector registry v18"
    semantic_schema["properties"]["version"]["const"] = semantics["version"]
    write("semantic_registry/v18.schema.json", semantic_schema)

    presentation = copy.deepcopy(load("presentation_registry/v16.json"))
    presentation["$schema"] = "./v17.schema.json"
    presentation["version"] = "keel.presentation_registry.v17"
    presentation["semantic_registry_version"] = semantics["version"]
    presentation["profiles"].extend(
        base.base.base.base.presentation_profile(item) for item in ACTION_DEFS
    )
    write("presentation_registry/v17.json", presentation)
    presentation_schema = copy.deepcopy(load("presentation_registry/v16.schema.json"))
    presentation_schema["$id"] = "https://github.com/keelapi/keel-permit/presentation_registry/v17.schema.json"
    presentation_schema["title"] = "Keel Permit presentation registry v17"
    presentation_schema["properties"]["version"]["const"] = presentation["version"]
    presentation_schema["properties"]["semantic_registry_version"]["const"] = semantics["version"]
    write("presentation_registry/v17.schema.json", presentation_schema)

    vectors = copy.deepcopy(load("consequence_registry/test-vectors/v13.json"))
    vectors["version"] = "keel.consequence_registry.test_vectors.v14"
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
                    "evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "expected_semantic_id": item["semantic_id"],
                "expected_title": item["customer_title"],
                "expected_fact_profile_id": base.profile_id(item),
                "valid_authorization_facts": fact_vector(item),
            }
        )
    write("consequence_registry/test-vectors/v14.json", vectors)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v13", "consequence_registry/v13.json"),
        ("keel.permit.consequence_registry.v13.schema", "consequence_registry/v13.schema.json"),
        ("keel.permit.goal3a_portfolio_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v16", "fact_profiles/v16.json"),
        ("keel.permit.fact_profile_registry.v16.schema", "fact_profiles/v16.schema.json"),
        ("keel.permit.semantic_selector_registry.v18", "semantic_registry/v18.json"),
        ("keel.permit.semantic_selector_registry.v18.schema", "semantic_registry/v18.schema.json"),
        ("keel.permit.presentation_registry.v17", "presentation_registry/v17.json"),
        ("keel.permit.presentation_registry.v17.schema", "presentation_registry/v17.schema.json"),
        ("permit-to-x.test-vectors.consequence-registry.v14", "consequence_registry/test-vectors/v14.json"),
    ]
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        if path in existing:
            existing[path].update({"id": artifact_id, "sha256": sha256(path)})
        else:
            manifest["artifacts"].append(
                {"id": artifact_id, "path": path, "sha256": sha256(path)}
            )
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
