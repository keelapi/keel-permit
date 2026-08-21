#!/usr/bin/env python3
"""Build the reusable Keel action-gateway semantic contracts."""

from __future__ import annotations

import copy

from build_transactional_cx_registries import load, sha256, write

FACT_SCHEMA = "schemas/action-gateway-exact-facts-v1.schema.json"
SOURCE_KIND = "action_gateway_service"
ENTRIES = (
    {
        "action": "message.send",
        "semantic_id": "keel.action.message_send.v1",
        "fact_profile_id": "keel.facts.message_send_gateway_exact.v1",
        "presentation_profile_id": "message_send.r1",
        "title": "AI Permit-to-Send-Message",
        "type_definition": (
            "Exact authorization to send one exact message to one allowlisted "
            "destination through a customer-controlled bridge behind Keel's "
            "credential and dispatch boundary"
        ),
        "target_paths": ["/destination_hmac", "/connector_identity"],
        "material_paths": [
            "/destination_allowlisted",
            "/message_body_digest",
            "/provider_wire_body_digest",
            "/request_digest",
            "/idempotency_digest",
        ],
        "specific_fields": [
            ("/message_bridge_kind", "string", "operational", False),
            ("/destination_hmac", "commitment", "personal_data", True),
            ("/destination_allowlisted", "boolean", "operational", False),
            ("/message_body_digest", "digest", "personal_data", False),
        ],
        "does_not_establish": [
            "provider_delivery_or_recipient_receipt",
            "recipient_identity_beyond_the_allowlisted_commitment",
            "truth_quality_or_legality_of_message_content",
            "recipient_consent_or_authority_to_form_an_agreement",
            "provider_state_after_the_recorded_dispatch_boundary",
        ],
    },
    {
        "action": "calendar.event.create",
        "semantic_id": "keel.action.calendar_event_create_gateway.v1",
        "fact_profile_id": "keel.facts.calendar_event_create_gateway_exact.v1",
        "presentation_profile_id": "calendar_event_create_gateway.r1",
        "title": "AI Permit-to-Create-Calendar-Event",
        "type_definition": (
            "Exact authorization to create one exact event on one allowlisted "
            "customer calendar with an allowlisted attendee set through Keel's "
            "credential and dispatch boundary"
        ),
        "target_paths": [
            "/calendar_reference_hmac",
            "/attendee_set_hmac",
            "/connector_identity",
        ],
        "material_paths": [
            "/calendar_allowlisted",
            "/attendees_allowlisted",
            "/event_payload_digest",
            "/provider_wire_body_digest",
            "/request_digest",
            "/idempotency_digest",
        ],
        "specific_fields": [
            ("/calendar_provider", "string", "operational", False),
            ("/calendar_reference_hmac", "commitment", "personal_data", True),
            ("/calendar_allowlisted", "boolean", "operational", False),
            ("/attendee_set_hmac", "commitment", "personal_data", True),
            ("/attendees_allowlisted", "boolean", "operational", False),
            ("/event_payload_digest", "digest", "personal_data", False),
        ],
        "does_not_establish": [
            "attendee_acceptance_availability_or_attendance",
            "provider_completion_beyond_the_recorded_response",
            "calendar_state_after_the_recorded_dispatch_boundary",
            "legal_or_business_correctness_of_the_event",
        ],
    },
)


def field(
    path: str,
    value_type: str,
    classification: str = "operational",
    commitment: bool = False,
) -> dict:
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": classification,
        "low_entropy_possible": commitment,
        "disclosure": (
            {
                "verifier_safe": "commitment",
                "authorized": "commitment_with_optional_opening",
                "private": "commitment_with_optional_opening",
            }
            if commitment
            else {
                "verifier_safe": "cleartext",
                "authorized": "cleartext",
                "private": "cleartext",
            }
        ),
        "retention": {
            "class": "deletable_identity" if commitment else "permit_evidence",
            "max_days": None,
            "erasable": commitment,
            "erasure_action": "erase_opening" if commitment else "retain_signed_value",
        },
        "commitment_method": (
            "keel.hmac_sha256_jcs.v1" if commitment else "signed_cleartext"
        ),
    }


def main() -> None:
    semantics = copy.deepcopy(load("semantic_registry/v19.json"))
    semantics["$schema"] = "./v20.schema.json"
    semantics["version"] = "keel.semantic_selector_registry.v20"
    for item in ENTRIES:
        semantics["entries"].append(
            {
                "semantic_id": item["semantic_id"],
                "semantic_kind": "exact_action",
                "trusted_source_kinds": [SOURCE_KIND],
                "fact_profile_id": item["fact_profile_id"],
                "match": {
                    "action_names": [item["action"]],
                    "operations": [item["action"]],
                    "allowed_chain_roles": ["session_root", "action_child"],
                    "required_evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "excluded_permit_products": ["cost_permit"],
                "release_state": "eligible",
            }
        )
    write("semantic_registry/v20.json", semantics)

    semantic_schema = copy.deepcopy(load("semantic_registry/v19.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v20.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v20"
    semantic_schema["properties"]["version"]["const"] = semantics["version"]
    semantic_schema["$defs"]["entry"]["properties"]["trusted_source_kinds"][
        "items"
    ]["enum"].append(SOURCE_KIND)
    write("semantic_registry/v20.schema.json", semantic_schema)

    # v20 is immutable once generated. v21 broadens the existing exact-payment
    # selector to the server-owned action gateway without changing its action,
    # facts, or presentation meaning.
    payment_semantics = copy.deepcopy(semantics)
    payment_semantics["$schema"] = "./v21.schema.json"
    payment_semantics["version"] = "keel.semantic_selector_registry.v21"
    payment_entry = next(
        item
        for item in payment_semantics["entries"]
        if item["semantic_id"] == "keel.action.payment_execute.v1"
    )
    payment_entry["trusted_source_kinds"].append(SOURCE_KIND)
    write("semantic_registry/v21.json", payment_semantics)

    payment_semantic_schema = copy.deepcopy(semantic_schema)
    payment_semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v21.schema.json"
    )
    payment_semantic_schema["title"] = "Keel Permit semantic selector registry v21"
    payment_semantic_schema["properties"]["version"]["const"] = payment_semantics[
        "version"
    ]
    write("semantic_registry/v21.schema.json", payment_semantic_schema)

    presentations = copy.deepcopy(load("presentation_registry/v18.json"))
    presentations["$schema"] = "./v19.schema.json"
    presentations["version"] = "keel.presentation_registry.v19"
    presentations["semantic_registry_version"] = semantics["version"]
    for item in ENTRIES:
        presentations["profiles"].append(
            {
                "semantic_id": item["semantic_id"],
                "presentation_profile_id": item["presentation_profile_id"],
                "customer_title": item["title"],
                "type_definition": item["type_definition"],
                "leading_fields": [
                    {"field": "resource", "label": "Allowlisted target"},
                    {"field": "provider", "label": "Action gateway"},
                    {"field": "request_digest", "label": "Bound request"},
                    {"field": "linked_to", "label": "Work authority"},
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
                "does_not_establish": item["does_not_establish"],
                "fallback_profile": "generic_ai_permit",
                "release_state": "eligible",
            }
        )
    write("presentation_registry/v19.json", presentations)

    presentation_schema = copy.deepcopy(load("presentation_registry/v18.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v19.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v19"
    presentation_schema["properties"]["version"]["const"] = presentations["version"]
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        semantics["version"]
    )
    write("presentation_registry/v19.schema.json", presentation_schema)

    # Presentation registries name the exact semantic registry they render.
    # The payment title and profile are unchanged; v20 is the immutable pairing
    # for selector v21 so a verifier never borrows presentation data from a
    # different signed registry generation.
    payment_presentations = copy.deepcopy(presentations)
    payment_presentations["$schema"] = "./v20.schema.json"
    payment_presentations["version"] = "keel.presentation_registry.v20"
    payment_presentations["semantic_registry_version"] = payment_semantics["version"]
    write("presentation_registry/v20.json", payment_presentations)

    payment_presentation_schema = copy.deepcopy(presentation_schema)
    payment_presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v20.schema.json"
    )
    payment_presentation_schema["title"] = "Keel Permit presentation registry v20"
    payment_presentation_schema["properties"]["version"]["const"] = (
        payment_presentations["version"]
    )
    payment_presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        payment_semantics["version"]
    )
    write("presentation_registry/v20.schema.json", payment_presentation_schema)

    profiles = copy.deepcopy(load("fact_profiles/v17.json"))
    profiles["$schema"] = "./v18.schema.json"
    profiles["version"] = "keel.fact_profile_registry.v18"
    common_fields = [
        field("/connector_identity", "string"),
        field("/connector_type", "string"),
        field("/provider_environment", "string"),
        field("/gateway_protocol_version", "string"),
        field("/originating_principal_id", "string"),
        field("/allowlist_source", "string"),
        field("/max_uses", "integer"),
        field("/provider_wire_body_digest", "digest"),
        field("/request_digest", "digest"),
        field("/idempotency_digest", "digest"),
    ]
    for item in ENTRIES:
        profiles["profiles"].append(
            {
                "fact_profile_id": item["fact_profile_id"],
                "semantic_ids": [item["semantic_id"]],
                "authorized_action": item["action"],
                "facts_schema": FACT_SCHEMA,
                "facts_schema_digest": f"sha256:{sha256(FACT_SCHEMA)}",
                "target_fact_paths": item["target_paths"],
                "material_request_fact_paths": item["material_paths"],
                "fields": [
                    *copy.deepcopy(common_fields),
                    *[
                        field(path, value_type, classification, commitment)
                        for path, value_type, classification, commitment in item[
                            "specific_fields"
                        ]
                    ],
                ],
                "release_state": "eligible",
            }
        )
    write("fact_profiles/v18.json", profiles)

    profile_schema = copy.deepcopy(load("fact_profiles/v17.schema.json"))
    profile_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v18.schema.json"
    )
    profile_schema["title"] = "Keel Permit fact profile registry v18"
    profile_schema["properties"]["version"]["const"] = profiles["version"]
    write("fact_profiles/v18.schema.json", profile_schema)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.action_gateway_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v18", "fact_profiles/v18.json"),
        ("keel.permit.fact_profile_registry.v18.schema", "fact_profiles/v18.schema.json"),
        ("keel.permit.semantic_selector_registry.v20", "semantic_registry/v20.json"),
        ("keel.permit.semantic_selector_registry.v20.schema", "semantic_registry/v20.schema.json"),
        ("keel.permit.semantic_selector_registry.v21", "semantic_registry/v21.json"),
        ("keel.permit.semantic_selector_registry.v21.schema", "semantic_registry/v21.schema.json"),
        ("keel.permit.presentation_registry.v19", "presentation_registry/v19.json"),
        ("keel.permit.presentation_registry.v19.schema", "presentation_registry/v19.schema.json"),
        ("keel.permit.presentation_registry.v20", "presentation_registry/v20.json"),
        ("keel.permit.presentation_registry.v20.schema", "presentation_registry/v20.schema.json"),
        ("permit-to-x.test-vectors.action-gateway.v1", "test-vectors/action-gateway-v1.json"),
    ]
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        value = {"id": artifact_id, "path": path, "sha256": sha256(path)}
        if path in existing:
            existing[path].update(value)
        else:
            manifest["artifacts"].append(value)
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
