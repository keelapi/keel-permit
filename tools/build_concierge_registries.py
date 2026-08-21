#!/usr/bin/env python3
"""Build additive outbound-call registries for the Concierge habitat."""

from __future__ import annotations

import copy

from build_transactional_cx_registries import load, sha256, write

FACT_SCHEMA = "schemas/telephony-call-outbound-exact-facts-v1.schema.json"
SEMANTIC_ID = "keel.action.telephony_call_outbound.v1"
FACT_PROFILE_ID = "keel.facts.telephony_call_outbound_exact.v1"


def fact_field(
    path: str,
    value_type: str,
    *,
    classification: str = "operational",
    low_entropy: bool = True,
    commitment: bool = False,
    required: bool = True,
) -> dict:
    disclosure = (
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
    )
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": required,
        "classification": classification,
        "low_entropy_possible": low_entropy,
        "disclosure": disclosure,
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


def main() -> None:
    semantic = copy.deepcopy(load("semantic_registry/v18.json"))
    semantic["$schema"] = "./v19.schema.json"
    semantic["version"] = "keel.semantic_selector_registry.v19"
    semantic["entries"].append(
        {
            "semantic_id": SEMANTIC_ID,
            "semantic_kind": "exact_action",
            "trusted_source_kinds": ["telephony_origination_service"],
            "fact_profile_id": FACT_PROFILE_ID,
            "match": {
                "action_names": ["call.outbound"],
                "operations": ["call.outbound"],
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
    write("semantic_registry/v19.json", semantic)

    semantic_schema = copy.deepcopy(load("semantic_registry/v18.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v19.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v19"
    semantic_schema["properties"]["version"]["const"] = semantic["version"]
    source_kinds = semantic_schema["$defs"]["entry"]["properties"][
        "trusted_source_kinds"
    ]["items"]["enum"]
    source_kinds.append("telephony_origination_service")
    write("semantic_registry/v19.schema.json", semantic_schema)

    presentation = copy.deepcopy(load("presentation_registry/v17.json"))
    presentation["$schema"] = "./v18.schema.json"
    presentation["version"] = "keel.presentation_registry.v18"
    presentation["semantic_registry_version"] = semantic["version"]
    presentation["profiles"].append(
        {
            "semantic_id": SEMANTIC_ID,
            "presentation_profile_id": "telephony_call_outbound.r1",
            "customer_title": "AI Permit-to-Place-Outbound-Call",
            "type_definition": "Exact authorization to originate one outbound telephone call to one allowlisted destination through a verified telephony connector",
            "leading_fields": [
                {"field": "recipient", "label": "Allowlisted destination"},
                {"field": "provider", "label": "Telephony connector"},
                {"field": "request_digest", "label": "Bound call request"},
                {"field": "linked_to", "label": "Linked to"},
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
                "that_the_destination_answered_or_the_call_connected",
                "the_content_of_anything_said_on_the_call",
                "authorization_of_commitments_made_verbally_during_the_call",
                "consent_of_the_called_party",
                "keel_observation_or_recording_of_the_conversation",
                "provider_success_or_call_completion",
            ],
            "fallback_profile": "generic_ai_permit",
            "release_state": "eligible",
        }
    )
    write("presentation_registry/v18.json", presentation)

    presentation_schema = copy.deepcopy(load("presentation_registry/v17.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v18.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v18"
    presentation_schema["properties"]["version"]["const"] = presentation["version"]
    presentation_schema["properties"]["semantic_registry_version"]["const"] = semantic[
        "version"
    ]
    write("presentation_registry/v18.schema.json", presentation_schema)

    fact_profiles = copy.deepcopy(load("fact_profiles/v16.json"))
    fact_profiles["$schema"] = "./v17.schema.json"
    fact_profiles["version"] = "keel.fact_profile_registry.v17"
    fact_profiles["profiles"].append(
        {
            "fact_profile_id": FACT_PROFILE_ID,
            "semantic_ids": [SEMANTIC_ID],
            "authorized_action": "call.outbound",
            "facts_schema": FACT_SCHEMA,
            "facts_schema_digest": f"sha256:{sha256(FACT_SCHEMA)}",
            "target_fact_paths": [
                "/destination_reference_commitment",
                "/connector_identity",
            ],
            "material_request_fact_paths": [
                "/destination_allowlisted",
                "/destination_allowlist_digest",
                "/provider_wire_body_digest",
                "/request_digest",
                "/idempotency_digest",
            ],
            "fields": [
                fact_field("/connector_identity", "string"),
                fact_field("/connector_type", "string"),
                fact_field("/provider_environment", "string"),
                fact_field(
                    "/destination_reference_commitment",
                    "commitment",
                    classification="personal_data",
                    commitment=True,
                ),
                fact_field("/destination_allowlisted", "boolean"),
                fact_field(
                    "/destination_allowlist_digest", "digest", low_entropy=False
                ),
                fact_field("/destination_country_code", "string", required=False),
                fact_field("/originating_principal_id", "string"),
                fact_field("/work_root_permit_id", "string", required=False),
                fact_field("/work_authority_id", "string", required=False),
                fact_field("/action_access_level", "string"),
                fact_field("/action_risk_tags", "array"),
                fact_field("/provider_wire_body_digest", "digest", low_entropy=False),
                fact_field("/request_digest", "digest", low_entropy=False),
                fact_field("/idempotency_digest", "digest", low_entropy=False),
            ],
            "release_state": "eligible",
        }
    )
    write("fact_profiles/v17.json", fact_profiles)

    fact_schema = copy.deepcopy(load("fact_profiles/v16.schema.json"))
    fact_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v17.schema.json"
    )
    fact_schema["title"] = "Keel Permit fact profile registry v17"
    fact_schema["properties"]["version"]["const"] = fact_profiles["version"]
    write("fact_profiles/v17.schema.json", fact_schema)


if __name__ == "__main__":
    main()
