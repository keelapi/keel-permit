#!/usr/bin/env python3
"""Build additive provider-neutral telephony gateway contracts.

The historical Vocal Bridge facts/profile remain byte-for-byte immutable. This
builder adds a distinct trusted source and facts profile for a Keel-controlled
HTTPS gateway, while preserving the same deliberately narrow customer title.
"""

from __future__ import annotations

import copy

from build_transactional_cx_registries import load, sha256, write


FACT_SCHEMA = "schemas/telephony-call-outbound-gateway-exact-facts-v1.schema.json"
SEMANTIC_ID = "keel.action.telephony_call_outbound_gateway.v1"
FACT_PROFILE_ID = "keel.facts.telephony_call_outbound_gateway_exact.v1"
RESPONSE_FACT_SCHEMA = "schemas/telephony-call-respond-gateway-exact-facts-v1.schema.json"
RESPONSE_SEMANTIC_ID = "keel.action.telephony_call_respond_gateway.v1"
RESPONSE_FACT_PROFILE_ID = "keel.facts.telephony_call_respond_gateway_exact.v1"
SOURCE_KIND = "telephony_gateway_service"


def _field(path: str, value_type: str, *, commitment: bool = False) -> dict:
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": "personal_data" if commitment else "operational",
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
            "keel.salted_sha256_jcs.v1" if commitment else "signed_cleartext"
        ),
    }


def main() -> None:
    facts_schema = copy.deepcopy(
        load("schemas/telephony-call-outbound-exact-facts-v1.schema.json")
    )
    facts_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/schemas/"
        "telephony-call-outbound-gateway-exact-facts-v1.schema.json"
    )
    facts_schema["title"] = "Outbound telephone call gateway exact authorization facts v1"
    facts_schema["description"] = (
        "Facts established by Keel before one exact outbound call is sent to a "
        "pinned customer-controlled telephony gateway. The gateway cannot be "
        "selected by the governed caller and no dialable number is disclosed."
    )
    facts_schema["properties"]["version"] = {
        "const": "keel.telephony_call_outbound_gateway_exact_facts.v1"
    }
    facts_schema["properties"]["fact_profile_id"] = {"const": FACT_PROFILE_ID}
    facts_schema["properties"]["connector_type"] = {
        "const": "keel_gateway_https"
    }
    facts_schema["properties"]["gateway_protocol_version"] = {
        "const": "keel.action_gateway.v1"
    }
    facts_schema["properties"]["telephony_gateway_protocol_version"] = {
        "const": "keel.telephony_gateway.v1"
    }
    facts_schema["required"].extend(
        [
            "gateway_protocol_version",
            "telephony_gateway_protocol_version",
            "work_root_permit_id",
            "work_authority_id",
        ]
    )
    write(FACT_SCHEMA, facts_schema)

    digest_definition = {
        "type": "string",
        "pattern": "^sha256:[0-9a-f]{64}$",
    }
    response_facts_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/keelapi/keel-permit/schemas/"
            "telephony-call-respond-gateway-exact-facts-v1.schema.json"
        ),
        "title": "Voice turn response gateway exact authorization facts v1",
        "description": (
            "Verifier-safe facts established by Keel before one exact text "
            "response is released to a pending authenticated voice turn. Raw "
            "session references, turn references, and response text are forbidden."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": [
            "version",
            "fact_profile_id",
            "action",
            "connector_identity",
            "connector_type",
            "provider_environment",
            "gateway_protocol_version",
            "originating_principal_id",
            "work_root_permit_id",
            "work_authority_id",
            "call_response_bridge_kind",
            "session_reference_digest",
            "turn_reference_digest",
            "response_text_digest",
            "provider_wire_body_digest",
            "request_digest",
            "idempotency_digest",
        ],
        "properties": {
            "version": {
                "const": "keel.telephony_call_respond_gateway_exact_facts.v1"
            },
            "fact_profile_id": {"const": RESPONSE_FACT_PROFILE_ID},
            "action": {"const": "call.respond"},
            "connector_identity": {"type": "string", "format": "uuid"},
            "connector_type": {"const": "keel_gateway_https"},
            "provider_environment": {
                "enum": ["provider_live", "provider_sandbox"]
            },
            "gateway_protocol_version": {"const": "keel.action_gateway.v1"},
            "originating_principal_id": {"type": "string", "format": "uuid"},
            "work_root_permit_id": {"type": "string", "format": "uuid"},
            "work_authority_id": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$",
            },
            "call_response_bridge_kind": {
                "const": "synchronous_voice_turn_v1"
            },
            "session_reference_digest": digest_definition,
            "turn_reference_digest": digest_definition,
            "response_text_digest": digest_definition,
            "provider_wire_body_digest": digest_definition,
            "request_digest": digest_definition,
            "idempotency_digest": digest_definition,
        },
    }
    write(RESPONSE_FACT_SCHEMA, response_facts_schema)

    semantics = copy.deepcopy(load("semantic_registry/v21.json"))
    semantics["$schema"] = "./v22.schema.json"
    semantics["version"] = "keel.semantic_selector_registry.v22"
    semantics["entries"].append(
        {
            "semantic_id": SEMANTIC_ID,
            "semantic_kind": "exact_action",
            "trusted_source_kinds": [SOURCE_KIND],
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
    semantics["entries"].append(
        {
            "semantic_id": RESPONSE_SEMANTIC_ID,
            "semantic_kind": "exact_action",
            "trusted_source_kinds": [SOURCE_KIND],
            "fact_profile_id": RESPONSE_FACT_PROFILE_ID,
            "match": {
                "action_names": ["call.respond"],
                "operations": ["call.respond"],
                "allowed_chain_roles": ["action_child"],
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
    write("semantic_registry/v22.json", semantics)

    semantic_schema = copy.deepcopy(load("semantic_registry/v21.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v22.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v22"
    semantic_schema["properties"]["version"]["const"] = semantics["version"]
    trusted_sources = semantic_schema["$defs"]["entry"]["properties"][
        "trusted_source_kinds"
    ]["items"]["enum"]
    if SOURCE_KIND not in trusted_sources:
        trusted_sources.append(SOURCE_KIND)
    write("semantic_registry/v22.schema.json", semantic_schema)

    profiles = copy.deepcopy(load("fact_profiles/v18.json"))
    profiles["$schema"] = "./v19.schema.json"
    profiles["version"] = "keel.fact_profile_registry.v19"
    profiles["profiles"].append(
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
                "/gateway_protocol_version",
                "/telephony_gateway_protocol_version",
            ],
            "fields": [
                _field("/connector_identity", "string"),
                _field("/connector_type", "string"),
                _field("/provider_environment", "string"),
                _field("/gateway_protocol_version", "string"),
                _field("/telephony_gateway_protocol_version", "string"),
                _field("/destination_reference_commitment", "commitment", commitment=True),
                _field("/destination_allowlisted", "boolean"),
                _field("/destination_allowlist_digest", "digest"),
                _field("/originating_principal_id", "string"),
                _field("/work_root_permit_id", "string"),
                _field("/work_authority_id", "string"),
                _field("/action_access_level", "string"),
                _field("/action_risk_tags", "array"),
                _field("/provider_wire_body_digest", "digest"),
                _field("/request_digest", "digest"),
                _field("/idempotency_digest", "digest"),
            ],
            "release_state": "eligible",
        }
    )
    profiles["profiles"].append(
        {
            "fact_profile_id": RESPONSE_FACT_PROFILE_ID,
            "semantic_ids": [RESPONSE_SEMANTIC_ID],
            "authorized_action": "call.respond",
            "facts_schema": RESPONSE_FACT_SCHEMA,
            "facts_schema_digest": f"sha256:{sha256(RESPONSE_FACT_SCHEMA)}",
            "target_fact_paths": [
                "/session_reference_digest",
                "/turn_reference_digest",
            ],
            "material_request_fact_paths": [
                "/response_text_digest",
                "/provider_wire_body_digest",
                "/request_digest",
                "/idempotency_digest",
                "/gateway_protocol_version",
                "/call_response_bridge_kind",
            ],
            "fields": [
                _field("/connector_identity", "string"),
                _field("/connector_type", "string"),
                _field("/provider_environment", "string"),
                _field("/gateway_protocol_version", "string"),
                _field("/originating_principal_id", "string"),
                _field("/work_root_permit_id", "string"),
                _field("/work_authority_id", "string"),
                _field("/call_response_bridge_kind", "string"),
                _field("/session_reference_digest", "digest"),
                _field("/turn_reference_digest", "digest"),
                _field("/response_text_digest", "digest"),
                _field("/provider_wire_body_digest", "digest"),
                _field("/request_digest", "digest"),
                _field("/idempotency_digest", "digest"),
            ],
            "release_state": "eligible",
        }
    )
    write("fact_profiles/v19.json", profiles)

    profile_schema = copy.deepcopy(load("fact_profiles/v18.schema.json"))
    profile_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v19.schema.json"
    )
    profile_schema["title"] = "Keel Permit fact profile registry v19"
    profile_schema["properties"]["version"]["const"] = profiles["version"]
    write("fact_profiles/v19.schema.json", profile_schema)

    presentations = copy.deepcopy(load("presentation_registry/v20.json"))
    presentations["$schema"] = "./v21.schema.json"
    presentations["version"] = "keel.presentation_registry.v21"
    presentations["semantic_registry_version"] = semantics["version"]
    presentations["profiles"].append(
        {
            "semantic_id": SEMANTIC_ID,
            "presentation_profile_id": "telephony_call_outbound_gateway.r1",
            "customer_title": "AI Permit-to-Place-Outbound-Call",
            "type_definition": (
                "Exact authorization to originate one outbound telephone call "
                "to one allowlisted destination through a pinned Keel-controlled "
                "telephony gateway"
            ),
            "leading_fields": [
                {"field": "recipient", "label": "Allowlisted destination"},
                {"field": "provider", "label": "Telephony gateway"},
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
                "governance_of_the_later_live_conversation",
                "provider_success_or_call_completion",
            ],
            "fallback_profile": "generic_ai_permit",
            "release_state": "eligible",
        }
    )
    presentations["profiles"].append(
        {
            "semantic_id": RESPONSE_SEMANTIC_ID,
            "presentation_profile_id": "telephony_call_respond_gateway.r1",
            "customer_title": "AI Permit-to-Respond-to-Voice-Turn",
            "type_definition": (
                "Exact authorization to release one exact text response to one "
                "pending authenticated voice turn through a pinned gateway"
            ),
            "leading_fields": [
                {"field": "request_digest", "label": "Bound response request"},
                {"field": "provider", "label": "Voice gateway"},
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
                "that_the_caller_heard_or_understood_the_response",
                "the_truth_or_appropriateness_of_the_response_content",
                "authorization_of_any_separate_transfer_dtmf_sms_or_hangup",
                "consent_of_any_call_participant",
                "provider_success_or_call_completion",
            ],
            "fallback_profile": "generic_ai_permit",
            "release_state": "eligible",
        }
    )
    write("presentation_registry/v21.json", presentations)

    presentation_schema = copy.deepcopy(load("presentation_registry/v20.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v21.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v21"
    presentation_schema["properties"]["version"]["const"] = presentations["version"]
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        semantics["version"]
    )
    write("presentation_registry/v21.schema.json", presentation_schema)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.telephony_call_outbound_gateway_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.telephony_call_respond_gateway_exact_facts.v1.schema", RESPONSE_FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v19", "fact_profiles/v19.json"),
        ("keel.permit.fact_profile_registry.v19.schema", "fact_profiles/v19.schema.json"),
        ("keel.permit.semantic_selector_registry.v22", "semantic_registry/v22.json"),
        ("keel.permit.semantic_selector_registry.v22.schema", "semantic_registry/v22.schema.json"),
        ("keel.permit.presentation_registry.v21", "presentation_registry/v21.json"),
        ("keel.permit.presentation_registry.v21.schema", "presentation_registry/v21.schema.json"),
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
