#!/usr/bin/env python3
"""Build presentation registry v25: v24 plus titles for the three Aidbox healthcare semantics.

Semantic registry v23 added three synthetic Aidbox administration actions
(mailing-address update, appointment reschedule, records release) without
presentation profiles, so their Permits fell back to the generic "AI Permit"
title and no AI-PT acronym. v25 keeps every v24 profile byte-for-byte in
content and order, appends one profile per Aidbox semantic, and moves
`semantic_registry_version` to v23, the registry that defines them.

Acronyms follow the v24 rule (``AI-PT`` plus the initial of each word after
"Permit-to"). v24 stays published and byte-identical.
"""

from __future__ import annotations

import copy

from build_presentation_acronym_registry import AcronymRegistry, acronym_for, validate_acronyms
from build_transactional_cx_registries import load, sha256, write

V25 = AcronymRegistry(number=25, prefix="AI-PT", source="presentation_registry/v24.json")
SEMANTIC_REGISTRY_VERSION = "keel.semantic_selector_registry.v23"

_HEALTHCARE_EVIDENCE = [
    "record_identity",
    "authorization",
    "approval",
    "relationship",
    "limits",
    "dispatch",
    "provider_outcome",
    "evidence_scope",
]

ADDED_PROFILES = [
    {
        "semantic_id": "keel.action.healthcare_patient_mailing_address_update.v1",
        "presentation_profile_id": "healthcare_patient_mailing_address_update.r1",
        "customer_title": "AI Permit-to-Update-Patient-Address",
        "type_definition": (
            "Exact authorization to replace one verified synthetic patient's complete mailing address "
            "without changing clinical fields"
        ),
        "leading_fields": [
            {"field": "resource", "label": "Synthetic patient record"},
            {"field": "provider", "label": "Aidbox FHIR sandbox"},
            {"field": "request_digest", "label": "Request digest"},
        ],
        "evidence_sections": list(_HEALTHCARE_EVIDENCE),
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "identity_coverage_or_care_of_a_real_patient",
            "legal_or_business_correctness_of_the_requested_action",
        ],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    },
    {
        "semantic_id": "keel.action.healthcare_appointment_reschedule.v1",
        "presentation_profile_id": "healthcare_appointment_reschedule.r1",
        "customer_title": "AI Permit-to-Reschedule-Appointment",
        "type_definition": (
            "Exact authorization to move one booked synthetic appointment to one free slot on the same schedule"
        ),
        "leading_fields": [
            {"field": "resource", "label": "Synthetic appointment"},
            {"field": "provider", "label": "Aidbox FHIR sandbox"},
            {"field": "request_digest", "label": "Request digest"},
        ],
        "evidence_sections": list(_HEALTHCARE_EVIDENCE),
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "identity_coverage_or_care_of_a_real_patient",
            "legal_or_business_correctness_of_the_requested_action",
        ],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    },
    {
        "semantic_id": "keel.action.healthcare_records_release.v1",
        "presentation_profile_id": "healthcare_records_release.r1",
        "customer_title": "AI Permit-to-Release-Records",
        "type_definition": (
            "Exact authorization to release one defined synthetic document set to one validated external recipient"
        ),
        "leading_fields": [
            {"field": "resource", "label": "Document set"},
            {"field": "recipient", "label": "External recipient"},
            {"field": "provider", "label": "Aidbox FHIR sandbox"},
            {"field": "request_digest", "label": "Request digest"},
        ],
        "evidence_sections": list(_HEALTHCARE_EVIDENCE),
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "identity_coverage_or_care_of_a_real_patient",
            "legal_or_business_correctness_of_the_requested_action",
        ],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    },
]


def build_registry() -> dict:
    registry = copy.deepcopy(load(V25.source))
    registry["$schema"] = f"./v{V25.number}.schema.json"
    registry["version"] = V25.version
    registry["semantic_registry_version"] = SEMANTIC_REGISTRY_VERSION
    for added in ADDED_PROFILES:
        profile = copy.deepcopy(added)
        acronym = acronym_for(profile, V25.prefix)
        if acronym is not None:
            profile["acronym"] = acronym
        registry["profiles"].append(profile)
    validate_acronyms(registry, V25)
    return registry


def build_schema() -> dict:
    schema = copy.deepcopy(load(V25.source_schema))
    schema["$id"] = f"https://github.com/keelapi/keel-permit/presentation_registry/v{V25.number}.schema.json"
    schema["title"] = f"Keel Permit presentation registry v{V25.number}"
    schema["properties"]["version"]["const"] = V25.version
    schema["properties"]["semantic_registry_version"]["const"] = SEMANTIC_REGISTRY_VERSION
    return schema


def main() -> None:
    write(V25.target, build_registry())
    write(V25.target_schema, build_schema())
    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in (
        (f"keel.permit.presentation_registry.v{V25.number}", V25.target),
        (f"keel.permit.presentation_registry.v{V25.number}.schema", V25.target_schema),
    ):
        value = {"id": artifact_id, "path": path, "sha256": sha256(path)}
        if path in existing:
            existing[path].update(value)
        else:
            manifest["artifacts"].append(value)
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
