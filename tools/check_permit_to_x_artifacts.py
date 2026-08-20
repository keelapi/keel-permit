#!/usr/bin/env python3
"""Validate the bounded Work and Permit-to-X public contract artifacts."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
VERDICTS = {
    "supported",
    "disproved",
    "insufficient_evidence",
    "unverifiable_scope",
}
WORK_CLAIMS = {
    "permit.work_authority_manifest.v1",
    "permit.work_child_containment.v1",
    "permit_chain.execution_authorized_at_boundary.v1",
    "permit.work_value_conservation.v1",
}
WORK_V2_CLAIMS = {
    "permit.work_authority_manifest.v2",
    "permit.work_child_containment.v2",
    "permit_chain.execution_authorized_at_boundary.v2",
    "permit.work_value_conservation.v2",
    "permit.work_exact_review.v1",
}
UNIVERSAL_CLAIMS = {
    "permit.type.v1",
    "permit.exact_target.v1",
    "permit.material_request.v1",
    "permit.valid_at_dispatch.v1",
    "permit.revocation_at_dispatch.v1",
    "permit.enforced_at_certified_boundary.v1",
    "permit.bounded_use.v1",
    "permit.single_use.v1",
    "permit.replay_prevented.v1",
    "permit.idempotency_bound.v1",
    "provider.receipt_state.v1",
    "provider.rejected.v1",
    "provider.accepted.v1",
    "provider.completed.v1",
}
CONSEQUENCE_EXACT_CLAIMS = {
    "permit.generate_text_exact_request.v1",
    "permit.refund_original_payment_bound.v1",
}
ENFORCEMENT_REGIME_CLAIMS = {
    "permit.enforcement_regime_at_issuance.v1",
    "permit.enforcement_regime_at_dispatch.v1",
}
TRUSTED_SOURCE_KINDS = {
    "work_request_server_reconciled",
    "action_verb_execute",
    "realtime_session_service",
    "agent_delegation_service",
    "telephony_origination_service",
}
POPULATION_PATHS = {
    "work_authorities": "authorities",
    "child_permits": "child_permits",
    "work_value_events": "value_events",
    "lifecycle_events": "lifecycle_events",
}


class ContractFailure(RuntimeError):
    """Raised for a contract validation failure."""


def load_json(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    # These vectors use JSON values that serialize identically under JCS and
    # Python's sorted compact JSON profile (no floats or non-ASCII edge cases).
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def one_entry(
    values: list[dict[str, Any]],
    *,
    key: str,
    expected: str,
) -> dict[str, Any]:
    matches = [
        value
        for value in values
        if isinstance(value, dict) and value.get(key) == expected
    ]
    if len(matches) != 1:
        raise ContractFailure(f"expected exactly one {key}={expected}")
    return matches[0]


def schema_registry() -> Registry:
    registry = Registry()
    schema_paths = list((ROOT / "schemas").glob("*.schema.json"))
    schema_paths.extend(
        [
            ROOT / "semantic_registry/v1.schema.json",
            ROOT / "semantic_registry/v2.schema.json",
            ROOT / "semantic_registry/v3.schema.json",
            ROOT / "semantic_registry/v4.schema.json",
            ROOT / "semantic_registry/v5.schema.json",
            ROOT / "semantic_registry/v6.schema.json",
            ROOT / "semantic_registry/v7.schema.json",
            ROOT / "semantic_registry/v8.schema.json",
            ROOT / "presentation_registry/v1.schema.json",
            ROOT / "presentation_registry/v2.schema.json",
            ROOT / "presentation_registry/v3.schema.json",
            ROOT / "presentation_registry/v4.schema.json",
            ROOT / "presentation_registry/v5.schema.json",
            ROOT / "presentation_registry/v6.schema.json",
            ROOT / "presentation_registry/v7.schema.json",
            ROOT / "consequence_registry/v1.schema.json",
            ROOT / "consequence_registry/v2.schema.json",
            ROOT / "consequence_registry/v3.schema.json",
            ROOT / "fact_profiles/v1.schema.json",
            ROOT / "fact_profiles/v2.schema.json",
            ROOT / "fact_profiles/v3.schema.json",
            ROOT / "fact_profiles/v4.schema.json",
            ROOT / "fact_profiles/v5.schema.json",
            ROOT / "fact_profiles/v6.schema.json",
        ]
    )
    for path in sorted(schema_paths):
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            registry = registry.with_resource(schema_id, Resource.from_contents(schema))
    return registry


def validate_instance(
    instance: Any,
    schema_path: str,
    registry: Registry,
    label: str,
) -> None:
    schema = load_json(schema_path)
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ContractFailure(f"{label} fails {schema_path} at {location}: {first.message}")


def entry_matches(entry: dict[str, Any], candidate: dict[str, Any]) -> bool:
    if entry.get("release_state") not in {"eligible", "generic_qualified"}:
        return False
    if candidate.get("trusted_source_kind") not in entry["trusted_source_kinds"]:
        return False
    if candidate.get("permit_product") in entry["excluded_permit_products"]:
        return False
    match = entry["match"]
    if match.get("action_names") and candidate.get("action_name") not in match["action_names"]:
        return False
    if match.get("operations") and candidate.get("operation") not in match["operations"]:
        return False
    if candidate.get("chain_role") not in match["allowed_chain_roles"]:
        return False
    if (
        "required_surfaces" in match
        and candidate.get("governed_surface") not in match["required_surfaces"]
    ):
        return False
    required_evidence = set(match.get("required_evidence_capabilities", []))
    return required_evidence.issubset(set(candidate.get("evidence_capabilities", [])))


def select_semantic(
    semantic_registry: dict[str, Any],
    candidate: dict[str, Any],
) -> tuple[str | None, str | None]:
    if candidate.get("permit_product") == "cost_permit":
        return None, "cost_permit_unchanged"
    matches = [
        entry["semantic_id"]
        for entry in semantic_registry["entries"]
        if entry_matches(entry, candidate)
    ]
    if len(matches) > 1:
        return None, "registry_ambiguous"
    if len(matches) == 1:
        return matches[0], None
    if candidate.get("trusted_source_kind") not in TRUSTED_SOURCE_KINDS:
        return None, "unclassified_action_request"
    return None, "generic_ai_permit"


def validate_semantics_and_presentation(registry: Registry) -> None:
    semantics = load_json("semantic_registry/v1.json")
    semantics_v2 = load_json("semantic_registry/v2.json")
    semantics_v3 = load_json("semantic_registry/v3.json")
    semantics_v4 = load_json("semantic_registry/v4.json")
    semantics_v5 = load_json("semantic_registry/v5.json")
    semantics_v6 = load_json("semantic_registry/v6.json")
    semantics_v7 = load_json("semantic_registry/v7.json")
    presentations = load_json("presentation_registry/v1.json")
    presentations_v2 = load_json("presentation_registry/v2.json")
    presentations_v3 = load_json("presentation_registry/v3.json")
    presentations_v4 = load_json("presentation_registry/v4.json")
    presentations_v5 = load_json("presentation_registry/v5.json")
    presentations_v6 = load_json("presentation_registry/v6.json")
    validate_instance(
        semantics,
        "semantic_registry/v1.schema.json",
        registry,
        "semantic registry",
    )
    validate_instance(
        semantics_v2,
        "semantic_registry/v2.schema.json",
        registry,
        "semantic registry v2",
    )
    validate_instance(
        semantics_v3,
        "semantic_registry/v3.schema.json",
        registry,
        "semantic registry v3",
    )
    validate_instance(
        semantics_v4,
        "semantic_registry/v4.schema.json",
        registry,
        "semantic registry v4",
    )
    validate_instance(
        semantics_v5,
        "semantic_registry/v5.schema.json",
        registry,
        "semantic registry v5",
    )
    validate_instance(
        semantics_v6,
        "semantic_registry/v6.schema.json",
        registry,
        "semantic registry v6",
    )
    validate_instance(
        semantics_v7,
        "semantic_registry/v7.schema.json",
        registry,
        "semantic registry v7",
    )
    validate_instance(
        presentations,
        "presentation_registry/v1.schema.json",
        registry,
        "presentation registry",
    )
    validate_instance(
        presentations_v2,
        "presentation_registry/v2.schema.json",
        registry,
        "presentation registry v2",
    )
    validate_instance(
        presentations_v3,
        "presentation_registry/v3.schema.json",
        registry,
        "presentation registry v3",
    )
    validate_instance(
        presentations_v4,
        "presentation_registry/v4.schema.json",
        registry,
        "presentation registry v4",
    )
    validate_instance(
        presentations_v5,
        "presentation_registry/v5.schema.json",
        registry,
        "presentation registry v5",
    )
    validate_instance(
        presentations_v6,
        "presentation_registry/v6.schema.json",
        registry,
        "presentation registry v6",
    )

    latest_semantic_ids = [entry["semantic_id"] for entry in semantics_v7["entries"]]
    latest_profile_ids = [
        profile["presentation_profile_id"]
        for profile in presentations_v6["profiles"]
    ]
    if len(latest_semantic_ids) != len(set(latest_semantic_ids)):
        raise ContractFailure("semantic registry v7 contains duplicate semantic ids")
    if len(latest_profile_ids) != len(set(latest_profile_ids)):
        raise ContractFailure("presentation registry v6 contains duplicate profile ids")
    if {profile["semantic_id"] for profile in presentations_v6["profiles"]} != set(
        latest_semantic_ids
    ):
        raise ContractFailure(
            "presentation registry v6 must cover semantic registry v7 exactly"
        )

    v4_semantic_ids = {entry["semantic_id"] for entry in semantics_v4["entries"]}
    if {profile["semantic_id"] for profile in presentations_v3["profiles"]} != (
        v4_semantic_ids
    ):
        raise ContractFailure(
            "historical presentation registry v3 must cover semantic registry v4 exactly"
        )
    if {profile["semantic_id"] for profile in presentations_v2["profiles"]} != set(
        v4_semantic_ids
    ):
        raise ContractFailure(
            "historical presentation registry v2 must cover semantic registry v4 exactly"
        )

    semantic_ids = [entry["semantic_id"] for entry in semantics["entries"]]
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("semantic registry contains duplicate semantic_id values")
    profile_ids = [profile["presentation_profile_id"] for profile in presentations["profiles"]]
    if len(profile_ids) != len(set(profile_ids)):
        raise ContractFailure("presentation registry contains duplicate profile ids")
    presented_semantics = {profile["semantic_id"] for profile in presentations["profiles"]}
    if presented_semantics != set(semantic_ids):
        raise ContractFailure("presentation profiles must cover the semantic registry exactly")
    if not all("cost_permit" in entry["excluded_permit_products"] for entry in semantics["entries"]):
        raise ContractFailure("every initial semantic entry must preserve the cost-permit carve-out")

    allowed_fields = set(presentations_v6["allowed_leading_fields"])
    allowed_sections = set(presentations_v6["allowed_evidence_sections"])
    forbidden_keys = {"claims", "verdict", "authorization_conditions", "policy_conditions"}
    for profile in presentations_v6["profiles"]:
        if any(field["field"] not in allowed_fields for field in profile["leading_fields"]):
            raise ContractFailure(f"{profile['presentation_profile_id']} uses an unknown leading field")
        if not set(profile["evidence_sections"]).issubset(allowed_sections):
            raise ContractFailure(f"{profile['presentation_profile_id']} uses an unknown evidence section")
        if forbidden_keys.intersection(profile):
            raise ContractFailure(f"{profile['presentation_profile_id']} contains authorizing/verdict fields")

    by_semantic = {profile["semantic_id"]: profile for profile in presentations["profiles"]}
    realtime = by_semantic["keel.context.realtime_session.v1"]
    if realtime["customer_title"] != "AI Permit — Realtime session":
        raise ContractFailure("realtime must remain generic-qualified")
    banned_realtime_words = {"Speak", "Talk", "Converse", "Call"}
    if any(word in realtime["customer_title"] for word in banned_realtime_words):
        raise ContractFailure("realtime presentation leaked an unadmitted speech/call title")

    selector_vectors = load_json("semantic_registry/test-vectors/v1.json")
    for vector in selector_vectors["vectors"]:
        actual_semantic, actual_fallback = select_semantic(semantics, vector["candidate"])
        expected = vector["expected"]
        if (actual_semantic, actual_fallback) != (
            expected["semantic_id"],
            expected["fallback"],
        ):
            raise ContractFailure(
                f"semantic vector {vector['id']} got {(actual_semantic, actual_fallback)!r}"
            )

    ambiguous = copy.deepcopy(semantics)
    ambiguous["entries"].append(copy.deepcopy(ambiguous["entries"][0]))
    candidate = selector_vectors["vectors"][0]["candidate"]
    if select_semantic(ambiguous, candidate) != (None, "registry_ambiguous"):
        raise ContractFailure("ambiguous selector registry did not fail closed")

    fallback_by_id = {
        profile["presentation_profile_id"]: profile
        for profile in presentations["fallback_profiles"]
    }
    presentation_vectors = load_json("presentation_registry/test-vectors/v1.json")
    for vector in presentation_vectors["vectors"]:
        profile = by_semantic.get(vector.get("semantic_id"))
        needs_fallback = profile is None or (
            vector.get("pinned_profile")
            and profile["presentation_profile_id"] != vector["pinned_profile"]
        )
        if needs_fallback:
            profile = fallback_by_id[vector["fallback"]]
        if profile["customer_title"] != vector["expected_title"]:
            raise ContractFailure(f"presentation vector {vector['id']} rendered the wrong title")

    non_interference = presentation_vectors["non_interference"]
    candidate = next(
        vector["candidate"]
        for vector in selector_vectors["vectors"]
        if vector["expected"]["semantic_id"] == non_interference["semantic_id"]
    )
    before = select_semantic(semantics, candidate)
    mutated_presentations = copy.deepcopy(presentations)
    next(
        profile
        for profile in mutated_presentations["profiles"]
        if profile["semantic_id"] == non_interference["semantic_id"]
    )["customer_title"] = non_interference["replacement_customer_title"]
    after = select_semantic(semantics, candidate)
    if before != after or digest(semantics) != digest(copy.deepcopy(semantics)):
        raise ContractFailure("presentation-only change interfered with semantic selection")

    consequence_registry = load_json("consequence_registry/v1.json")
    validate_instance(
        consequence_registry,
        "consequence_registry/v1.schema.json",
        registry,
        "consequence registry v1",
    )
    consequences = consequence_registry["consequences"]
    consequence_vectors = load_json("consequence_registry/test-vectors/v1.json")
    exact_consequence_vectors = load_json("consequence_registry/test-vectors/v2.json")
    latest_fact_registry = load_json("fact_profiles/v4.json")
    consequence_types = [item["consequence_type"] for item in consequences]
    consequence_semantics = [item["semantic_id"] for item in consequences]
    consequence_tools = [
        tool for item in consequences for tool in item["tool_names"]
    ]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry contains duplicate consequence types")
    if len(consequence_semantics) != len(set(consequence_semantics)):
        raise ContractFailure("consequence registry contains duplicate semantic ids")
    if len(consequence_tools) != len(set(consequence_tools)):
        raise ContractFailure("consequence registry contains overlapping tool names")
    base_semantics = {entry["semantic_id"] for entry in semantics_v4["entries"]}
    if base_semantics.intersection(consequence_semantics):
        raise ContractFailure("consequence registry redefines a historical semantic")
    by_v5_semantic = {entry["semantic_id"]: entry for entry in semantics_v5["entries"]}
    by_v4_presentation = {
        profile["semantic_id"]: profile for profile in presentations_v4["profiles"]
    }
    by_v6_semantic = {entry["semantic_id"]: entry for entry in semantics_v6["entries"]}
    by_v5_presentation = {
        profile["semantic_id"]: profile for profile in presentations_v5["profiles"]
    }
    by_latest_fact_profile = {
        profile["fact_profile_id"]: profile
        for profile in latest_fact_registry["profiles"]
    }
    database_facts_schema = load_json(
        "schemas/database-exact-facts-v1.schema.json"
    )
    database_facts_validator = jsonschema.Draft202012Validator(
        database_facts_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    vector_by_id = {
        vector["id"]: vector for vector in consequence_vectors["vectors"]
    }
    if set(vector_by_id) != set(consequence_types):
        raise ContractFailure("consequence vectors must cover every consequence exactly")
    exact_vector_by_id = {
        vector["id"]: vector for vector in exact_consequence_vectors["vectors"]
    }
    if set(exact_vector_by_id) != set(consequence_types):
        raise ContractFailure(
            "exact consequence vectors must cover every consequence exactly"
        )
    for consequence in consequences:
        consequence_type = consequence["consequence_type"]
        required_trust = {"connector_identity", "tool_contract"}
        if consequence_type.startswith(("payment.", "ledger.")):
            required_trust.add("gateway_preflight_hmac")
        if not required_trust.issubset(
            set(consequence["trusted_fact_requirements"])
        ):
            raise ContractFailure(
                f"{consequence['consequence_type']} omits connector trust requirements"
            )
        entry = by_v5_semantic.get(consequence["semantic_id"])
        profile = by_v4_presentation.get(consequence["semantic_id"])
        if entry is None or entry["match"].get("action_names") != consequence["tool_names"]:
            raise ContractFailure(
                f"{consequence['consequence_type']} did not generate its exact selector"
            )
        if profile is None or profile["customer_title"] != consequence["customer_title"]:
            raise ContractFailure(
                f"{consequence['consequence_type']} did not generate its presentation"
            )
        vector = vector_by_id[consequence["consequence_type"]]
        candidate = vector["candidate"]
        if select_semantic(semantics_v5, candidate) != (
            vector["expected_semantic_id"],
            None,
        ):
            raise ContractFailure(
                f"{consequence['consequence_type']} is not selected exactly once"
            )
        if profile["customer_title"] != vector["expected_title"]:
            raise ContractFailure(
                f"{consequence['consequence_type']} vector title drifted"
            )
        exact_vector = exact_vector_by_id[consequence["consequence_type"]]
        exact_entry = by_v6_semantic.get(consequence["semantic_id"])
        exact_profile = by_v5_presentation.get(consequence["semantic_id"])
        expected_fact_profile_id = exact_vector["expected_fact_profile_id"]
        fact_profile = by_latest_fact_profile.get(expected_fact_profile_id)
        if exact_entry is None or exact_entry.get("fact_profile_id") != (
            expected_fact_profile_id
        ):
            raise ContractFailure(
                f"{consequence['consequence_type']} lacks its exact fact profile"
            )
        if fact_profile is None or consequence["semantic_id"] not in fact_profile[
            "semantic_ids"
        ]:
            raise ContractFailure(
                f"{consequence['consequence_type']} fact profile is not semantic-bound"
            )
        if exact_profile is None or exact_profile["customer_title"] != (
            exact_vector["expected_title"]
        ):
            raise ContractFailure(
                f"{consequence['consequence_type']} exact presentation drifted"
            )
        if select_semantic(semantics_v6, exact_vector["candidate"]) != (
            exact_vector["expected_semantic_id"],
            None,
        ):
            raise ContractFailure(
                f"{consequence['consequence_type']} exact selector is ambiguous"
            )
        authorization_facts = exact_vector["valid_authorization_facts"]
        facts_errors = list(
            database_facts_validator.iter_errors(authorization_facts)
        )
        if facts_errors:
            raise ContractFailure(
                f"{consequence['consequence_type']} exact facts are invalid: "
                f"{facts_errors[0].message}"
            )
        if authorization_facts["fact_profile_id"] != expected_fact_profile_id:
            raise ContractFailure(
                f"{consequence['consequence_type']} vector fact profile drifted"
            )
        mismatched_facts = copy.deepcopy(authorization_facts)
        mismatched_facts["fact_profile_id"] = next(
            profile_id
            for profile_id in by_latest_fact_profile
            if profile_id.startswith("keel.facts.database_")
            and profile_id != expected_fact_profile_id
        )
        if database_facts_validator.is_valid(mismatched_facts):
            raise ContractFailure(
                f"{consequence['consequence_type']} accepted another action's fact profile"
            )

    consequence_registry_v2 = load_json("consequence_registry/v2.json")
    validate_instance(
        consequence_registry_v2,
        "consequence_registry/v2.schema.json",
        registry,
        "consequence registry v2",
    )
    latest_consequences = consequence_registry_v2["consequences"]
    if latest_consequences[: len(consequences)] != consequences:
        raise ContractFailure(
            "consequence registry v2 must preserve every v1 entry byte-for-value"
        )
    latest_types = [item["consequence_type"] for item in latest_consequences]
    latest_semantics = [item["semantic_id"] for item in latest_consequences]
    latest_tools = [
        tool for item in latest_consequences for tool in item["tool_names"]
    ]
    if len(latest_types) != len(set(latest_types)):
        raise ContractFailure("consequence registry v2 contains duplicate types")
    if len(latest_semantics) != len(set(latest_semantics)):
        raise ContractFailure("consequence registry v2 contains duplicate semantics")
    if len(latest_tools) != len(set(latest_tools)):
        raise ContractFailure("consequence registry v2 contains overlapping tools")

    exact_consequence_vectors_v3 = load_json(
        "consequence_registry/test-vectors/v3.json"
    )
    latest_vector_by_id = {
        vector["id"]: vector
        for vector in exact_consequence_vectors_v3["vectors"]
    }
    if set(latest_vector_by_id) != set(latest_types):
        raise ContractFailure(
            "v3 exact consequence vectors must cover consequence registry v2"
        )
    latest_fact_registry_v5 = load_json("fact_profiles/v5.json")
    latest_fact_by_id = {
        profile["fact_profile_id"]: profile
        for profile in latest_fact_registry_v5["profiles"]
    }
    by_v7_semantic = {
        entry["semantic_id"]: entry for entry in semantics_v7["entries"]
    }
    by_v6_presentation = {
        profile["semantic_id"]: profile
        for profile in presentations_v6["profiles"]
    }
    fact_validators = {
        path: jsonschema.Draft202012Validator(
            load_json(path),
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        )
        for path in {
            profile["facts_schema"]
            for profile in latest_fact_registry_v5["profiles"]
        }
    }
    for consequence in latest_consequences:
        consequence_type = consequence["consequence_type"]
        required_trust = {"connector_identity", "tool_contract"}
        if consequence_type.startswith(("payment.", "ledger.")):
            required_trust.add("gateway_preflight_hmac")
        if not required_trust.issubset(
            set(consequence["trusted_fact_requirements"])
        ):
            raise ContractFailure(
                f"{consequence_type} omits connector trust requirements"
            )
        vector = latest_vector_by_id[consequence_type]
        expected_profile_id = vector["expected_fact_profile_id"]
        entry = by_v7_semantic.get(consequence["semantic_id"])
        profile = latest_fact_by_id.get(expected_profile_id)
        presentation = by_v6_presentation.get(consequence["semantic_id"])
        if entry is None or entry.get("fact_profile_id") != expected_profile_id:
            raise ContractFailure(
                f"{consequence_type} lacks its v7 exact semantic binding"
            )
        if profile is None or consequence["semantic_id"] not in profile["semantic_ids"]:
            raise ContractFailure(
                f"{consequence_type} lacks its v5 fact-profile binding"
            )
        if presentation is None or presentation["customer_title"] != consequence[
            "customer_title"
        ]:
            raise ContractFailure(
                f"{consequence_type} lacks its v6 human presentation"
            )
        if select_semantic(semantics_v7, vector["candidate"]) != (
            consequence["semantic_id"],
            None,
        ):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in v7"
            )
        facts = vector["valid_authorization_facts"]
        validator = fact_validators[profile["facts_schema"]]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if facts.get("fact_profile_id") != expected_profile_id:
            raise ContractFailure(
                f"{consequence_type} vector fact profile drifted"
            )
        alternate_profiles = [
            candidate["fact_profile_id"]
            for candidate in latest_fact_registry_v5["profiles"]
            if candidate["facts_schema"] == profile["facts_schema"]
            and candidate["fact_profile_id"] != expected_profile_id
        ]
        if alternate_profiles:
            mismatched = copy.deepcopy(facts)
            mismatched["fact_profile_id"] = alternate_profiles[0]
            if validator.is_valid(mismatched):
                raise ContractFailure(
                    f"{consequence_type} accepted another action's fact profile"
                )
        action = facts["action"]
        adversarial_mutations = {
            "payment.invoice.pay": [
                ("invoice_status_before", "paid"),
                ("amount_minor", 0),
                ("connector_identity", "database.readwrite"),
                ("ledger_schema_version", "unexpected-cross-action-field"),
            ],
            "ledger.entry.record": [
                ("value_conserved", False),
                ("accounts_distinct", False),
                ("connector_identity", "payments"),
                ("invoice_status_before", "open"),
            ],
            "payment.reconciliation.record": [
                ("amounts_match", False),
                ("currencies_match", False),
                ("provider_outcome_state", "unknown"),
                ("expected_current_status", "reconciled"),
                ("invoice_state_digest", "sha256:" + "a" * 64),
            ],
        }.get(action, [])
        adversarial_mutations.extend(
            [
                ("preflight_observed_at", "not-a-time"),
                ("preflight_expires_at", "not-a-time"),
                ("preflight_snapshot_digest", "sha256:short"),
            ]
        )
        for field, value in adversarial_mutations:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )


def validate_transactional_cx_contract(registry: Registry) -> None:
    consequence_v2 = load_json("consequence_registry/v2.json")
    consequence_v3 = load_json("consequence_registry/v3.json")
    validate_instance(
        consequence_v3,
        "consequence_registry/v3.schema.json",
        registry,
        "consequence registry v3",
    )
    prior_consequences = consequence_v2["consequences"]
    consequences = consequence_v3["consequences"]
    if consequences[: len(prior_consequences)] != prior_consequences:
        raise ContractFailure(
            "consequence registry v3 must preserve every v2 entry byte-for-value"
        )

    facts_v5 = load_json("fact_profiles/v5.json")
    facts_v6 = load_json("fact_profiles/v6.json")
    semantics_v7 = load_json("semantic_registry/v7.json")
    semantics_v8 = load_json("semantic_registry/v8.json")
    presentations_v6 = load_json("presentation_registry/v6.json")
    presentations_v7 = load_json("presentation_registry/v7.json")
    vectors_v4 = load_json("consequence_registry/test-vectors/v4.json")

    validate_instance(
        facts_v6,
        "fact_profiles/v6.schema.json",
        registry,
        "fact profile registry v6",
    )
    validate_instance(
        semantics_v8,
        "semantic_registry/v8.schema.json",
        registry,
        "semantic registry v8",
    )
    validate_instance(
        presentations_v7,
        "presentation_registry/v7.schema.json",
        registry,
        "presentation registry v7",
    )
    if facts_v6["profiles"][: len(facts_v5["profiles"])] != facts_v5["profiles"]:
        raise ContractFailure("fact profile registry v6 is not an additive v5 extension")
    if semantics_v8["entries"][: len(semantics_v7["entries"])] != semantics_v7[
        "entries"
    ]:
        raise ContractFailure("semantic registry v8 is not an additive v7 extension")
    if presentations_v7["profiles"][: len(presentations_v6["profiles"])] != (
        presentations_v6["profiles"]
    ):
        raise ContractFailure("presentation registry v7 is not an additive v6 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v3 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v3 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v3 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v4["vectors"]}
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure(
            "v4 exact consequence vectors must cover consequence registry v3"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v6["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v8["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile
        for profile in presentations_v7["profiles"]
    }
    if len(profiles_by_id) != len(facts_v6["profiles"]):
        raise ContractFailure("fact profile registry v6 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v8["entries"]):
        raise ContractFailure("semantic registry v8 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v7["profiles"]):
        raise ContractFailure("presentation registry v7 contains duplicate semantics")

    schema_path = "schemas/transactional-cx-exact-facts-v1.schema.json"
    schema = load_json(schema_path)
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    previous_count = len(prior_consequences)
    cx_consequences = consequences[previous_count:]
    expected_titles = {
        "payment.refund": "AI Permit-to-Refund-Payment",
        "customer.credit.issue": "AI Permit-to-Issue-Account-Credit",
        "subscription.cancellation.schedule": (
            "AI Permit-to-Schedule-Subscription-Cancellation"
        ),
        "subscription.cancellation.withdraw": (
            "AI Permit-to-Withdraw-Subscription-Cancellation"
        ),
        "support.case.resolve": "AI Permit-to-Resolve-Support-Case",
    }
    for consequence in cx_consequences:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its CX fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        action = consequence["tool_names"][0]
        if presentation is None or presentation.get("customer_title") != expected_titles[
            action
        ]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if presentation.get("does_not_establish") != consequence.get(
            "does_not_establish"
        ):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get(
            "trusted_fact_requirements", []
        ):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if select_semantic(semantics_v8, vector["candidate"]) != (semantic_id, None):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in semantic v8"
            )

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        if action == "payment.refund":
            if facts["amount_minor"] > facts["refundable_amount_minor_before"]:
                raise ContractFailure("refund vector exceeds provider-observed remainder")
            if facts["refund_application_fee"] or facts["reverse_transfer"]:
                raise ContractFailure("refund vector expands into unmodeled Connect effects")
        elif action == "customer.credit.issue":
            if facts["provider_amount_minor"] != -facts["amount_minor"]:
                raise ContractFailure("account-credit sign invariant is not exact")
            expected = facts["customer_balance_before_minor"] - facts["amount_minor"]
            if facts["expected_customer_balance_after_minor"] != expected:
                raise ContractFailure("account-credit expected balance is inconsistent")
        elif action == "subscription.cancellation.schedule":
            if facts["cancel_at_period_end_before"] is not False or facts[
                "cancel_at_period_end_requested"
            ] is not True:
                raise ContractFailure("cancellation schedule transition is not false-to-true")
        elif action == "subscription.cancellation.withdraw":
            if facts["cancel_at_period_end_before"] is not True or facts[
                "cancel_at_period_end_requested"
            ] is not False:
                raise ContractFailure("cancellation withdrawal is not true-to-false")
            if facts["canceled_at_before"] is not None or facts["ended_at_before"] is not None:
                raise ContractFailure("withdrawal vector describes an ended subscription")
        elif action == "support.case.resolve":
            if facts["current_stage_state"] != "OPEN" or facts[
                "requested_stage_state"
            ] != "CLOSED":
                raise ContractFailure("support resolution is not OPEN-to-CLOSED")

        adversarial = copy.deepcopy(facts)
        adversarial["fact_profile_id"] = next(
            item["fact_profile_id"]
            for item in facts_v6["profiles"]
            if item["fact_profile_id"] != profile_id
            and item["facts_schema"] == schema_path
        )
        if validator.is_valid(adversarial):
            raise ContractFailure(f"{consequence_type} accepts another CX fact profile")

        common_mutations = [
            ("preflight_expires_at", "not-a-time"),
            ("preflight_snapshot_digest", "sha256:short"),
            (
                "connector_identity",
                "hubspot" if facts["connector_identity"] == "stripe" else "stripe",
            ),
        ]
        action_mutations = {
            "payment.refund": [("amount_minor", 0), ("reverse_transfer", True)],
            "customer.credit.issue": [
                ("provider_amount_minor", 1500),
                ("credit_direction", "customer_debit"),
            ],
            "subscription.cancellation.schedule": [
                ("cancel_at_period_end_before", True),
                ("cancel_at_period_end_requested", False),
            ],
            "subscription.cancellation.withdraw": [
                ("cancel_at_period_end_before", False),
                ("canceled_at_before", "2026-08-10T12:00:00Z"),
            ],
            "support.case.resolve": [
                ("current_stage_state", "CLOSED"),
                ("requested_stage_state", "OPEN"),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v8["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v8 and fact profile registry v6 must bind exactly"
        )


def validate_release_contract(registry: Registry) -> None:
    consequence_v3 = load_json("consequence_registry/v3.json")
    consequence_v4 = load_json("consequence_registry/v4.json")
    validate_instance(
        consequence_v4,
        "consequence_registry/v4.schema.json",
        registry,
        "consequence registry v4",
    )
    prior_consequences = consequence_v3["consequences"]
    consequences = consequence_v4["consequences"]
    if consequences[: len(prior_consequences)] != prior_consequences:
        raise ContractFailure(
            "consequence registry v4 must preserve every v3 entry byte-for-value"
        )

    facts_v6 = load_json("fact_profiles/v6.json")
    facts_v7 = load_json("fact_profiles/v7.json")
    semantics_v8 = load_json("semantic_registry/v8.json")
    semantics_v9 = load_json("semantic_registry/v9.json")
    presentations_v7 = load_json("presentation_registry/v7.json")
    presentations_v8 = load_json("presentation_registry/v8.json")
    vectors_v5 = load_json("consequence_registry/test-vectors/v5.json")

    validate_instance(
        facts_v7,
        "fact_profiles/v7.schema.json",
        registry,
        "fact profile registry v7",
    )
    validate_instance(
        semantics_v9,
        "semantic_registry/v9.schema.json",
        registry,
        "semantic registry v9",
    )
    validate_instance(
        presentations_v8,
        "presentation_registry/v8.schema.json",
        registry,
        "presentation registry v8",
    )
    if facts_v7["profiles"][: len(facts_v6["profiles"])] != facts_v6["profiles"]:
        raise ContractFailure("fact profile registry v7 is not an additive v6 extension")
    if semantics_v9["entries"][: len(semantics_v8["entries"])] != semantics_v8[
        "entries"
    ]:
        raise ContractFailure("semantic registry v9 is not an additive v8 extension")
    if presentations_v8["profiles"][: len(presentations_v7["profiles"])] != (
        presentations_v7["profiles"]
    ):
        raise ContractFailure("presentation registry v8 is not an additive v7 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v4 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v4 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v4 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v5["vectors"]}
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure(
            "v5 exact consequence vectors must cover consequence registry v4"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v7["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v9["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile
        for profile in presentations_v8["profiles"]
    }
    if len(profiles_by_id) != len(facts_v7["profiles"]):
        raise ContractFailure("fact profile registry v7 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v9["entries"]):
        raise ContractFailure("semantic registry v9 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v8["profiles"]):
        raise ContractFailure("presentation registry v8 contains duplicate semantics")

    schema_path = "schemas/release-exact-facts-v1.schema.json"
    schema = load_json(schema_path)
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    previous_count = len(prior_consequences)
    release_consequences = consequences[previous_count:]
    expected_titles = {
        "repository.pull_request.merge": "AI Permit-to-Merge-Pull-Request",
        "deployment.commit.deploy": "AI Permit-to-Deploy-Commit",
        "deployment.rollback": "AI Permit-to-Roll-Back-Deployment",
    }

    def release_invariants_hold(facts: dict[str, Any]) -> bool:
        action = facts.get("action")
        if action == "repository.pull_request.merge":
            return (
                facts.get("observed_approving_reviews", 0)
                >= facts.get("required_approving_reviews", 1)
                and facts.get("required_status_checks_count", 0) >= 1
                and facts.get("required_status_checks_state") == "success"
                and facts.get("pull_request_state") == "open"
                and facts.get("mergeable_state") == "clean"
            )
        if action == "deployment.commit.deploy":
            return (
                facts.get("artifact_revision_sha") == facts.get("source_commit_sha")
                and facts.get("current_image_digest") != facts.get("target_image_digest")
                and facts.get("current_config_digest") != facts.get("target_config_digest")
                and facts.get("source_commit_signature_verified") is True
                and facts.get("artifact_revision_matches_source_commit") is True
            )
        if action == "deployment.rollback":
            return (
                facts.get("current_image_digest")
                != facts.get("rollback_target_image_digest")
                and facts.get("current_config_digest")
                != facts.get("rollback_target_config_digest")
                and facts.get("current_release_instance_id")
                != facts.get("prior_release_instance_id")
            )
        return False

    for consequence in release_consequences:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its release fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        action = consequence["tool_names"][0]
        if presentation is None or presentation.get("customer_title") != expected_titles[
            action
        ]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if presentation.get("does_not_establish") != consequence.get(
            "does_not_establish"
        ):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get(
            "trusted_fact_requirements", []
        ):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if select_semantic(semantics_v9, vector["candidate"]) != (semantic_id, None):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in semantic v9"
            )

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not release_invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} vector violates release invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        adversarial_profile = copy.deepcopy(facts)
        adversarial_profile["fact_profile_id"] = next(
            item["fact_profile_id"]
            for item in facts_v7["profiles"]
            if item["fact_profile_id"] != profile_id
            and item["facts_schema"] == schema_path
        )
        if validator.is_valid(adversarial_profile):
            raise ContractFailure(
                f"{consequence_type} accepts another release fact profile"
            )

        common_mutations = [
            ("preflight_expires_at", "not-a-time"),
            ("preflight_snapshot_digest", "sha256:short"),
            (
                "connector_identity",
                "fly" if facts["connector_identity"] == "github" else "github",
            ),
        ]
        action_mutations = {
            "repository.pull_request.merge": [
                ("head_commit_sha", "short"),
                ("draft", True),
                ("strict_status_checks", False),
                ("observed_approving_reviews", 0),
            ],
            "deployment.commit.deploy": [
                ("artifact_revision_sha", "c" * 40),
                (
                    "target_image_digest",
                    facts.get("current_image_digest", "sha256:" + "0" * 64),
                ),
                ("machine_lease_required", False),
                ("config_delta", "arbitrary"),
            ],
            "deployment.rollback": [
                (
                    "rollback_target_image_digest",
                    facts.get("current_image_digest", "sha256:" + "0" * 64),
                ),
                (
                    "rollback_target_config_digest",
                    facts.get("current_config_digest", "sha256:" + "0" * 64),
                ),
                ("release_ledger_version", "untrusted"),
                ("machine_lease_required", False),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and release_invariants_hold(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v9["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v9 and fact profile registry v7 must bind exactly"
        )


def validate_identity_security_contract(registry: Registry) -> None:
    consequence_v4 = load_json("consequence_registry/v4.json")
    consequence_v5 = load_json("consequence_registry/v5.json")
    validate_instance(
        consequence_v5,
        "consequence_registry/v5.schema.json",
        registry,
        "consequence registry v5",
    )
    prior_consequences = consequence_v4["consequences"]
    consequences = consequence_v5["consequences"]
    if consequences[: len(prior_consequences)] != prior_consequences:
        raise ContractFailure(
            "consequence registry v5 must preserve every v4 entry byte-for-value"
        )

    facts_v7 = load_json("fact_profiles/v7.json")
    facts_v8 = load_json("fact_profiles/v8.json")
    semantics_v9 = load_json("semantic_registry/v9.json")
    semantics_v10 = load_json("semantic_registry/v10.json")
    presentations_v8 = load_json("presentation_registry/v8.json")
    presentations_v9 = load_json("presentation_registry/v9.json")
    vectors_v6 = load_json("consequence_registry/test-vectors/v6.json")

    validate_instance(
        facts_v8,
        "fact_profiles/v8.schema.json",
        registry,
        "fact profile registry v8",
    )
    validate_instance(
        semantics_v10,
        "semantic_registry/v10.schema.json",
        registry,
        "semantic registry v10",
    )
    validate_instance(
        presentations_v9,
        "presentation_registry/v9.schema.json",
        registry,
        "presentation registry v9",
    )
    if facts_v8["profiles"][: len(facts_v7["profiles"])] != facts_v7["profiles"]:
        raise ContractFailure("fact profile registry v8 is not an additive v7 extension")
    if semantics_v10["entries"][: len(semantics_v9["entries"])] != semantics_v9[
        "entries"
    ]:
        raise ContractFailure("semantic registry v10 is not an additive v9 extension")
    if presentations_v9["profiles"][: len(presentations_v8["profiles"])] != (
        presentations_v8["profiles"]
    ):
        raise ContractFailure("presentation registry v9 is not an additive v8 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v5 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v5 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v5 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v6["vectors"]}
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure(
            "v6 exact consequence vectors must cover consequence registry v5"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v8["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v10["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile for profile in presentations_v9["profiles"]
    }
    if len(profiles_by_id) != len(facts_v8["profiles"]):
        raise ContractFailure("fact profile registry v8 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v10["entries"]):
        raise ContractFailure("semantic registry v10 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v9["profiles"]):
        raise ContractFailure("presentation registry v9 contains duplicate semantics")

    schema_path = "schemas/identity-security-exact-facts-v1.schema.json"
    schema = load_json(schema_path)
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    identity_consequences = consequences[len(prior_consequences) :]
    expected_titles = {
        "identity.mfa.reset": "AI Permit-to-Reset-MFA",
        "identity.sessions.revoke": "AI Permit-to-Revoke-Sessions",
        "identity.disable": "AI Permit-to-Disable-Identity",
        "identity.group_access.grant": "AI Permit-to-Grant-Group-Access",
        "identity.group_access.remove": "AI Permit-to-Remove-Group-Access",
        "security.indicator.block": "AI Permit-to-Block-Indicator",
    }

    def invariants_hold(facts: dict[str, Any]) -> bool:
        action = facts.get("action")
        if action == "identity.mfa.reset":
            return (
                facts.get("enrolled_factor_count", 0) >= 1
                and facts.get("reset_scope") == "all_enrolled_factors"
            )
        if action == "identity.sessions.revoke":
            return (
                facts.get("revoke_oauth_tokens") is True
                and facts.get("active_sessions_enumerable") is False
            )
        if action == "identity.disable":
            return (
                facts.get("current_user_status") == "ACTIVE"
                and facts.get("target_user_status") == "DEPROVISIONED"
                and facts.get("destructive_deprovisioning_acknowledged") is True
            )
        if action == "identity.group_access.grant":
            return (
                facts.get("current_membership") is False
                and facts.get("target_membership") is True
                and facts.get("projected_group_member_count")
                == facts.get("current_group_member_count", -1) + 1
            )
        if action == "identity.group_access.remove":
            return (
                facts.get("current_membership") is True
                and facts.get("target_membership") is False
                and facts.get("target_is_last_privileged_member") is False
                and facts.get("projected_group_member_count")
                == facts.get("current_group_member_count", -1) - 1
            )
        if action == "security.indicator.block":
            return (
                facts.get("zone_status") == "active"
                and facts.get("current_matching_rule_count") == 0
                and facts.get("target_action") == "block"
                and facts.get("rule_enabled") is True
                and facts.get("projected_rules_count")
                == facts.get("current_rules_count", -1) + 1
            )
        return False

    for consequence in identity_consequences:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its identity/security fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        action = consequence["tool_names"][0]
        if presentation is None or presentation.get("customer_title") != expected_titles[action]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if presentation.get("does_not_establish") != consequence.get("does_not_establish"):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get("trusted_fact_requirements", []):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if select_semantic(semantics_v10, vector["candidate"]) != (semantic_id, None):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in semantic v10"
            )

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} vector violates identity/security invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        common_mutations = [
            ("preflight_expires_at", "not-a-time"),
            ("preflight_snapshot_digest", "sha256:short"),
            ("max_uses", 2),
        ]
        action_mutations = {
            "identity.mfa.reset": [("enrolled_factor_count", 0)],
            "identity.sessions.revoke": [("revoke_oauth_tokens", False)],
            "identity.disable": [("destructive_deprovisioning_acknowledged", False)],
            "identity.group_access.grant": [("current_membership", True)],
            "identity.group_access.remove": [("target_is_last_privileged_member", True)],
            "security.indicator.block": [
                ("current_matching_rule_count", 1),
                ("target_action", "allow"),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v10["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v10 and fact profile registry v8 must bind exactly"
        )


def validate_coding_workspace_contract(registry: Registry) -> None:
    consequence_v5 = load_json("consequence_registry/v5.json")
    consequence_v6 = load_json("consequence_registry/v6.json")
    validate_instance(
        consequence_v6,
        "consequence_registry/v6.schema.json",
        registry,
        "consequence registry v6",
    )
    prior_consequences = consequence_v5["consequences"]
    consequences = consequence_v6["consequences"]
    if consequences[: len(prior_consequences)] != prior_consequences:
        raise ContractFailure(
            "consequence registry v6 must preserve every v5 entry byte-for-value"
        )

    facts_v8 = load_json("fact_profiles/v8.json")
    facts_v9 = load_json("fact_profiles/v9.json")
    semantics_v10 = load_json("semantic_registry/v10.json")
    semantics_v11 = load_json("semantic_registry/v11.json")
    presentations_v9 = load_json("presentation_registry/v9.json")
    presentations_v10 = load_json("presentation_registry/v10.json")
    vectors_v6 = load_json("consequence_registry/test-vectors/v6.json")
    vectors_v7 = load_json("consequence_registry/test-vectors/v7.json")

    validate_instance(facts_v9, "fact_profiles/v9.schema.json", registry, "fact profile registry v9")
    validate_instance(
        semantics_v11,
        "semantic_registry/v11.schema.json",
        registry,
        "semantic registry v11",
    )
    validate_instance(
        presentations_v10,
        "presentation_registry/v10.schema.json",
        registry,
        "presentation registry v10",
    )
    if facts_v9["profiles"][: len(facts_v8["profiles"])] != facts_v8["profiles"]:
        raise ContractFailure("fact profile registry v9 is not an additive v8 extension")
    if semantics_v11["entries"][: len(semantics_v10["entries"])] != semantics_v10["entries"]:
        raise ContractFailure("semantic registry v11 is not an additive v10 extension")
    if presentations_v10["profiles"][: len(presentations_v9["profiles"])] != presentations_v9["profiles"]:
        raise ContractFailure("presentation registry v10 is not an additive v9 extension")
    if vectors_v7["vectors"][: len(vectors_v6["vectors"])] != vectors_v6["vectors"]:
        raise ContractFailure("consequence vectors v7 are not an additive v6 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v6 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v6 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v6 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v7["vectors"]}
    if len(vectors_by_id) != len(vectors_v7["vectors"]):
        raise ContractFailure("consequence vectors v7 contain duplicate ids")
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure("v7 exact consequence vectors must cover consequence registry v6")
    profiles_by_id = {profile["fact_profile_id"]: profile for profile in facts_v9["profiles"]}
    semantics_by_id = {entry["semantic_id"]: entry for entry in semantics_v11["entries"]}
    presentations_by_id = {
        profile["semantic_id"]: profile for profile in presentations_v10["profiles"]
    }
    if len(profiles_by_id) != len(facts_v9["profiles"]):
        raise ContractFailure("fact profile registry v9 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v11["entries"]):
        raise ContractFailure("semantic registry v11 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v10["profiles"]):
        raise ContractFailure("presentation registry v10 contains duplicate semantics")

    schema_path = "schemas/coding-workspace-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path),
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    coding_consequences = consequences[len(prior_consequences) :]
    expected_actions = {
        "code.package.install.v1": "code.package.install",
        "repository.branch.push.v1": "repository.branch.push",
        "repository.pull_request.create.v1": "repository.pull_request.create",
    }
    expected_titles = {
        "code.package.install": "AI Permit-to-Install-Package",
        "repository.branch.push": "AI Permit-to-Push-Branch",
        "repository.pull_request.create": "AI Permit-to-Create-Pull-Request",
    }
    if {
        item["consequence_type"]: item["tool_names"][0]
        for item in coding_consequences
    } != expected_actions:
        raise ContractFailure("consequence registry v6 coding action set drifted")

    def invariants_hold(facts: dict[str, Any]) -> bool:
        action = facts.get("action")
        if action == "code.package.install":
            return (
                facts.get("connector_identity") == "npm"
                and facts.get("workspace_is_disposable") is True
                and facts.get("package_allowlisted") is True
                and facts.get("registry_origin") == "https://registry.npmjs.org"
                and facts.get("target_dependency_version") != facts.get("current_dependency_version")
                and facts.get("package_lock_present") is True
                and facts.get("install_mode") == "save_exact"
                and facts.get("lifecycle_scripts_disabled") is True
            )
        if action == "repository.branch.push":
            return (
                facts.get("connector_identity") == "github"
                and facts.get("base_branch_protected") is True
                and facts.get("target_branch_exists") is False
                and facts.get("target_branch_protected") is False
                and facts.get("base_branch") != facts.get("target_branch")
                and 1 <= facts.get("workspace_file_count", 0) <= 32
                and 1 <= facts.get("workspace_total_bytes", 0) <= 1_048_576
                and facts.get("protected_path_change_count") == 0
                and facts.get("push_mode") == "create_ref_only"
                and facts.get("force_push") is False
            )
        if action == "repository.pull_request.create":
            return (
                facts.get("connector_identity") == "github"
                and facts.get("head_ref_exists") is True
                and facts.get("base_branch_protected") is True
                and facts.get("same_repository") is True
                and facts.get("head_branch") != facts.get("base_branch")
                and facts.get("head_commit_sha") != facts.get("base_commit_sha")
                and facts.get("compare_status") == "ahead"
                and facts.get("ahead_by", 0) >= 1
                and facts.get("changed_files_count", 0) >= 1
                and facts.get("protected_path_change_count") == 0
                and facts.get("existing_open_pull_request_count") == 0
                and facts.get("merge_authorized") is False
            )
        return False

    for consequence in coding_consequences:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        action = consequence["tool_names"][0]
        if vector.get("expected_semantic_id") != semantic_id:
            raise ContractFailure(f"{consequence_type} vector semantic drifted")
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its coding fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        if presentation is None or presentation.get("customer_title") != expected_titles[action]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if presentation.get("does_not_establish") != consequence.get("does_not_establish"):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get("trusted_fact_requirements", []):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if select_semantic(semantics_v11, vector["candidate"]) != (semantic_id, None):
            raise ContractFailure(f"{consequence_type} is not selected exactly once in semantic v11")

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(f"{consequence_type} exact facts are invalid: {errors[0].message}")
        if not invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} vector violates coding workspace invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        alternate_connector = "github" if facts["connector_identity"] == "npm" else "npm"
        common_mutations = [
            ("connector_identity", alternate_connector),
            ("preflight_expires_at", "not-a-time"),
            ("preflight_snapshot_digest", "sha256:short"),
            ("max_uses", 2),
        ]
        action_mutations = {
            "code.package.install": [
                ("workspace_is_disposable", False),
                ("package_allowlisted", False),
                ("target_dependency_version", facts.get("current_dependency_version", "absent")),
                ("package_lock_present", False),
                ("lifecycle_scripts_disabled", False),
            ],
            "repository.branch.push": [
                ("target_branch_exists", True),
                ("target_branch", facts.get("base_branch", "main")),
                ("protected_path_change_count", 1),
                ("force_push", True),
            ],
            "repository.pull_request.create": [
                ("head_ref_exists", False),
                ("head_branch", facts.get("base_branch", "main")),
                ("ahead_by", 0),
                ("changed_files_count", 0),
                ("protected_path_change_count", 1),
                ("existing_open_pull_request_count", 1),
                ("merge_authorized", True),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(f"{consequence_type} accepted adversarial {field} mutation")

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v11["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v11 and fact profile registry v9 must bind exactly"
        )


def validate_collections_contract(registry: Registry) -> None:
    consequence_v6 = load_json("consequence_registry/v6.json")
    consequence_v7 = load_json("consequence_registry/v7.json")
    validate_instance(
        consequence_v7,
        "consequence_registry/v7.schema.json",
        registry,
        "consequence registry v7",
    )
    prior = consequence_v6["consequences"]
    consequences = consequence_v7["consequences"]
    if consequences[: len(prior)] != prior:
        raise ContractFailure(
            "consequence registry v7 must preserve every v6 entry byte-for-value"
        )

    facts_v9 = load_json("fact_profiles/v9.json")
    facts_v10 = load_json("fact_profiles/v10.json")
    semantics_v11 = load_json("semantic_registry/v11.json")
    semantics_v12 = load_json("semantic_registry/v12.json")
    presentations_v10 = load_json("presentation_registry/v10.json")
    presentations_v11 = load_json("presentation_registry/v11.json")
    vectors_v7 = load_json("consequence_registry/test-vectors/v7.json")
    vectors_v8 = load_json("consequence_registry/test-vectors/v8.json")

    validate_instance(
        facts_v10,
        "fact_profiles/v10.schema.json",
        registry,
        "fact profile registry v10",
    )
    validate_instance(
        semantics_v12,
        "semantic_registry/v12.schema.json",
        registry,
        "semantic registry v12",
    )
    validate_instance(
        presentations_v11,
        "presentation_registry/v11.schema.json",
        registry,
        "presentation registry v11",
    )
    if facts_v10["profiles"][: len(facts_v9["profiles"])] != facts_v9["profiles"]:
        raise ContractFailure(
            "fact profile registry v10 is not an additive v9 extension"
        )
    if semantics_v12["entries"][: len(semantics_v11["entries"])] != semantics_v11[
        "entries"
    ]:
        raise ContractFailure(
            "semantic registry v12 is not an additive v11 extension"
        )
    if presentations_v11["profiles"][: len(presentations_v10["profiles"])] != (
        presentations_v10["profiles"]
    ):
        raise ContractFailure(
            "presentation registry v11 is not an additive v10 extension"
        )
    if vectors_v8["vectors"][: len(vectors_v7["vectors"])] != vectors_v7["vectors"]:
        raise ContractFailure("consequence vectors v8 are not an additive v7 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v7 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v7 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v7 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v8["vectors"]}
    if len(vectors_by_id) != len(vectors_v8["vectors"]):
        raise ContractFailure("consequence vectors v8 contain duplicate ids")
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure(
            "v8 exact consequence vectors must cover consequence registry v7"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v10["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v12["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile for profile in presentations_v11["profiles"]
    }
    if len(profiles_by_id) != len(facts_v10["profiles"]):
        raise ContractFailure("fact profile registry v10 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v12["entries"]):
        raise ContractFailure("semantic registry v12 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v11["profiles"]):
        raise ContractFailure("presentation registry v11 contains duplicate semantics")

    schema_path = "schemas/collections-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path),
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    added = consequences[len(prior) :]
    expected_actions = {
        "collections.payment.collect.v1": "collections.payment.collect",
        "collections.payment_plan.create.v1": "collections.payment_plan.create",
        "collections.autopay.change.v1": "collections.autopay.change",
        "collections.notice.send.v1": "collections.notice.send",
    }
    expected_titles = {
        "collections.payment.collect": "AI Permit-to-Collect-Payment",
        "collections.payment_plan.create": "AI Permit-to-Create-Payment-Plan",
        "collections.autopay.change": "AI Permit-to-Change-Autopay",
        "collections.notice.send": "AI Permit-to-Send-Collections-Notice",
    }
    if {item["consequence_type"]: item["tool_names"][0] for item in added} != (
        expected_actions
    ):
        raise ContractFailure("consequence registry v7 collections action set drifted")

    def invariants_hold(facts: dict[str, Any]) -> bool:
        action = facts.get("action")
        if action == "collections.payment.collect":
            return (
                facts.get("connector_identity") == "payments"
                and facts.get("obligation_status") == "delinquent"
                and facts.get("amount_minor", 0) > 0
                and facts.get("amount_minor", 0)
                <= facts.get("remaining_balance_minor", -1)
                and facts.get("amount_within_balance") is True
                and facts.get("payment_method_attached") is True
                and facts.get("collection_mode") == "off_session"
                and facts.get("payment_intent_status_before") == "absent"
            )
        if action == "collections.payment_plan.create":
            return (
                facts.get("connector_identity") == "payments"
                and facts.get("installment_count", 0) >= 2
                and facts.get("installment_amount_minor", 0)
                * facts.get("installment_count", 0)
                == facts.get("total_plan_amount_minor")
                == facts.get("remaining_balance_minor")
                and facts.get("amount_matches_balance") is True
                and facts.get("default_payment_method_present") is True
                and facts.get("existing_active_plan_count") == 0
                and facts.get("schedule_mode") == "finite_subscription_schedule"
            )
        if action == "collections.autopay.change":
            requested = facts.get("requested_collection_method")
            return (
                facts.get("connector_identity") == "payments"
                and facts.get("current_collection_method") != requested
                and facts.get("autopay_enabled_before")
                is (facts.get("current_collection_method") == "charge_automatically")
                and facts.get("autopay_enabled_after")
                is (requested == "charge_automatically")
                and facts.get("default_payment_method_present") is True
                and facts.get("days_until_due")
                == (0 if requested == "charge_automatically" else 14)
            )
        if action == "collections.notice.send":
            return (
                facts.get("connector_identity") == "notification.email"
                and facts.get("recipient_is_dedicated_demo") is True
                and facts.get("channel") == "email"
                and facts.get("template_id") == "collections-friendly-reminder"
                and facts.get("template_version") == "v1"
                and facts.get("jurisdiction") == "DEMO-NOT-A-REAL-JURISDICTION"
                and facts.get("delivery_mode") == "provider_email"
            )
        return False

    for consequence in added:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        action = consequence["tool_names"][0]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if vector.get("expected_semantic_id") != semantic_id:
            raise ContractFailure(f"{consequence_type} vector semantic drifted")
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its collections fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        if presentation is None or presentation.get("customer_title") != expected_titles[
            action
        ]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if presentation.get("does_not_establish") != consequence.get(
            "does_not_establish"
        ):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get(
            "trusted_fact_requirements", []
        ):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if select_semantic(semantics_v12, vector["candidate"]) != (
            semantic_id,
            None,
        ):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in semantic v12"
            )

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not invariants_hold(facts):
            raise ContractFailure(
                f"{consequence_type} vector violates collections invariants"
            )
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        common_mutations = [
            ("preflight_expires_at", "not-a-time"),
            ("preflight_snapshot_digest", "sha256:short"),
            ("max_uses", 2),
        ]
        action_mutations = {
            "collections.payment.collect": [
                ("amount_minor", facts.get("remaining_balance_minor", 0) + 1),
                ("amount_within_balance", False),
                ("payment_method_attached", False),
            ],
            "collections.payment_plan.create": [
                ("total_plan_amount_minor", facts.get("remaining_balance_minor", 0) - 1),
                ("existing_active_plan_count", 1),
                ("default_payment_method_present", False),
            ],
            "collections.autopay.change": [
                ("requested_collection_method", facts.get("current_collection_method")),
                ("autopay_enabled_after", facts.get("autopay_enabled_before")),
                ("default_payment_method_present", False),
            ],
            "collections.notice.send": [
                ("recipient_is_dedicated_demo", False),
                ("template_id", "arbitrary-message"),
                ("jurisdiction", "US-CA"),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v12["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v12 and fact profile registry v10 must bind exactly"
        )


def validate_insurance_claims_contract(registry: Registry) -> None:
    consequence_v7 = load_json("consequence_registry/v7.json")
    consequence_v8 = load_json("consequence_registry/v8.json")
    validate_instance(
        consequence_v8,
        "consequence_registry/v8.schema.json",
        registry,
        "consequence registry v8",
    )
    prior = consequence_v7["consequences"]
    consequences = consequence_v8["consequences"]
    if consequences[: len(prior)] != prior:
        raise ContractFailure(
            "consequence registry v8 must preserve every v7 entry byte-for-value"
        )

    facts_v10 = load_json("fact_profiles/v10.json")
    facts_v11 = load_json("fact_profiles/v11.json")
    semantics_v12 = load_json("semantic_registry/v12.json")
    semantics_v13 = load_json("semantic_registry/v13.json")
    presentations_v11 = load_json("presentation_registry/v11.json")
    presentations_v12 = load_json("presentation_registry/v12.json")
    vectors_v8 = load_json("consequence_registry/test-vectors/v8.json")
    vectors_v9 = load_json("consequence_registry/test-vectors/v9.json")

    for instance, schema_path, label in (
        (facts_v11, "fact_profiles/v11.schema.json", "fact profile registry v11"),
        (
            semantics_v13,
            "semantic_registry/v13.schema.json",
            "semantic registry v13",
        ),
        (
            presentations_v12,
            "presentation_registry/v12.schema.json",
            "presentation registry v12",
        ),
    ):
        validate_instance(instance, schema_path, registry, label)
    if facts_v11["profiles"][: len(facts_v10["profiles"])] != facts_v10["profiles"]:
        raise ContractFailure("fact profile registry v11 is not an additive v10 extension")
    if semantics_v13["entries"][: len(semantics_v12["entries"])] != semantics_v12[
        "entries"
    ]:
        raise ContractFailure("semantic registry v13 is not an additive v12 extension")
    if presentations_v12["profiles"][: len(presentations_v11["profiles"])] != (
        presentations_v11["profiles"]
    ):
        raise ContractFailure(
            "presentation registry v12 is not an additive v11 extension"
        )
    if vectors_v9["vectors"][: len(vectors_v8["vectors"])] != vectors_v8["vectors"]:
        raise ContractFailure("consequence vectors v9 are not an additive v8 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v8 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v8 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v8 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v9["vectors"]}
    if len(vectors_by_id) != len(vectors_v9["vectors"]):
        raise ContractFailure("consequence vectors v9 contain duplicate ids")
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure(
            "v9 exact consequence vectors must cover consequence registry v8"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v11["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v13["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile for profile in presentations_v12["profiles"]
    }
    if len(profiles_by_id) != len(facts_v11["profiles"]):
        raise ContractFailure("fact profile registry v11 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v13["entries"]):
        raise ContractFailure("semantic registry v13 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v12["profiles"]):
        raise ContractFailure("presentation registry v12 contains duplicate semantics")

    schema_path = "schemas/insurance-claims-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path),
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    added = consequences[len(prior) :]
    expected_actions = {
        "insurance.claim.decision.record.v1": "insurance.claim.decision.record",
        "insurance.claim.settlement.set.v1": "insurance.claim.settlement.set",
        "insurance.claim.payment.send.v1": "insurance.claim.payment.send",
        "insurance.claim.notice.send.v1": "insurance.claim.notice.send",
    }
    expected_titles = {
        "insurance.claim.decision.record": "AI Permit-to-Decide-Claim",
        "insurance.claim.settlement.set": "AI Permit-to-Settle-Claim",
        "insurance.claim.payment.send": "AI Permit-to-Pay-Claim",
        "insurance.claim.notice.send": (
            "AI Permit-to-Send-Claim-Determination-Notice"
        ),
    }
    if {item["consequence_type"]: item["tool_names"][0] for item in added} != (
        expected_actions
    ):
        raise ContractFailure("consequence registry v8 insurance action set drifted")

    def invariants_hold(facts: dict[str, Any]) -> bool:
        action = facts.get("action")
        if action == "insurance.claim.decision.record":
            reasons = {
                "approved": {"covered_loss_verified", "partial_coverage_verified"},
                "denied": {"coverage_exclusion_applies", "insufficient_documentation"},
            }
            return (
                facts.get("connector_identity") == "claims.system"
                and facts.get("claim_status_before") == "under_review"
                and facts.get("decision_record_count_before") == 0
                and facts.get("decision_reason_code")
                in reasons.get(facts.get("requested_outcome"), set())
                and facts.get("human_review_required") is True
                and facts.get("required_approver_role") == "licensed_claims_adjuster"
                and facts.get("separation_of_duties_required") is True
                and facts.get("appeal_path_included") is True
            )
        if action == "insurance.claim.settlement.set":
            settlement = facts.get("settlement_amount_minor", 0)
            return (
                facts.get("connector_identity") == "claims.system"
                and facts.get("claim_status_before") == "approved"
                and facts.get("decision_outcome") == "approved"
                and facts.get("settlement_record_count_before") == 0
                and settlement > 0
                and settlement <= facts.get("covered_amount_minor", -1)
                and settlement <= facts.get("policy_limit_minor", -1)
                and facts.get("amount_within_covered_amount") is True
                and facts.get("amount_within_policy_limit") is True
            )
        if action == "insurance.claim.payment.send":
            paid = facts.get("paid_amount_minor_before", -1)
            remaining = facts.get("remaining_payable_minor", -1)
            settlement = facts.get("settlement_amount_minor", -1)
            return (
                facts.get("connector_identity") == "payments"
                and facts.get("claim_status_before") == "settled"
                and facts.get("settlement_status_before") == "approved_for_payment"
                and paid >= 0
                and remaining > 0
                and paid + remaining == settlement
                and facts.get("payment_amount_minor") == remaining
                and facts.get("amount_matches_remaining_payable") is True
                and facts.get("destination_allowlisted") is True
                and facts.get("transfer_status_before") == "absent"
            )
        if action == "insurance.claim.notice.send":
            outcome = facts.get("recorded_decision_outcome")
            template = facts.get("template_id")
            amount = facts.get("settlement_amount_minor")
            return (
                facts.get("connector_identity") == "notification.email"
                and facts.get("recipient_is_dedicated_demo") is True
                and template
                == {
                    "approved": "claim-approval-notice",
                    "denied": "claim-denial-notice",
                }.get(outcome)
                and ((outcome == "approved" and amount > 0) or (outcome == "denied" and amount == 0))
                and facts.get("appeal_instructions_included") is True
                and facts.get("notice_record_count_before") == 0
                and facts.get("jurisdiction") == "DEMO-NOT-A-REAL-JURISDICTION"
                and facts.get("delivery_mode") == "provider_email"
            )
        return False

    allowed_leading_fields = set(presentations_v12["allowed_leading_fields"])
    allowed_sections = set(presentations_v12["allowed_evidence_sections"])
    for consequence in added:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        action = consequence["tool_names"][0]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if vector.get("expected_semantic_id") != semantic_id:
            raise ContractFailure(f"{consequence_type} vector semantic drifted")
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its insurance fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        if presentation is None or presentation.get("customer_title") != expected_titles[
            action
        ]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if not {
            field["field"] for field in presentation.get("leading_fields", [])
        }.issubset(allowed_leading_fields):
            raise ContractFailure(f"{consequence_type} uses an unknown leading field")
        if not set(presentation.get("evidence_sections", [])).issubset(
            allowed_sections
        ):
            raise ContractFailure(f"{consequence_type} uses an unknown evidence section")
        if presentation.get("does_not_establish") != consequence.get(
            "does_not_establish"
        ):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get(
            "trusted_fact_requirements", []
        ):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if action in {
            "insurance.claim.decision.record",
            "insurance.claim.settlement.set",
        }:
            if "keel_signed_co_signature_requirement" not in consequence.get(
                "trusted_fact_requirements", []
            ):
                raise ContractFailure(f"{consequence_type} omits co-signature policy binding")
            if "/co_signature_requirement_digest" not in profile.get(
                "material_request_fact_paths", []
            ):
                raise ContractFailure(f"{consequence_type} omits co-signature digest")
        if select_semantic(semantics_v13, vector["candidate"]) != (
            semantic_id,
            None,
        ):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in semantic v13"
            )

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not invariants_hold(facts):
            raise ContractFailure(
                f"{consequence_type} vector violates insurance invariants"
            )
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        common_mutations = [
            ("preflight_expires_at", "not-a-time"),
            ("preflight_snapshot_digest", "sha256:short"),
            ("max_uses", 2),
        ]
        action_mutations = {
            "insurance.claim.decision.record": [
                ("decision_record_count_before", 1),
                ("human_review_required", False),
                ("decision_reason_code", "coverage_exclusion_applies"),
            ],
            "insurance.claim.settlement.set": [
                ("settlement_record_count_before", 1),
                ("settlement_amount_minor", facts.get("covered_amount_minor", 0) + 1),
                ("amount_within_covered_amount", False),
            ],
            "insurance.claim.payment.send": [
                ("payment_amount_minor", facts.get("remaining_payable_minor", 0) - 1),
                ("destination_allowlisted", False),
                ("transfer_status_before", "present"),
            ],
            "insurance.claim.notice.send": [
                ("recipient_is_dedicated_demo", False),
                ("template_id", "claim-denial-notice"),
                ("appeal_instructions_included", False),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v13["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v13 and fact profile registry v11 must bind exactly"
        )


def validate_erp_crm_contract(registry: Registry) -> None:
    consequence_v8 = load_json("consequence_registry/v8.json")
    consequence_v9 = load_json("consequence_registry/v9.json")
    validate_instance(
        consequence_v9,
        "consequence_registry/v9.schema.json",
        registry,
        "consequence registry v9",
    )
    prior = consequence_v8["consequences"]
    consequences = consequence_v9["consequences"]
    if consequences[: len(prior)] != prior:
        raise ContractFailure(
            "consequence registry v9 must preserve every v8 entry byte-for-value"
        )

    facts_v11 = load_json("fact_profiles/v11.json")
    facts_v12 = load_json("fact_profiles/v12.json")
    semantics_v13 = load_json("semantic_registry/v13.json")
    semantics_v14 = load_json("semantic_registry/v14.json")
    presentations_v12 = load_json("presentation_registry/v12.json")
    presentations_v13 = load_json("presentation_registry/v13.json")
    vectors_v9 = load_json("consequence_registry/test-vectors/v9.json")
    vectors_v10 = load_json("consequence_registry/test-vectors/v10.json")

    for instance, schema_path, label in (
        (facts_v12, "fact_profiles/v12.schema.json", "fact profile registry v12"),
        (
            semantics_v14,
            "semantic_registry/v14.schema.json",
            "semantic registry v14",
        ),
        (
            presentations_v13,
            "presentation_registry/v13.schema.json",
            "presentation registry v13",
        ),
    ):
        validate_instance(instance, schema_path, registry, label)
    if facts_v12["profiles"][: len(facts_v11["profiles"])] != facts_v11["profiles"]:
        raise ContractFailure("fact profile registry v12 is not an additive v11 extension")
    if semantics_v14["entries"][: len(semantics_v13["entries"])] != semantics_v13[
        "entries"
    ]:
        raise ContractFailure("semantic registry v14 is not an additive v13 extension")
    if presentations_v13["profiles"][: len(presentations_v12["profiles"])] != (
        presentations_v12["profiles"]
    ):
        raise ContractFailure(
            "presentation registry v13 is not an additive v12 extension"
        )
    if vectors_v10["vectors"][: len(vectors_v9["vectors"])] != vectors_v9["vectors"]:
        raise ContractFailure("consequence vectors v10 are not an additive v9 extension")

    consequence_types = [item["consequence_type"] for item in consequences]
    semantic_ids = [item["semantic_id"] for item in consequences]
    tool_names = [tool for item in consequences for tool in item["tool_names"]]
    if len(consequence_types) != len(set(consequence_types)):
        raise ContractFailure("consequence registry v9 contains duplicate types")
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ContractFailure("consequence registry v9 contains duplicate semantics")
    if len(tool_names) != len(set(tool_names)):
        raise ContractFailure("consequence registry v9 contains overlapping tools")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v10["vectors"]}
    if len(vectors_by_id) != len(vectors_v10["vectors"]):
        raise ContractFailure("consequence vectors v10 contain duplicate ids")
    if set(vectors_by_id) != set(consequence_types):
        raise ContractFailure(
            "v10 exact consequence vectors must cover consequence registry v9"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v12["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v14["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile for profile in presentations_v13["profiles"]
    }
    if len(profiles_by_id) != len(facts_v12["profiles"]):
        raise ContractFailure("fact profile registry v12 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v14["entries"]):
        raise ContractFailure("semantic registry v14 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v13["profiles"]):
        raise ContractFailure("presentation registry v13 contains duplicate semantics")

    schema_path = "schemas/erp-crm-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path),
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    added = consequences[len(prior) :]
    expected_actions = {
        "crm.deal.stage.change.v1": "crm.deal.stage.change",
        "crm.customer.record.update.v1": "crm.customer.record.update",
        "crm.quote.create.v1": "crm.quote.create",
    }
    expected_titles = {
        "crm.deal.stage.change": "AI Permit-to-Change-Deal-Stage",
        "crm.customer.record.update": "AI Permit-to-Update-Customer-Record",
        "crm.quote.create": "AI Permit-to-Create-Quote",
    }
    if {item["consequence_type"]: item["tool_names"][0] for item in added} != (
        expected_actions
    ):
        raise ContractFailure("consequence registry v9 ERP/CRM action set drifted")

    def invariants_hold(facts: dict[str, Any]) -> bool:
        if not (
            facts.get("connector_identity") == "hubspot"
            and facts.get("provider_environment") == "developer_test"
            and facts.get("provider_account_type") == "DEVELOPER_TEST"
            and facts.get("record_is_synthetic") is True
            and facts.get("max_uses") == 1
        ):
            return False
        action = facts.get("action")
        if action == "crm.deal.stage.change":
            return (
                facts.get("current_stage_id") != facts.get("requested_stage_id")
                and facts.get("transition_allowlisted") is True
            )
        if action == "crm.customer.record.update":
            return (
                facts.get("property_name") in {"jobtitle", "lifecyclestage", "phone"}
                and facts.get("property_allowlisted") is True
                and facts.get("property_read_only") is False
                and facts.get("value_before_commitment")
                != facts.get("value_after_commitment")
            )
        if action == "crm.quote.create":
            subtotal = facts.get("subtotal_amount_minor", -1)
            discount = facts.get("discount_amount_minor", -1)
            tax = facts.get("tax_amount_minor", -1)
            return (
                subtotal > 0
                and discount >= 0
                and tax >= 0
                and subtotal - discount + tax == facts.get("total_amount_minor")
                and facts.get("total_matches_provider_pricing") is True
                and facts.get("quote_status") == "DRAFT"
                and facts.get("payment_enabled") is False
                and facts.get("e_signature_enabled") is False
                and facts.get("publication_status") == "not_published"
                and facts.get("existing_quote_count_for_idempotency_key") == 0
            )
        return False

    allowed_leading_fields = set(presentations_v13["allowed_leading_fields"])
    allowed_sections = set(presentations_v13["allowed_evidence_sections"])
    for consequence in added:
        consequence_type = consequence["consequence_type"]
        vector = vectors_by_id[consequence_type]
        semantic_id = consequence["semantic_id"]
        profile_id = vector["expected_fact_profile_id"]
        action = consequence["tool_names"][0]
        entry = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if vector.get("expected_semantic_id") != semantic_id:
            raise ContractFailure(f"{consequence_type} vector semantic drifted")
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks its exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks its ERP/CRM fact profile")
        if semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{consequence_type} fact profile semantic drifted")
        if presentation is None or presentation.get("customer_title") != expected_titles[
            action
        ]:
            raise ContractFailure(f"{consequence_type} lacks its exact human title")
        if not {
            field["field"] for field in presentation.get("leading_fields", [])
        }.issubset(allowed_leading_fields):
            raise ContractFailure(f"{consequence_type} uses an unknown leading field")
        if not set(presentation.get("evidence_sections", [])).issubset(
            allowed_sections
        ):
            raise ContractFailure(f"{consequence_type} uses an unknown evidence section")
        if presentation.get("does_not_establish") != consequence.get(
            "does_not_establish"
        ):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        requirements = consequence.get("trusted_fact_requirements", [])
        if "gateway_preflight_hmac" not in requirements:
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if "gateway_pinned_developer_test_portal" not in requirements:
            raise ContractFailure(f"{consequence_type} omits portal custody boundary")
        if select_semantic(semantics_v14, vector["candidate"]) != (
            semantic_id,
            None,
        ):
            raise ContractFailure(
                f"{consequence_type} is not selected exactly once in semantic v14"
            )

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} vector violates ERP/CRM invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} facts schema digest is stale")

        common_mutations = [
            ("provider_environment", "production"),
            ("provider_account_type", "STANDARD"),
            ("record_is_synthetic", False),
            ("preflight_expires_at", "not-a-time"),
            ("max_uses", 2),
        ]
        action_mutations = {
            "crm.deal.stage.change": [
                ("requested_stage_id", facts.get("current_stage_id")),
                ("transition_allowlisted", False),
            ],
            "crm.customer.record.update": [
                ("property_name", "email"),
                ("property_read_only", True),
                ("value_after_commitment", facts.get("value_before_commitment")),
            ],
            "crm.quote.create": [
                ("quote_status", "APPROVAL_NOT_NEEDED"),
                ("payment_enabled", True),
                ("e_signature_enabled", True),
                ("total_amount_minor", facts.get("total_amount_minor", 0) + 1),
                ("existing_quote_count_for_idempotency_key", 1),
            ],
        }[action]
        for field, value in [*common_mutations, *action_mutations]:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v14["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v14 and fact profile registry v12 must bind exactly"
        )


def validate_procurement_ap_contract(registry: Registry) -> None:
    consequence_v9 = load_json("consequence_registry/v9.json")
    consequence_v10 = load_json("consequence_registry/v10.json")
    facts_v12 = load_json("fact_profiles/v12.json")
    facts_v13 = load_json("fact_profiles/v13.json")
    semantics_v14 = load_json("semantic_registry/v14.json")
    semantics_v15 = load_json("semantic_registry/v15.json")
    presentations_v13 = load_json("presentation_registry/v13.json")
    presentations_v14 = load_json("presentation_registry/v14.json")
    vectors_v10 = load_json("consequence_registry/test-vectors/v10.json")
    vectors_v11 = load_json("consequence_registry/test-vectors/v11.json")

    for instance, schema_path, label in (
        (
            consequence_v10,
            "consequence_registry/v10.schema.json",
            "consequence registry v10",
        ),
        (facts_v13, "fact_profiles/v13.schema.json", "fact profile registry v13"),
        (
            semantics_v15,
            "semantic_registry/v15.schema.json",
            "semantic registry v15",
        ),
        (
            presentations_v14,
            "presentation_registry/v14.schema.json",
            "presentation registry v14",
        ),
    ):
        validate_instance(instance, schema_path, registry, label)

    additive_pairs = (
        (consequence_v9, consequence_v10, "consequences", "consequence v10"),
        (facts_v12, facts_v13, "profiles", "fact profiles v13"),
        (semantics_v14, semantics_v15, "entries", "semantic v15"),
        (presentations_v13, presentations_v14, "profiles", "presentation v14"),
        (vectors_v10, vectors_v11, "vectors", "consequence vectors v11"),
    )
    for prior, current, key, label in additive_pairs:
        if current[key][: len(prior[key])] != prior[key]:
            raise ContractFailure(f"{label} is not an additive extension")

    expected_actions = {
        "procurement.vendor.create.v1": "procurement.vendor.create",
        "procurement.purchase_order.issue.v1": "procurement.purchase_order.issue",
        "procurement.spend.commit.v1": "procurement.spend.commit",
        "ap.invoice.approve.v1": "ap.invoice.approve",
        "ap.invoice.duplicate.reject.v1": "ap.invoice.duplicate.reject",
        "ap.invoice.payment.release.v1": "ap.invoice.payment.release",
    }
    expected_titles = {
        "procurement.vendor.create": "AI Permit-to-Create-Vendor",
        "procurement.purchase_order.issue": "AI Permit-to-Issue-Purchase-Order",
        "procurement.spend.commit": "AI Permit-to-Commit-Procurement-Spend",
        "ap.invoice.approve": "AI Permit-to-Approve-Invoice",
        "ap.invoice.duplicate.reject": "AI Permit-to-Reject-Duplicate-Invoice",
        "ap.invoice.payment.release": "AI Permit-to-Release-Invoice-Payment",
    }
    prior_consequences = consequence_v9["consequences"]
    consequences = consequence_v10["consequences"]
    added = consequences[len(prior_consequences) :]
    if {item["consequence_type"]: item["tool_names"][0] for item in added} != (
        expected_actions
    ):
        raise ContractFailure("consequence registry v10 procurement/AP action set drifted")

    for key, values in (
        ("consequence type", [item["consequence_type"] for item in consequences]),
        ("semantic id", [item["semantic_id"] for item in consequences]),
        ("tool", [tool for item in consequences for tool in item["tool_names"]]),
    ):
        if len(values) != len(set(values)):
            raise ContractFailure(f"consequence registry v10 duplicates {key}")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v11["vectors"]}
    if set(vectors_by_id) != {item["consequence_type"] for item in consequences}:
        raise ContractFailure(
            "v11 exact consequence vectors must cover consequence registry v10"
        )
    profiles_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v13["profiles"]
    }
    semantics_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v15["entries"]
    }
    presentations_by_id = {
        profile["semantic_id"]: profile
        for profile in presentations_v14["profiles"]
    }
    if len(profiles_by_id) != len(facts_v13["profiles"]):
        raise ContractFailure("fact profile registry v13 contains duplicate ids")
    if len(semantics_by_id) != len(semantics_v15["entries"]):
        raise ContractFailure("semantic registry v15 contains duplicate ids")
    if len(presentations_by_id) != len(presentations_v14["profiles"]):
        raise ContractFailure("presentation registry v14 contains duplicate semantics")

    schema_path = "schemas/procurement-ap-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path),
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )

    def invariants_hold(facts: dict[str, Any]) -> bool:
        if not (
            facts.get("connector_identity") == "odoo"
            and facts.get("record_is_synthetic") is True
            and facts.get("max_uses") == 1
        ):
            return False
        action = facts.get("action")
        expected_environment = (
            "self_hosted_plus_provider_sandbox"
            if action == "ap.invoice.payment.release"
            else "self_hosted_synthetic"
        )
        if facts.get("provider_environment") != expected_environment:
            return False
        if action == "procurement.vendor.create":
            return (
                facts.get("supplier_rank_requested") == 1
                and facts.get("duplicate_vendor_count") == 0
                and facts.get("required_fields_complete") is True
                and facts.get("bank_account_created") is False
            )
        if action == "procurement.purchase_order.issue":
            return (
                facts.get("total_amount_minor", 0) > 0
                and facts.get("purchase_order_status_before") == "absent"
                and facts.get("requested_purchase_order_status") == "draft"
                and facts.get("spend_committed") is False
                and facts.get("supplier_notification_sent") is False
                and facts.get("total_matches_provider_pricing") is True
            )
        if action == "procurement.spend.commit":
            return (
                0 < facts.get("total_amount_minor", 0)
                <= facts.get("available_budget_minor", -1)
                and facts.get("amount_within_budget") is True
                and facts.get("current_purchase_order_status") == "draft"
                and facts.get("requested_purchase_order_status") == "purchase"
                and facts.get("spend_committed_before") is False
                and facts.get("spend_committed_after") is True
                and facts.get("payment_released") is False
            )
        if action == "ap.invoice.approve":
            return (
                facts.get("current_invoice_status") == "draft"
                and facts.get("requested_invoice_status") == "posted"
                and facts.get("payment_status") == "not_paid"
                and facts.get("duplicate_candidate_count") == 0
                and facts.get("three_way_match_complete") is True
                and facts.get("invoice_total_matches_purchase_order") is True
                and facts.get("receipt_quantity_covers_invoice") is True
                and facts.get("accounting_period_open") is True
            )
        if action == "ap.invoice.duplicate.reject":
            return (
                facts.get("current_invoice_status") == "draft"
                and facts.get("requested_invoice_status") == "cancel"
                and facts.get("payment_status") == "not_paid"
                and facts.get("payment_released") is False
                and facts.get("duplicate_match_method")
                == "provider_vendor_number_and_total_exact.v1"
                and facts.get("vendor_reference_matches") is True
                and facts.get("invoice_number_matches") is True
                and facts.get("total_amount_matches") is True
            )
        if action == "ap.invoice.payment.release":
            return (
                facts.get("invoice_status") == "posted"
                and facts.get("payment_status") == "not_paid"
                and facts.get("three_way_match_complete") is True
                and facts.get("stripe_livemode") is False
                and facts.get("stripe_transfer_status_before") == "absent"
                and facts.get("existing_transfer_count") == 0
                and facts.get("workflow_step_count") == 2
                and facts.get("odoo_payment_registration_required") is True
                and facts.get("value_conservation_valid") is True
            )
        return False

    allowed_leading_fields = set(presentations_v14["allowed_leading_fields"])
    allowed_sections = set(presentations_v14["allowed_evidence_sections"])
    for consequence in added:
        consequence_type = consequence["consequence_type"]
        action = consequence["tool_names"][0]
        semantic_id = consequence["semantic_id"]
        vector = vectors_by_id[consequence_type]
        profile_id = vector["expected_fact_profile_id"]
        semantic = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if semantic is None or semantic.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks exact fact profile")
        if presentation is None or presentation.get("customer_title") != (
            expected_titles[action]
        ):
            raise ContractFailure(f"{consequence_type} lacks exact human title")
        if not {
            item["field"] for item in presentation.get("leading_fields", [])
        }.issubset(allowed_leading_fields):
            raise ContractFailure(f"{consequence_type} uses unknown leading field")
        if not set(presentation.get("evidence_sections", [])).issubset(
            allowed_sections
        ):
            raise ContractFailure(f"{consequence_type} uses unknown evidence section")
        if presentation.get("does_not_establish") != consequence.get(
            "does_not_establish"
        ):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        requirements = consequence.get("trusted_fact_requirements", [])
        if not {
            "gateway_pinned_self_hosted_database",
            "gateway_preflight_hmac",
        }.issubset(requirements):
            raise ContractFailure(f"{consequence_type} omits gateway custody controls")
        if select_semantic(semantics_v15, vector["candidate"]) != (
            semantic_id,
            None,
        ):
            raise ContractFailure(f"{consequence_type} is not selected exactly once")

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} violates exact invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} schema digest is stale")

        mutations = [
            ("record_is_synthetic", False),
            ("max_uses", 2),
            ("preflight_expires_at", "not-a-time"),
        ]
        if action == "procurement.spend.commit":
            mutations.append(
                ("total_amount_minor", facts.get("available_budget_minor", 0) + 1)
            )
        elif action == "ap.invoice.payment.release":
            mutations.extend(
                [("stripe_livemode", True), ("existing_transfer_count", 1)]
            )
        else:
            boolean_fields = [
                name
                for name, value in facts.items()
                if isinstance(value, bool) and name != "record_is_synthetic"
            ]
            if boolean_fields:
                name = boolean_fields[0]
                mutations.append((name, not facts[name]))
        for field, value in mutations:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(
                    f"{consequence_type} accepted adversarial {field} mutation"
                )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v15["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure(
            "semantic registry v15 and fact profile registry v13 must bind exactly"
        )


def validate_commerce_regulated_contract(registry: Registry) -> None:
    consequence_v10 = load_json("consequence_registry/v10.json")
    consequence_v11 = load_json("consequence_registry/v11.json")
    facts_v13 = load_json("fact_profiles/v13.json")
    facts_v14 = load_json("fact_profiles/v14.json")
    semantics_v15 = load_json("semantic_registry/v15.json")
    semantics_v16 = load_json("semantic_registry/v16.json")
    presentations_v14 = load_json("presentation_registry/v14.json")
    presentations_v15 = load_json("presentation_registry/v15.json")
    vectors_v11 = load_json("consequence_registry/test-vectors/v11.json")
    vectors_v12 = load_json("consequence_registry/test-vectors/v12.json")

    for instance, schema_path, label in (
        (consequence_v11, "consequence_registry/v11.schema.json", "consequence registry v11"),
        (facts_v14, "fact_profiles/v14.schema.json", "fact profile registry v14"),
        (semantics_v16, "semantic_registry/v16.schema.json", "semantic registry v16"),
        (presentations_v15, "presentation_registry/v15.schema.json", "presentation registry v15"),
    ):
        validate_instance(instance, schema_path, registry, label)

    for prior, current, key, label in (
        (consequence_v10, consequence_v11, "consequences", "consequence v11"),
        (facts_v13, facts_v14, "profiles", "fact profiles v14"),
        (semantics_v15, semantics_v16, "entries", "semantic v16"),
        (presentations_v14, presentations_v15, "profiles", "presentation v15"),
        (vectors_v11, vectors_v12, "vectors", "consequence vectors v12"),
    ):
        if current[key][: len(prior[key])] != prior[key]:
            raise ContractFailure(f"{label} is not an additive extension")

    expected_titles = {
        "commerce.order.place": "AI Permit-to-Place-Order",
        "commerce.merchant.pay": "AI Permit-to-Pay-Merchant",
        "commerce.inventory.reserve": "AI Permit-to-Reserve-Inventory",
        "benefits.case.grant": "AI Permit-to-Grant-Benefit",
        "benefits.case.deny": "AI Permit-to-Deny-Benefit",
        "benefits.eligibility.change": "AI Permit-to-Change-Benefit-Eligibility",
        "benefits.payment.issue": "AI Permit-to-Issue-Benefit-Payment",
        "benefits.determination.notice.send": "AI Permit-to-Send-Benefit-Determination-Notice",
        "healthcare.prior_authorization.submit": "AI Permit-to-Submit-Prior-Authorization",
        "healthcare.prior_authorization.clinical_information.request": "AI Permit-to-Request-Clinical-Information",
        "healthcare.prior_authorization.approve": "AI Permit-to-Approve-Prior-Authorization",
        "healthcare.prior_authorization.deny": "AI Permit-to-Deny-Prior-Authorization",
        "healthcare.appointment.schedule": "AI Permit-to-Schedule-Appointment",
        "healthcare.claim.submit": "AI Permit-to-Submit-Healthcare-Claim",
        "healthcare.patient_administrative_record.update": "AI Permit-to-Update-Patient-Administrative-Record",
    }
    added = consequence_v11["consequences"][len(consequence_v10["consequences"]) :]
    if {item["tool_names"][0] for item in added} != set(expected_titles):
        raise ContractFailure("consequence registry v11 commerce/regulated action set drifted")

    consequences = consequence_v11["consequences"]
    for key, values in (
        ("consequence type", [item["consequence_type"] for item in consequences]),
        ("semantic id", [item["semantic_id"] for item in consequences]),
        ("tool", [tool for item in consequences for tool in item["tool_names"]]),
    ):
        if len(values) != len(set(values)):
            raise ContractFailure(f"consequence registry v11 duplicates {key}")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v12["vectors"]}
    if set(vectors_by_id) != {item["consequence_type"] for item in consequences}:
        raise ContractFailure("v12 exact vectors must cover consequence registry v11")
    profiles_by_id = {item["fact_profile_id"]: item for item in facts_v14["profiles"]}
    semantics_by_id = {item["semantic_id"]: item for item in semantics_v16["entries"]}
    presentations_by_id = {item["semantic_id"]: item for item in presentations_v15["profiles"]}
    for label, mapping, source in (
        ("fact profile", profiles_by_id, facts_v14["profiles"]),
        ("semantic", semantics_by_id, semantics_v16["entries"]),
        ("presentation", presentations_by_id, presentations_v15["profiles"]),
    ):
        if len(mapping) != len(source):
            raise ContractFailure(f"registry v11 contains duplicate {label} ids")

    schema_path = "schemas/commerce-regulated-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path), registry=registry, format_checker=jsonschema.FormatChecker()
    )

    def invariants_hold(facts: dict[str, Any]) -> bool:
        if facts.get("record_is_synthetic") is not True or facts.get("max_uses") != 1:
            return False
        action = facts.get("action")
        if action == "commerce.inventory.reserve":
            return (
                facts.get("inventory_sufficient") is True
                and facts.get("available_unit_count", -1) >= facts.get("requested_unit_count", 0) > 0
            )
        if action == "benefits.eligibility.change":
            return facts.get("current_eligibility_status") != facts.get("requested_eligibility_status")
        if action == "healthcare.appointment.schedule":
            start = facts.get("appointment_start_at", "")
            end = facts.get("appointment_end_at", "")
            return start < end and facts.get("schedule_conflict_count") == 0
        if action == "healthcare.patient_administrative_record.update":
            return (
                facts.get("requested_record_version") == facts.get("record_version_before", -1) + 1
                and facts.get("clinical_field_mutation_requested") is False
            )
        if action in {"commerce.merchant.pay", "benefits.payment.issue"}:
            return facts.get("stripe_livemode") is False and facts.get("existing_payment_count") == 0
        if action in {"benefits.case.grant", "benefits.case.deny"}:
            expected = "granted" if action.endswith("grant") else "denied"
            return facts.get("requested_determination_status") == expected
        return True

    allowed_leading_fields = set(presentations_v15["allowed_leading_fields"])
    allowed_sections = set(presentations_v15["allowed_evidence_sections"])
    for consequence in added:
        consequence_type = consequence["consequence_type"]
        action_name = consequence["tool_names"][0]
        semantic_id = consequence["semantic_id"]
        vector = vectors_by_id[consequence_type]
        profile_id = vector["expected_fact_profile_id"]
        semantic = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if semantic is None or semantic.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks exact fact profile")
        if presentation is None or presentation.get("customer_title") != expected_titles[action_name]:
            raise ContractFailure(f"{consequence_type} lacks exact human title")
        if not {item["field"] for item in presentation.get("leading_fields", [])}.issubset(allowed_leading_fields):
            raise ContractFailure(f"{consequence_type} uses unknown leading field")
        if not set(presentation.get("evidence_sections", [])).issubset(allowed_sections):
            raise ContractFailure(f"{consequence_type} uses unknown evidence section")
        if presentation.get("does_not_establish") != consequence.get("does_not_establish"):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        if "gateway_preflight_hmac" not in consequence.get("trusted_fact_requirements", []):
            raise ContractFailure(f"{consequence_type} omits authenticated preflight")
        if select_semantic(semantics_v16, vector["candidate"]) != (semantic_id, None):
            raise ContractFailure(f"{consequence_type} is not selected exactly once")

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(f"{consequence_type} exact facts are invalid: {errors[0].message}")
        if not invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} violates exact invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action_name:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} schema digest is stale")

        mutations = [("record_is_synthetic", False), ("max_uses", 2), ("preflight_expires_at", "not-a-time")]
        if action_name == "commerce.inventory.reserve":
            mutations.append(("available_unit_count", 0))
        elif action_name == "benefits.eligibility.change":
            mutations.append(("requested_eligibility_status", facts["current_eligibility_status"]))
        elif action_name == "healthcare.appointment.schedule":
            mutations.append(("appointment_end_at", facts["appointment_start_at"]))
        elif action_name == "healthcare.patient_administrative_record.update":
            mutations.append(("requested_record_version", facts["record_version_before"] + 2))
        elif action_name in {"commerce.merchant.pay", "benefits.payment.issue"}:
            mutations.append(("stripe_livemode", True))
        for field, value in mutations:
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(f"{consequence_type} accepted adversarial {field} mutation")

    bound_profile_ids = {
        entry["fact_profile_id"] for entry in semantics_v16["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure("semantic registry v16 and fact profile registry v14 must bind exactly")


def validate_wave5_breadth_contract(registry: Registry) -> None:
    consequence_v11 = load_json("consequence_registry/v11.json")
    consequence_v12 = load_json("consequence_registry/v12.json")
    facts_v14 = load_json("fact_profiles/v14.json")
    facts_v15 = load_json("fact_profiles/v15.json")
    semantics_v16 = load_json("semantic_registry/v16.json")
    semantics_v17 = load_json("semantic_registry/v17.json")
    presentations_v15 = load_json("presentation_registry/v15.json")
    presentations_v16 = load_json("presentation_registry/v16.json")
    vectors_v12 = load_json("consequence_registry/test-vectors/v12.json")
    vectors_v13 = load_json("consequence_registry/test-vectors/v13.json")

    for instance, schema_path, label in (
        (consequence_v12, "consequence_registry/v12.schema.json", "consequence registry v12"),
        (facts_v15, "fact_profiles/v15.schema.json", "fact profile registry v15"),
        (semantics_v17, "semantic_registry/v17.schema.json", "semantic registry v17"),
        (presentations_v16, "presentation_registry/v16.schema.json", "presentation registry v16"),
    ):
        validate_instance(instance, schema_path, registry, label)

    for prior, current, key, label in (
        (consequence_v11, consequence_v12, "consequences", "consequence v12"),
        (facts_v14, facts_v15, "profiles", "fact profiles v15"),
        (semantics_v16, semantics_v17, "entries", "semantic v17"),
        (presentations_v15, presentations_v16, "profiles", "presentation v16"),
        (vectors_v12, vectors_v13, "vectors", "consequence vectors v13"),
    ):
        if current[key][: len(prior[key])] != prior[key]:
            raise ContractFailure(f"{label} is not an additive extension")

    expected_titles = {
        "trust_safety.content.remove": "AI Permit-to-Remove-Community-Content",
        "trust_safety.member.suspend": "AI Permit-to-Suspend-Community-Member",
        "trust_safety.member.restore": "AI Permit-to-Restore-Community-Member",
        "recruiting.candidate.advance": "AI Permit-to-Advance-Candidate",
        "recruiting.candidate.reject": "AI Permit-to-Reject-Candidate",
        "recruiting.offer.send": "AI Permit-to-Send-Employment-Offer",
        "legal.agreement.send": "AI Permit-to-Send-Agreement",
        "legal.agreement.void": "AI Permit-to-Void-Agreement",
        "trading.paper.order.place": "AI Permit-to-Place-Paper-Trade",
        "trading.paper.order.cancel": "AI Permit-to-Cancel-Paper-Trade",
        "supply.replenishment_order.issue": "AI Permit-to-Issue-Replenishment-Order",
        "supply.shipment.create": "AI Permit-to-Create-Shipment",
        "supply.shipping_label.purchase": "AI Permit-to-Purchase-Test-Shipping-Label",
        "supply.shipment.route.change": "AI Permit-to-Change-Shipment-Route",
        "legacy.customer.address.change": "AI Permit-to-Change-Customer-Address",
        "sales.email.send": "AI Permit-to-Send-Sales-Email",
        "sales.discount.offer": "AI Permit-to-Offer-Discount",
        "calendar.event.create": "AI Permit-to-Create-Calendar-Event",
        "email.message.send": "AI Permit-to-Send-Email",
        "commerce.item.purchase": "AI Permit-to-Purchase-Item",
        "marketing.content.publish": "AI Permit-to-Publish-Content",
        "marketing.campaign.launch": "AI Permit-to-Launch-Campaign",
        "marketing.campaign.budget.change": "AI Permit-to-Change-Campaign-Budget",
        "education.student.enroll": "AI Permit-to-Enroll-Student",
        "education.enrollment.drop": "AI Permit-to-Drop-Enrollment",
        "education.transcript.release": "AI Permit-to-Release-Transcript",
        "research.dataset.purchase": "AI Permit-to-Purchase-Dataset",
        "research.artifact.publish": "AI Permit-to-Publish-Research-Artifact",
        "metered.api.usage.purchase": "AI Permit-to-Purchase-API-Usage",
        "metered.compute.units.purchase": "AI Permit-to-Purchase-Compute-Units",
        "physical.access.unlock": "AI Permit-to-Unlock-Demo-Door",
        "physical.relay.actuate": "AI Permit-to-Actuate-Demo-Relay",
        "physical.arm.move": "AI Permit-to-Move-Demo-Arm",
    }
    added = consequence_v12["consequences"][len(consequence_v11["consequences"]) :]
    if {item["tool_names"][0] for item in added} != set(expected_titles):
        raise ContractFailure("consequence registry v12 Wave 5 action set drifted")

    consequences = consequence_v12["consequences"]
    for key, values in (
        ("consequence type", [item["consequence_type"] for item in consequences]),
        ("semantic id", [item["semantic_id"] for item in consequences]),
        ("tool", [tool for item in consequences for tool in item["tool_names"]]),
    ):
        if len(values) != len(set(values)):
            raise ContractFailure(f"consequence registry v12 duplicates {key}")

    prior_tools = {
        tool: item for item in consequence_v11["consequences"] for tool in item["tool_names"]
    }
    if prior_tools.get("crm.deal.stage.change", {}).get("customer_title") != (
        "AI Permit-to-Change-Deal-Stage"
    ):
        raise ContractFailure("Wave 5 SDR habitat lost its existing exact CRM-stage action")

    vectors_by_id = {vector["id"]: vector for vector in vectors_v13["vectors"]}
    if set(vectors_by_id) != {item["consequence_type"] for item in consequences}:
        raise ContractFailure("v13 exact vectors must cover consequence registry v12")
    profiles_by_id = {item["fact_profile_id"]: item for item in facts_v15["profiles"]}
    semantics_by_id = {item["semantic_id"]: item for item in semantics_v17["entries"]}
    presentations_by_id = {item["semantic_id"]: item for item in presentations_v16["profiles"]}
    for label, mapping, source in (
        ("fact profile", profiles_by_id, facts_v15["profiles"]),
        ("semantic", semantics_by_id, semantics_v17["entries"]),
        ("presentation", presentations_by_id, presentations_v16["profiles"]),
    ):
        if len(mapping) != len(source):
            raise ContractFailure(f"registry v12 contains duplicate {label} ids")

    schema_path = "schemas/wave5-breadth-exact-facts-v1.schema.json"
    validator = jsonschema.Draft202012Validator(
        load_json(schema_path), registry=registry, format_checker=jsonschema.FormatChecker()
    )
    allowed_leading_fields = set(presentations_v16["allowed_leading_fields"])
    allowed_sections = set(presentations_v16["allowed_evidence_sections"])
    spec = (ROOT / "spec/wave5-breadth-exact-action-contract-v1.md").read_text(
        encoding="utf-8"
    )

    def invariants_hold(facts: dict[str, Any]) -> bool:
        if facts.get("target_is_dedicated_demo") is not True or facts.get("max_uses") != 1:
            return False
        action = facts.get("action")
        if action == "sales.discount.offer":
            return facts.get("discount_basis_points", 0) <= facts.get(
                "discount_ceiling_basis_points", -1
            )
        if action == "marketing.campaign.budget.change":
            return facts.get("requested_daily_budget_minor", 0) <= facts.get(
                "daily_budget_ceiling_minor", -1
            )
        if action in {"calendar.event.create"}:
            return facts.get("event_start_at", "") < facts.get("event_end_at", "")
        if action in {"sales.email.send", "email.message.send"}:
            return facts.get("daily_send_count_before", 0) < facts.get("daily_send_limit", 0)
        if action == "physical.relay.actuate":
            return facts.get("relay_state_before") != facts.get("requested_relay_state")
        if action and action.startswith("physical."):
            return all(
                facts.get(field) is True
                for field in (
                    "physical_safety_interlock_armed",
                    "human_safety_signoff_present",
                    "emergency_stop_verified",
                )
            )
        return True

    for consequence in added:
        consequence_type = consequence["consequence_type"]
        action_name = consequence["tool_names"][0]
        semantic_id = consequence["semantic_id"]
        vector = vectors_by_id[consequence_type]
        profile_id = vector["expected_fact_profile_id"]
        semantic = semantics_by_id.get(semantic_id)
        profile = profiles_by_id.get(profile_id)
        presentation = presentations_by_id.get(semantic_id)
        if semantic is None or semantic.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{consequence_type} lacks exact semantic binding")
        if profile is None or profile.get("facts_schema") != schema_path:
            raise ContractFailure(f"{consequence_type} lacks exact fact profile")
        expected_title = expected_titles[action_name]
        if presentation is None or presentation.get("customer_title") != expected_title:
            raise ContractFailure(f"{consequence_type} lacks exact human title")
        if expected_title not in spec:
            raise ContractFailure(f"{consequence_type} title is absent from the Wave 5 spec")
        if not {item["field"] for item in presentation.get("leading_fields", [])}.issubset(
            allowed_leading_fields
        ):
            raise ContractFailure(f"{consequence_type} uses unknown leading field")
        if not set(presentation.get("evidence_sections", [])).issubset(allowed_sections):
            raise ContractFailure(f"{consequence_type} uses unknown evidence section")
        if presentation.get("does_not_establish") != consequence.get("does_not_establish"):
            raise ContractFailure(f"{consequence_type} presentation limits drifted")
        trusted = set(consequence.get("trusted_fact_requirements", []))
        if not {"gateway_preflight_hmac", "gateway_pinned_dedicated_demo_target"}.issubset(
            trusted
        ):
            raise ContractFailure(f"{consequence_type} omits authenticated demo preflight")
        if select_semantic(semantics_v17, vector["candidate"]) != (semantic_id, None):
            raise ContractFailure(f"{consequence_type} is not selected exactly once")

        facts = vector["valid_authorization_facts"]
        errors = list(validator.iter_errors(facts))
        if errors:
            raise ContractFailure(
                f"{consequence_type} exact facts are invalid: {errors[0].message}"
            )
        if not invariants_hold(facts):
            raise ContractFailure(f"{consequence_type} violates exact invariants")
        if facts.get("fact_profile_id") != profile_id or facts.get("action") != action_name:
            raise ContractFailure(f"{consequence_type} vector identity drifted")
        if profile.get("facts_schema_digest") != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{consequence_type} schema digest is stale")

        for field, value in (
            ("target_is_dedicated_demo", False),
            ("max_uses", 2),
            ("preflight_expires_at", "not-a-time"),
        ):
            mutated = copy.deepcopy(facts)
            mutated[field] = value
            if validator.is_valid(mutated) and invariants_hold(mutated):
                raise ContractFailure(f"{consequence_type} accepted adversarial {field} mutation")
        if action_name.startswith("physical."):
            for field in (
                "physical_safety_interlock_armed",
                "human_safety_signoff_present",
                "emergency_stop_verified",
            ):
                mutated = copy.deepcopy(facts)
                mutated[field] = False
                if validator.is_valid(mutated) and invariants_hold(mutated):
                    raise ContractFailure(
                        f"{consequence_type} accepted unsafe {field} mutation"
                    )

    bound_profile_ids = {
        entry["fact_profile_id"]
        for entry in semantics_v17["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_profile_ids != set(profiles_by_id):
        raise ContractFailure("semantic registry v17 and fact profile registry v15 must bind exactly")


def validate_goal3a_portfolio_contract(registry: Registry) -> None:
    consequence_v12 = load_json("consequence_registry/v12.json")
    consequence_v13 = load_json("consequence_registry/v13.json")
    facts_v15 = load_json("fact_profiles/v15.json")
    facts_v16 = load_json("fact_profiles/v16.json")
    semantics_v17 = load_json("semantic_registry/v17.json")
    semantics_v18 = load_json("semantic_registry/v18.json")
    presentations_v16 = load_json("presentation_registry/v16.json")
    presentations_v17 = load_json("presentation_registry/v17.json")
    vectors_v14 = load_json("consequence_registry/test-vectors/v14.json")
    vectors_v15 = load_json("consequence_registry/test-vectors/v15.json")

    for instance, schema_path, label in (
        (consequence_v13, "consequence_registry/v13.schema.json", "consequence registry v13"),
        (facts_v16, "fact_profiles/v16.schema.json", "fact profile registry v16"),
        (semantics_v18, "semantic_registry/v18.schema.json", "semantic registry v18"),
        (presentations_v17, "presentation_registry/v17.schema.json", "presentation registry v17"),
    ):
        validate_instance(instance, schema_path, registry, label)

    for prior, current, key, label in (
        (consequence_v12, consequence_v13, "consequences", "consequence v13"),
        (facts_v15, facts_v16, "profiles", "fact profiles v16"),
        (presentations_v16, presentations_v17, "profiles", "presentation v17"),
        (vectors_v14, vectors_v15, "vectors", "portfolio vectors v15"),
    ):
        if current[key][: len(prior[key])] != prior[key]:
            raise ContractFailure(f"{label} is not an additive extension")

    expected_semantic_prefix = copy.deepcopy(semantics_v17["entries"])
    for entry in expected_semantic_prefix:
        if entry.get("semantic_id") == "keel.action.payment_execute.v1":
            entry["match"]["action_names"].append("stripe.payment_intent.create")
            entry["match"]["operations"].append("call.tools")
        elif entry.get("semantic_id") == "keel.action.payment_refund.v2":
            entry["match"]["action_names"].append("stripe.refund.create")
    if semantics_v18["entries"][: len(expected_semantic_prefix)] != (
        expected_semantic_prefix
    ):
        raise ContractFailure(
            "semantic v18 changed history beyond the two Great Bank aliases"
        )

    vectors = vectors_v15.get("vectors", [])
    action_names = [vector["candidate"]["action_name"] for vector in vectors]
    if len(vectors) != 96 or len(action_names) != len(set(action_names)):
        raise ContractFailure(
            "portfolio vectors v15 must cover exactly 96 unique consequential actions"
        )
    if {vector["candidate"]["action_name"] for vector in vectors[-2:]} != {
        "stripe.payment_intent.create",
        "stripe.refund.create",
    }:
        raise ContractFailure("portfolio vectors v15 lost the two Great Bank aliases")

    semantic_by_id = {
        entry["semantic_id"]: entry for entry in semantics_v18["entries"]
    }
    profile_by_id = {
        profile["fact_profile_id"]: profile for profile in facts_v16["profiles"]
    }
    presentation_by_semantic = {
        profile["semantic_id"]: profile
        for profile in presentations_v17["profiles"]
    }
    for vector in vectors:
        vector_id = vector["id"]
        actual_semantic, fallback = select_semantic(
            semantics_v18, vector["candidate"]
        )
        expected_semantic = vector["expected_semantic_id"]
        if actual_semantic != expected_semantic or fallback is not None:
            raise ContractFailure(
                f"{vector_id} selected {(actual_semantic, fallback)!r}"
            )
        semantic = semantic_by_id[expected_semantic]
        expected_profile = vector["expected_fact_profile_id"]
        if semantic.get("fact_profile_id") != expected_profile:
            raise ContractFailure(f"{vector_id} selected the wrong fact profile")
        profile = profile_by_id[expected_profile]
        facts = vector["valid_authorization_facts"]
        if (
            facts.get("fact_profile_id") != expected_profile
            or facts.get("action") != profile.get("authorized_action")
        ):
            raise ContractFailure(f"{vector_id} exact-fact identity drifted")
        validate_instance(
            facts,
            str(profile["facts_schema"]),
            registry,
            f"{vector_id} exact facts",
        )
        presentation = presentation_by_semantic.get(expected_semantic)
        if (
            presentation is None
            or presentation.get("customer_title") != vector["expected_title"]
        ):
            raise ContractFailure(f"{vector_id} rendered the wrong AI Permit-to-X")


def set_vector_path(document: dict[str, Any], path: list[Any], value: Any) -> None:
    current: Any = document
    for segment in path[:-1]:
        current = current[segment]
    current[path[-1]] = value


def normalize_summary_value(value: Any) -> str:
    normalized = unicodedata.normalize("NFC", str(value))
    return re.sub(r"\s+", " ", normalized).strip()


def render_human_summary(
    document: dict[str, Any],
    summary_semantics: dict[str, Any],
) -> str:
    templates = summary_semantics["templates"]
    artifact_kind = document["artifact_kind"]
    authorization = document["authorization"]
    lifecycle = document["lifecycle"]
    outcome = document["outcome"]
    verification = document["verification"]
    values = {
        "agent": normalize_summary_value(document["identity"].get("agent") or "the agent"),
        "action": normalize_summary_value(authorization["action"]),
        "target": normalize_summary_value(authorization["target"]),
        "issued_at": normalize_summary_value(lifecycle.get("issued_at")),
        "expires_at": normalize_summary_value(lifecycle.get("expires_at")),
        "provider_state": normalize_summary_value(outcome.get("provider_state")),
        "provider_object_id": normalize_summary_value(outcome.get("provider_object_id")),
        "integrity_verdict": normalize_summary_value(verification["integrity_verdict"]),
        "trust_mode": normalize_summary_value(verification["trust_mode"]),
    }
    sentences: list[str] = []
    if artifact_kind == "denial":
        sentences.append(templates["denial"].format(**values))
    elif artifact_kind == "review":
        sentences.append(templates["review"].format(**values))
    else:
        sentences.append(templates["permit_authorization"].format(**values))
        if lifecycle.get("expires_at") is None:
            sentences.append(templates["permit_validity_unbounded"].format(**values))
        else:
            sentences.append(templates["permit_validity_bounded"].format(**values))
        if outcome["dispatch_state"] == "not_dispatched":
            sentences.append(templates["not_dispatched"])
        elif outcome.get("provider_state") and outcome.get("provider_object_id"):
            sentences.append(templates["provider_observed_with_id"].format(**values))
        elif outcome.get("provider_state"):
            sentences.append(templates["provider_observed_without_id"].format(**values))
        else:
            sentences.append(templates["outcome_unknown"])
    sentences.append(templates["verification"].format(**values))
    return summary_semantics["output"]["sentence_separator"].join(sentences)


def package_inventory_valid(document: dict[str, Any]) -> bool:
    entries = document["entries"]
    paths = [entry["path"] for entry in entries]
    if len(paths) != len(set(paths)):
        return False
    role_by_path = {entry["path"]: entry["role"] for entry in entries}
    return (
        role_by_path.get(document["primary_view"]) == "human_view"
        and role_by_path.get(document["signed_evidence"]) == "signed_evidence"
    )


def validate_human_artifact_contract(registry: Registry) -> None:
    presentation = load_json("presentation_registry/v6.json")
    vectors = load_json("presentation_registry/test-vectors/v2.json")
    corpus = load_json("test-vectors/permit_human_artifact/v1/corpus.json")

    human_contract = presentation["human_artifact_contract"]
    if set(human_contract["lifecycle_fields"]["required"]) != {
        "issued_at",
        "expires_at",
        "status",
    }:
        raise ContractFailure("human artifact lifecycle must require issued_at, expires_at, and status")
    required_advanced = {
        "signed_evidence_json",
        "canonical_signed_bytes",
        "canonical_signed_bytes_hex",
        "canonical_signed_bytes_base64",
        "signatures",
        "digests",
        "contract_pins",
    }
    if not required_advanced.issubset(set(human_contract["advanced_representations"])):
        raise ContractFailure("human artifact contract omits an advanced representation")

    profiles = {
        profile["semantic_id"]: profile for profile in presentation["profiles"]
    }
    fallbacks = {
        profile["presentation_profile_id"]: profile
        for profile in presentation["fallback_profiles"]
    }
    state_titles = human_contract["state_titles"]
    status_labels = human_contract["status_labels"]
    for vector in vectors["title_vectors"]:
        artifact_kind = vector["artifact_kind"]
        if artifact_kind == "denial":
            actual = state_titles["denial"]
        elif artifact_kind == "review":
            actual = state_titles["review"]
        else:
            profile = profiles.get(vector.get("semantic_id"))
            if profile is None:
                profile = fallbacks[vector["fallback"]]
            actual = profile["customer_title"]
        if actual != vector["expected_title"]:
            raise ContractFailure(
                f"human title vector {vector['id']} rendered {actual!r}"
            )

    expected_summary = vectors["summary_contract"]
    actual_summary = human_contract["summary"]
    if actual_summary["position"] != expected_summary["expected_position"]:
        raise ContractFailure("human summary is not positioned at the end")
    if actual_summary["derivation"] != expected_summary["expected_derivation"]:
        raise ContractFailure("human summary is not verifier-derived")
    if actual_summary["template"] != expected_summary["expected_template"]:
        raise ContractFailure("human summary template drifted")
    if set(actual_summary["required_inputs"]) != set(expected_summary["required_inputs"]):
        raise ContractFailure("human summary input contract drifted")
    if set(actual_summary["required_inputs"]).intersection(
        expected_summary["forbidden_inputs"]
    ):
        raise ContractFailure("human summary admits an untrusted input")

    summary_semantics = load_json(actual_summary["template"])
    if summary_semantics.get("version") != "keel.permit.human_summary.v1":
        raise ContractFailure("human summary semantic version is invalid")
    security = summary_semantics.get("security", {})
    if security.get("caller_supplied_title_allowed") is not False:
        raise ContractFailure("human summary semantics admit a caller title")
    if security.get("caller_supplied_summary_allowed") is not False:
        raise ContractFailure("human summary semantics admit caller summary text")
    if security.get("summary_is_authorization_input") is not False:
        raise ContractFailure("human summary semantics interfere with authorization")
    if security.get("summary_is_verifier_verdict_input") is not False:
        raise ContractFailure("human summary semantics interfere with verdicts")

    artifact_schema = load_json(corpus["artifact_schema"])
    artifact_validator = jsonschema.Draft202012Validator(
        artifact_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    valid_artifacts: dict[str, dict[str, Any]] = {}
    for vector in corpus["valid_artifacts"]:
        document = vector["document"]
        errors = list(artifact_validator.iter_errors(document))
        if errors:
            raise ContractFailure(
                f"human artifact vector {vector['id']} is invalid: {errors[0].message}"
            )
        rendered_summary = render_human_summary(document, summary_semantics)
        if document["summary"]["text"] != rendered_summary:
            raise ContractFailure(
                f"human artifact vector {vector['id']} summary drifted: "
                f"{rendered_summary!r}"
            )
        expected_state_label = status_labels[document["lifecycle"]["status"]]
        if document["state_label"] != expected_state_label:
            raise ContractFailure(
                f"human artifact vector {vector['id']} state label drifted"
            )
        valid_artifacts[vector["id"]] = document
    for mutation in corpus["artifact_mutations"]:
        document = copy.deepcopy(valid_artifacts[mutation["base"]])
        set_vector_path(document, mutation["path"], mutation["value"])
        if artifact_validator.is_valid(document):
            raise ContractFailure(
                f"human artifact mutation {mutation['id']} was accepted"
            )
    for mutation in corpus["render_mutations"]:
        document = copy.deepcopy(valid_artifacts[mutation["base"]])
        set_vector_path(document, mutation["path"], mutation["value"])
        if not artifact_validator.is_valid(document):
            raise ContractFailure(
                f"human render mutation {mutation['id']} did not reach comparison"
            )
        if mutation["field"] == "summary":
            comparison_failed = (
                document["summary"]["text"]
                != render_human_summary(document, summary_semantics)
            )
        elif mutation["field"] == "title":
            semantic_id = document["source"]["semantic_id"]
            expected_title = profiles[semantic_id]["customer_title"]
            comparison_failed = document["title"] != expected_title
        elif mutation["field"] == "state_label":
            expected_state_label = status_labels[document["lifecycle"]["status"]]
            comparison_failed = document["state_label"] != expected_state_label
        else:
            raise ContractFailure(
                f"human render mutation {mutation['id']} has an unknown field"
            )
        if not comparison_failed:
            raise ContractFailure(
                f"human render mutation {mutation['id']} did not produce a mismatch"
            )

    package_schema = load_json(corpus["package_schema"])
    package_validator = jsonschema.Draft202012Validator(
        package_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    valid_packages: dict[str, dict[str, Any]] = {}
    for vector in corpus["valid_package_manifests"]:
        document = vector["document"]
        errors = list(package_validator.iter_errors(document))
        if errors:
            raise ContractFailure(
                f"Permit package vector {vector['id']} is invalid: {errors[0].message}"
            )
        if not package_inventory_valid(document):
            raise ContractFailure(
                f"Permit package vector {vector['id']} has inconsistent inventory"
            )
        valid_packages[vector["id"]] = document
    for mutation in corpus["package_mutations"]:
        document = copy.deepcopy(valid_packages[mutation["base"]])
        set_vector_path(document, mutation["path"], mutation["value"])
        if package_validator.is_valid(document):
            raise ContractFailure(
                f"Permit package mutation {mutation['id']} was accepted"
            )
    for mutation in corpus["package_inventory_mutations"]:
        document = copy.deepcopy(valid_packages[mutation["base"]])
        set_vector_path(document, mutation["path"], mutation["value"])
        if not package_validator.is_valid(document):
            raise ContractFailure(
                f"Permit package inventory mutation {mutation['id']} did not reach comparison"
            )
        if package_inventory_valid(document):
            raise ContractFailure(
                f"Permit package inventory mutation {mutation['id']} was accepted"
            )


def validate_fact_profiles(registry: Registry) -> None:
    fact_registry = load_json("fact_profiles/v1.json")
    semantics = load_json("semantic_registry/v3.json")
    validate_instance(
        fact_registry,
        "fact_profiles/v1.schema.json",
        registry,
        "fact profile registry",
    )

    profiles = fact_registry["profiles"]
    by_profile_id = {profile["fact_profile_id"]: profile for profile in profiles}
    if len(by_profile_id) != len(profiles):
        raise ContractFailure("fact profile registry contains duplicate ids")

    semantic_ids = {entry["semantic_id"] for entry in semantics["entries"]}
    for profile in profiles:
        schema_path = profile["facts_schema"]
        schema_file = ROOT / schema_path
        if not schema_file.is_file():
            raise ContractFailure(
                f"{profile['fact_profile_id']} references missing schema {schema_path}"
            )
        actual_schema_digest = _sha256_file(schema_file)
        if profile["facts_schema_digest"] != actual_schema_digest:
            raise ContractFailure(
                f"{profile['fact_profile_id']} facts schema digest is stale"
            )
        unknown_semantics = sorted(set(profile["semantic_ids"]) - semantic_ids)
        if unknown_semantics:
            raise ContractFailure(
                f"{profile['fact_profile_id']} references unknown semantics: "
                f"{unknown_semantics}"
            )
        paths = [field["path"] for field in profile["fields"]]
        if len(paths) != len(set(paths)):
            raise ContractFailure(
                f"{profile['fact_profile_id']} contains duplicate field paths"
            )
        for field in profile["fields"]:
            if (
                field["classification"] in {"personal_data", "free_text", "secret"}
                and field["bulk_export_disclosure"] != "omit"
            ):
                raise ContractFailure(
                    f"{profile['fact_profile_id']} exposes sensitive field "
                    f"{field['path']} in bulk exports"
                )
            if field["classification"] in {"personal_data", "free_text"} and (
                field["commitment_method"] == "none"
            ):
                raise ContractFailure(
                    f"{profile['fact_profile_id']} leaves sensitive field "
                    f"{field['path']} uncommitted"
                )

    bound_profile_ids: set[str] = set()
    for entry in semantics["entries"]:
        profile_id = entry.get("fact_profile_id")
        if profile_id is None:
            continue
        profile = by_profile_id.get(profile_id)
        if profile is None:
            raise ContractFailure(
                f"{entry['semantic_id']} references unknown fact profile {profile_id}"
            )
        if entry["semantic_id"] not in profile["semantic_ids"]:
            raise ContractFailure(
                f"{entry['semantic_id']} is absent from {profile_id}.semantic_ids"
            )
        bound_profile_ids.add(profile_id)
    if bound_profile_ids != set(by_profile_id):
        raise ContractFailure("every eligible fact profile must be bound by a semantic")
    payment_entry = next(
        entry
        for entry in semantics["entries"]
        if entry["semantic_id"] == "keel.action.payment_execute.v1"
    )
    if payment_entry.get("fact_profile_id") != "keel.facts.payment_exact.v1":
        raise ContractFailure("payment.execute is not bound to exact payment facts")

    latest_fact_registry = load_json("fact_profiles/v5.json")
    latest_semantics = load_json("semantic_registry/v7.json")
    validate_instance(
        latest_fact_registry,
        "fact_profiles/v5.schema.json",
        registry,
        "fact profile registry v5",
    )
    latest_semantic_ids = {
        entry["semantic_id"] for entry in latest_semantics["entries"]
    }
    latest_profile_ids: set[str] = set()
    for profile in latest_fact_registry["profiles"]:
        profile_id = profile["fact_profile_id"]
        if profile_id in latest_profile_ids:
            raise ContractFailure("fact profile registry v5 contains duplicate ids")
        latest_profile_ids.add(profile_id)
        schema_path = profile["facts_schema"]
        if profile["facts_schema_digest"] != _sha256_file(ROOT / schema_path):
            raise ContractFailure(f"{profile_id} v5 facts schema digest is stale")
        unknown_semantics = sorted(
            set(profile["semantic_ids"]) - latest_semantic_ids
        )
        if unknown_semantics:
            raise ContractFailure(
                f"{profile_id} v5 references unknown semantics: {unknown_semantics}"
            )
    bound_latest_profiles = {
        entry["fact_profile_id"]
        for entry in latest_semantics["entries"]
        if entry.get("fact_profile_id") is not None
    }
    if bound_latest_profiles != latest_profile_ids:
        raise ContractFailure(
            "semantic registry v7 and fact profile registry v5 must bind exactly"
        )

    vectors = load_json("fact_profiles/test-vectors/v1.json")
    profile = by_profile_id.get(vectors.get("profile_id"))
    if profile is None:
        raise ContractFailure("fact-profile vectors reference an unknown profile")
    facts_schema = load_json(profile["facts_schema"])
    validator = jsonschema.Draft202012Validator(
        facts_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    for vector in vectors["vectors"]:
        actual_valid = not list(validator.iter_errors(vector["facts"]))
        if actual_valid != vector["expected_valid"]:
            raise ContractFailure(
                f"fact vector {vector['id']} validity was {actual_valid}, "
                f"expected {vector['expected_valid']}"
            )
        binding = vector.get("semantic_binding")
        if binding is None:
            continue
        validate_instance(
            binding,
            "schemas/permit-semantic-binding-v1.schema.json",
            registry,
            f"fact vector {vector['id']} semantic binding",
        )
        if not actual_valid:
            raise ContractFailure(
                f"fact vector {vector['id']} binds a schema-invalid fact object"
            )
        if binding["authorization_facts_digest"] != digest(vector["facts"]):
            raise ContractFailure(
                f"fact vector {vector['id']} does not bind its canonical facts"
            )
        if binding["fact_profile_registry_digest"] != _sha256_file(
            ROOT / "fact_profiles/v1.json"
        ):
            raise ContractFailure(
                f"fact vector {vector['id']} has a stale fact registry digest"
            )
        if binding["fact_profile_entry_digest"] != digest(profile):
            raise ContractFailure(
                f"fact vector {vector['id']} has a stale fact profile digest"
            )


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def assemble_pack(corpus: dict[str, Any]) -> dict[str, Any]:
    valid = corpus["valid"]
    pack = copy.deepcopy(valid["pack"])
    pack["root"]["work_package"] = copy.deepcopy(valid["work_package"])
    pack["authorities"] = [copy.deepcopy(valid["authority"])]
    pack["child_permits"] = [copy.deepcopy(valid["child_permit"])]
    pack["value_events"] = copy.deepcopy(valid["value_events"])
    pack["lifecycle_events"] = copy.deepcopy(valid["lifecycle_events"])
    return pack


def work_failure_code(corpus: dict[str, Any]) -> str | None:
    valid = corpus["valid"]
    request = valid["work_request"]
    package = valid["work_package"]
    authority = valid["authority"]
    child = valid["child_permit"]
    value_events = valid["value_events"]
    pack = assemble_pack(corpus)

    artifacts = pack.get("artifacts")
    if not isinstance(artifacts, list):
        return "WORK_ARTIFACT_INTEGRITY_INVALID"
    artifacts_by_id: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
        artifact_id = artifact.get("artifact_id")
        if not isinstance(artifact_id, str) or artifact_id in artifacts_by_id:
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
        if artifact.get("artifact_digest") != digest(artifact.get("payload")):
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
        artifacts_by_id[artifact_id] = artifact

    def reference_resolves(reference: Any) -> bool:
        if not isinstance(reference, dict):
            return False
        artifact = artifacts_by_id.get(reference.get("artifact_id"))
        return bool(
            artifact is not None
            and artifact.get("artifact_type") == reference.get("artifact_type")
            and artifact.get("artifact_digest") == reference.get("artifact_digest")
        )

    if not reference_resolves(pack["root"]["permit_artifact"]):
        return "WORK_ARTIFACT_INTEGRITY_INVALID"
    for child_evidence in pack["child_permits"]:
        if not reference_resolves(child_evidence.get("permit_artifact")):
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
        dispatch_reference = child_evidence.get("dispatch_boundary_evidence")
        if dispatch_reference is not None and not reference_resolves(dispatch_reference):
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
    for reference in pack["evidence_artifacts"]:
        if not reference_resolves(reference):
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
    for event in pack["value_events"]:
        evidence = event.get("evidence_reference")
        if evidence is None:
            continue
        artifact = artifacts_by_id.get(evidence.get("artifact_id"))
        if artifact is None or artifact.get("artifact_digest") != evidence.get(
            "artifact_digest"
        ):
            return "WORK_ARTIFACT_INTEGRITY_INVALID"
    for event in pack["lifecycle_events"]:
        matches = [
            artifact
            for artifact in artifacts
            if artifact.get("artifact_type") == "governance_event"
            and artifact.get("artifact_digest") == event.get("event_digest")
        ]
        if len(matches) != 1:
            return "WORK_ARTIFACT_INTEGRITY_INVALID"

    issued_ids = {item["authority_id"] for item in package["issued_authorities"]}
    excluded_ids = {item["authority_id"] for item in package["excluded_authorities"]}
    if not set(package["required_authority_ids"]).issubset(issued_ids - excluded_ids):
        return "WORK_REQUIRED_AUTHORITY_MISSING"
    if package["requested_authority_set_hash"] != digest(request["requested_authorities"]):
        return "WORK_AUTHORITY_SET_HASH_MISMATCH"

    canonical_authority = copy.deepcopy(authority)
    canonical_authority.pop("authority_canonical_hash", None)
    if authority["authority_canonical_hash"] != digest(canonical_authority):
        return "WORK_AUTHORITY_SET_HASH_MISMATCH"
    references = sorted(package["issued_authorities"], key=lambda item: item["authority_id"])
    if package["issued_authority_set_hash"] != digest(references):
        return "WORK_AUTHORITY_SET_HASH_MISMATCH"

    binding = child["work_binding"]
    if (
        binding["root_permit_id"] != authority["root_permit_id"]
        or binding["authority_id"] != authority["authority_id"]
        or binding["authority_canonical_hash"] != authority["authority_canonical_hash"]
        or binding["root_manifest_hash"] != digest(package)
    ):
        return "WORK_CHILD_BINDING_MISMATCH"

    sequences = [event["authority_sequence"] for event in value_events]
    transition_ids = [event["idempotency_key_digest"] for event in value_events]
    if sequences != list(range(1, len(sequences) + 1)) or len(transition_ids) != len(set(transition_ids)):
        return "WORK_VALUE_EVENT_SEQUENCE_INVALID"
    if any(event["currency"] != authority["currency"] for event in value_events):
        return "WORK_VALUE_CONSERVATION_MISMATCH"

    outstanding = 0
    terminal_value = 0
    for event in value_events:
        amount = event["amount_minor"]
        if event["event_type"] == "reserved":
            outstanding += amount
        elif event["event_type"] == "released":
            outstanding -= amount
        elif event["event_type"] in {"settled", "outcome_unknown"}:
            outstanding -= amount
            terminal_value += amount
        if outstanding < 0 or outstanding + terminal_value > authority["value_max_minor"]:
            return "WORK_VALUE_CONSERVATION_MISMATCH"
        if event["event_type"] == "settled":
            evidence = event.get("evidence_reference")
            if not evidence:
                return "WORK_SETTLEMENT_EVIDENCE_MISSING"
            if not any(
                artifact["artifact_id"] == evidence["artifact_id"]
                and artifact["artifact_digest"] == evidence["artifact_digest"]
                for artifact in pack["evidence_artifacts"]
            ):
                return "WORK_SETTLEMENT_EVIDENCE_MISSING"

    population_commitments = {
        item["population"]: item for item in pack["scope_commitment"]["populations"]
    }
    signature = pack.get("scope_commitment_signature")
    if not isinstance(signature, dict):
        return "WORK_SCOPE_COMMITMENT_MISSING"
    if signature.get("canonical_hash") != pack["declared_cutoff"]["checkpoint_digest"]:
        return "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID"
    if set(population_commitments) != set(POPULATION_PATHS):
        return "WORK_SCOPE_COMMITMENT_MISSING"
    for population, pack_path in POPULATION_PATHS.items():
        values = pack[pack_path]
        commitment = population_commitments[population]
        if commitment["included_count"] != len(values) or commitment["included_set_hash"] != digest(values):
            return "WORK_SCOPE_POPULATION_MISMATCH"
    signature_payload = {
        "version": "keel.work_scope_commitment_signature_payload.v1",
        "project_id": pack["project_id"],
        "root_permit_id": pack["root_permit_id"],
        "export_source": pack["export_source"],
        "recorded_through": pack["declared_cutoff"]["recorded_through"],
        "checkpoint_id": pack["declared_cutoff"]["checkpoint_id"],
        "scope_commitment": pack["scope_commitment"],
        "binding_key_id": signature["binding_key_id"],
    }
    if signature.get("canonical_hash") != digest(signature_payload):
        return "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID"

    if set(pack["requested_claims"]) != WORK_CLAIMS:
        return "WORK_VERSION_UNSUPPORTED"
    return None


def mutate(root: dict[str, Any], mutation: dict[str, Any]) -> None:
    parts = mutation["target"].split(".")
    current: Any = root["valid"]
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = parts[-1]
    if mutation.get("operation") == "delete":
        if isinstance(current, list):
            del current[int(final)]
        else:
            del current[final]
        return
    if isinstance(current, list):
        current[int(final)] = copy.deepcopy(mutation["value"])
    else:
        current[final] = copy.deepcopy(mutation["value"])


def validate_work_contract(registry: Registry) -> None:
    corpus = load_json("test-vectors/permit_to_work/v1/corpus.json")
    valid = corpus["valid"]
    pack = assemble_pack(corpus)
    validate_instance(valid["work_request"], "schemas/work-request-v1.schema.json", registry, "work request")
    validate_instance(valid["work_package"], "schemas/work-package-v1.schema.json", registry, "work package")
    validate_instance(valid["authority"], "schemas/work-authority-v1.schema.json", registry, "work authority")
    for index, event in enumerate(valid["value_events"]):
        validate_instance(event, "schemas/work-value-event-v1.schema.json", registry, f"value event {index}")
    validate_instance(pack, "schemas/work-chain-pack-v1.schema.json", registry, "work-chain pack")
    replacement_request = copy.deepcopy(valid["work_request"])
    replacement_request["existing_authority"] = {
        "mode": "replace_existing",
        "root_permit_id": "11111111-1111-4111-8111-111111111111",
    }
    validate_instance(
        replacement_request,
        "schemas/work-request-v1.schema.json",
        registry,
        "replacement work request",
    )
    additional_request = copy.deepcopy(valid["work_request"])
    additional_request["existing_authority"] = {
        "mode": "add_separate",
        "root_permit_id": "11111111-1111-4111-8111-111111111111",
        "combined_risk_acknowledged": True,
    }
    validate_instance(
        additional_request,
        "schemas/work-request-v1.schema.json",
        registry,
        "additional work request",
    )
    invalid_additional = copy.deepcopy(additional_request)
    del invalid_additional["existing_authority"]["combined_risk_acknowledged"]
    invalid_schema = load_json("schemas/work-request-v1.schema.json")
    invalid_errors = list(
        jsonschema.Draft202012Validator(
            invalid_schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).iter_errors(invalid_additional)
    )
    if not invalid_errors:
        raise ContractFailure("add_separate work request accepted without combined-risk acknowledgement")
    if work_failure_code(corpus) is not None:
        raise ContractFailure(f"valid Work corpus failed with {work_failure_code(corpus)}")

    for mutation in corpus["negative_mutations"]:
        mutated = copy.deepcopy(corpus)
        mutate(mutated, mutation)
        actual = work_failure_code(mutated)
        if actual != mutation["expected_failure_code"]:
            raise ContractFailure(
                f"Work mutation {mutation['id']} got {actual!r}, expected {mutation['expected_failure_code']!r}"
            )


def validate_work_authority_v2_contract(registry: Registry) -> None:
    """Validate the additive heterogeneous authority contract and mutations."""

    vectors = load_json("test-vectors/permit_to_work/v2/authority-vectors.json")
    schema = load_json("schemas/work-authority-v2.schema.json")
    comparator = load_json("comparator_registry/work-action-authority-v2.json")
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )

    if vectors.get("version") != "keel.permit_to_work_authority_vectors.v2":
        raise ContractFailure("Work authority v2 vectors have the wrong version")
    if vectors.get("canonicalization_profile") != "keel.canonical_json.payload.v1":
        raise ContractFailure("Work authority v2 vectors use an unsupported canonicalization profile")
    if comparator.get("version") != "work-action-authority.v2":
        raise ContractFailure("Work authority v2 comparator has the wrong version")
    if set(comparator.get("value_bindings", {})) != {
        "none",
        "declared_bounded",
        "provider_verified",
    }:
        raise ContractFailure("Work authority v2 comparator changed its value-binding modes")

    valid_by_id: dict[str, dict[str, Any]] = {}
    for entry in vectors.get("valid", []):
        vector_id = entry.get("id")
        authority = entry.get("authority")
        if not isinstance(vector_id, str) or not isinstance(authority, dict):
            raise ContractFailure("Work authority v2 valid vector is malformed")
        if vector_id in valid_by_id:
            raise ContractFailure(f"duplicate Work authority v2 vector id: {vector_id}")
        errors = list(validator.iter_errors(authority))
        if errors:
            raise ContractFailure(
                f"Work authority v2 vector {vector_id} failed schema: {errors[0].message}"
            )
        preimage = copy.deepcopy(authority)
        expected_hash = preimage.pop("authority_canonical_hash")
        actual_hash = digest(preimage)
        if actual_hash != expected_hash:
            raise ContractFailure(
                f"Work authority v2 vector {vector_id} has stale canonical hash: "
                f"{expected_hash!r} != {actual_hash!r}"
            )
        valid_by_id[vector_id] = authority

    for mutation in vectors.get("negative_mutations", []):
        mutation_id = mutation.get("id")
        base_id = mutation.get("base")
        if base_id not in valid_by_id:
            raise ContractFailure(
                f"Work authority v2 mutation {mutation_id} names unknown base {base_id!r}"
            )
        authority = copy.deepcopy(valid_by_id[base_id])
        current: Any = authority
        path = mutation.get("path")
        if not isinstance(path, list) or not path:
            raise ContractFailure(f"Work authority v2 mutation {mutation_id} has no path")
        for part in path[:-1]:
            current = current[part]
        final = path[-1]
        if mutation.get("operation") == "delete":
            del current[final]
        else:
            current[final] = copy.deepcopy(mutation.get("value"))

        if validator.is_valid(authority):
            raise ContractFailure(
                f"Work authority v2 mutation {mutation_id} was accepted by the schema"
            )
        if authority.get("version") != "keel.work_authority.v2":
            actual_failure = "WORK_VERSION_UNSUPPORTED"
        elif authority.get("comparator_version") != "work-action-authority.v2":
            actual_failure = "WORK_AUTHORITY_SCOPE_MISMATCH"
        else:
            actual_failure = "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID"
        expected_failure = mutation.get("expected_failure_code")
        if actual_failure != expected_failure:
            raise ContractFailure(
                f"Work authority v2 mutation {mutation_id} got {actual_failure!r}, "
                f"expected {expected_failure!r}"
            )


def validate_concierge_semantic_contract(registry: Registry) -> None:
    """Prove the outbound-call title is server-selected and fact-bound."""

    base_semantics = load_json("semantic_registry/v18.json")
    semantics = load_json("semantic_registry/v19.json")
    base_presentations = load_json("presentation_registry/v17.json")
    presentations = load_json("presentation_registry/v18.json")
    base_facts = load_json("fact_profiles/v16.json")
    fact_profiles = load_json("fact_profiles/v17.json")
    vectors = load_json("test-vectors/telephony-call-outbound-v1.json")

    validate_instance(
        semantics,
        "semantic_registry/v19.schema.json",
        registry,
        "Concierge semantic registry v19",
    )
    validate_instance(
        presentations,
        "presentation_registry/v18.schema.json",
        registry,
        "Concierge presentation registry v18",
    )
    validate_instance(
        fact_profiles,
        "fact_profiles/v17.schema.json",
        registry,
        "Concierge fact profile registry v17",
    )
    if semantics["entries"][:-1] != base_semantics["entries"]:
        raise ContractFailure("semantic registry v19 is not an additive v18 extension")
    if presentations["profiles"][:-1] != base_presentations["profiles"]:
        raise ContractFailure("presentation registry v18 is not an additive v17 extension")
    if fact_profiles["profiles"][:-1] != base_facts["profiles"]:
        raise ContractFailure("fact profile registry v17 is not an additive v16 extension")
    if len(semantics["entries"]) != len(base_semantics["entries"]) + 1:
        raise ContractFailure("semantic registry v19 must add exactly one semantic")
    if len(presentations["profiles"]) != len(base_presentations["profiles"]) + 1:
        raise ContractFailure("presentation registry v18 must add exactly one profile")
    if len(fact_profiles["profiles"]) != len(base_facts["profiles"]) + 1:
        raise ContractFailure("fact profile registry v17 must add exactly one profile")

    semantic_id = vectors["expected_semantic_id"]
    semantic = next(
        (entry for entry in semantics["entries"] if entry["semantic_id"] == semantic_id),
        None,
    )
    presentation = next(
        (
            profile
            for profile in presentations["profiles"]
            if profile["semantic_id"] == semantic_id
        ),
        None,
    )
    fact_profile_id = vectors["expected_fact_profile_id"]
    fact_profile = next(
        (
            profile
            for profile in fact_profiles["profiles"]
            if profile["fact_profile_id"] == fact_profile_id
        ),
        None,
    )
    if semantic is None or presentation is None or fact_profile is None:
        raise ContractFailure("outbound-call semantic, presentation, or fact profile is absent")
    if semantic.get("trusted_source_kinds") != ["telephony_origination_service"]:
        raise ContractFailure("outbound-call semantic source is not server-controlled")
    if semantic.get("fact_profile_id") != fact_profile_id:
        raise ContractFailure("outbound-call semantic names the wrong fact profile")
    if presentation.get("customer_title") != vectors["expected_title"]:
        raise ContractFailure("outbound-call presentation title changed")
    if not {
        "the_content_of_anything_said_on_the_call",
        "authorization_of_commitments_made_verbally_during_the_call",
    }.issubset(set(presentation.get("does_not_establish", []))):
        raise ContractFailure("outbound-call title lacks its conversation-governance ceiling")
    if "/provider_wire_body_digest" not in fact_profile.get(
        "material_request_fact_paths", []
    ):
        raise ContractFailure("outbound-call facts do not bind the provider wire body")

    actual_semantic, fallback = select_semantic(semantics, vectors["candidate"])
    if actual_semantic != semantic_id or fallback is not None:
        raise ContractFailure(
            f"outbound-call selector returned {(actual_semantic, fallback)!r}"
        )
    facts_schema_path = "schemas/telephony-call-outbound-exact-facts-v1.schema.json"
    facts_schema = load_json(facts_schema_path)
    facts_validator = jsonschema.Draft202012Validator(
        facts_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    valid_facts = vectors["valid_authorization_facts"]
    if not facts_validator.is_valid(valid_facts):
        raise ContractFailure("valid outbound-call authorization facts failed schema")
    serialized_facts = json.dumps(valid_facts, sort_keys=True)
    if "+14155550123" in serialized_facts or '"destination"' in serialized_facts:
        raise ContractFailure("outbound-call verifier-safe facts expose a raw destination")

    for case in vectors["negative_cases"]:
        mutated = copy.deepcopy(vectors)
        parts = case["target"].split(".")
        current: Any = mutated
        for part in parts[:-1]:
            current = current[part]
        if case.get("operation") == "delete":
            del current[parts[-1]]
        else:
            current[parts[-1]] = copy.deepcopy(case.get("value"))
        if case["expected"] == "fallback":
            selected, selected_fallback = select_semantic(
                semantics, mutated["candidate"]
            )
            if selected is not None or selected_fallback is None:
                raise ContractFailure(
                    f"outbound-call case {case['id']} did not fall back safely"
                )
        elif facts_validator.is_valid(mutated["valid_authorization_facts"]):
            raise ContractFailure(
                f"outbound-call case {case['id']} earned facts with invalid material"
            )


def validate_work_v2_contract_objects(registry: Registry) -> None:
    """Validate the strict v2 objects and cross-object invariants."""

    vectors = load_json("test-vectors/permit_to_work/v2/contract-vectors.json")
    pack_schema = load_json("schemas/work-chain-pack-v2.schema.json")
    lifecycle = pack_schema["$defs"]["lifecycle_event"]
    lifecycle_types = set(lifecycle["properties"]["event_type"]["enum"])
    if not {
        "work.authority.revoked",
        "work.delegation.revoked",
        "principal.revoked",
        "credential.revoked",
    }.issubset(lifecycle_types):
        raise ContractFailure("Work v2 lifecycle cannot express every dispatch revocation")
    if not {
        "authority_id",
        "delegation_id",
        "principal_id",
        "authenticated_credential_id_digest",
    }.issubset(lifecycle["properties"]):
        raise ContractFailure("Work v2 lifecycle revocations lack exact subject identifiers")
    authority_vectors = load_json(
        "test-vectors/permit_to_work/v2/authority-vectors.json"
    )
    request = vectors["request"]
    package = vectors["package"]
    bindings = vectors["bindings"]
    value_events = vectors["value_events"]
    review_transition = vectors["review_transition"]
    provider_value_fact = vectors["provider_value_fact"]
    dispatch_boundary = vectors["dispatch_boundary"]
    summary = vectors["summary"]

    validate_instance(request, "schemas/work-request-v2.schema.json", registry, "Work request v2")
    validate_instance(package, "schemas/work-package-v2.schema.json", registry, "Work package v2")
    for index, binding in enumerate(bindings):
        validate_instance(
            binding,
            "schemas/work-binding-v2.schema.json",
            registry,
            f"Work binding v2 {index}",
        )
    for index, event in enumerate(value_events):
        validate_instance(
            event,
            "schemas/work-value-event-v2.schema.json",
            registry,
            f"Work value event v2 {index}",
        )
    validate_instance(
        review_transition,
        "schemas/work-review-transition-v1.schema.json",
        registry,
        "Work review transition v1",
    )
    validate_instance(
        provider_value_fact,
        "schemas/provider-value-fact-v1.schema.json",
        registry,
        "provider value fact v1",
    )
    validate_instance(
        dispatch_boundary,
        "schemas/work-dispatch-boundary-v2.schema.json",
        registry,
        "Work dispatch boundary v2",
    )
    validate_instance(summary, "schemas/work-summary-v1.schema.json", registry, "Work summary v1")

    authorities = {
        entry["authority"]["authority_id"]: entry["authority"]
        for entry in authority_vectors["valid"]
    }

    def request_invariants_hold(candidate: dict[str, Any]) -> bool:
        lanes = candidate.get("requested_authorities")
        if not isinstance(lanes, list):
            return False
        lane_ids = [lane.get("authority_id") for lane in lanes if isinstance(lane, dict)]
        if len(lane_ids) != len(lanes) or len(lane_ids) != len(set(lane_ids)):
            return False
        if not set(candidate.get("required_authority_ids", [])).issubset(lane_ids):
            return False
        monetary = [
            lane
            for lane in lanes
            if lane.get("requested_value_binding") != "none"
        ]
        pool = candidate.get("customer_value_pool")
        if bool(monetary) != isinstance(pool, dict):
            return False
        return not monetary or not any(
            lane.get("currency") != pool.get("currency") for lane in monetary
        )

    if not request_invariants_hold(request):
        raise ContractFailure("valid Work request v2 violates root-pool invariants")
    request_without_pool = copy.deepcopy(request)
    request_without_pool.pop("customer_value_pool")
    if request_invariants_hold(request_without_pool):
        raise ContractFailure("monetary Work request v2 was accepted without a root pool")

    issued = {
        item["authority_id"]: item["authority_canonical_hash"]
        for item in package["issued_authorities"]
    }
    if set(issued) != {"phone-lane", "restaurant-deposit-lane"}:
        raise ContractFailure("Work package v2 issued set differs from the contract vector")
    if any(
        authority_id not in authorities
        or authorities[authority_id]["authority_canonical_hash"] != authority_hash
        for authority_id, authority_hash in issued.items()
    ):
        raise ContractFailure("Work package v2 authority references do not match canonical lanes")
    monetary_authorities = [
        authorities[authority_id]
        for authority_id in issued
        if authorities[authority_id]["value_binding"] != "none"
    ]
    pool = package.get("customer_value_pool")
    if not isinstance(pool, dict) or any(
        authority.get("currency") != pool.get("currency")
        for authority in monetary_authorities
    ):
        raise ContractFailure("Work package v2 pool does not cover every monetary lane")
    delegations = package["authority_delegations"]
    delegation_by_authority = {
        item["authority_id"]: item for item in delegations
    }
    if len(delegation_by_authority) != len(delegations) or not set(
        delegation_by_authority
    ).issubset(issued):
        raise ContractFailure("Work package v2 contains duplicate or unknown delegations")

    package_hash = digest(package)

    def binding_matches(candidate: dict[str, Any]) -> bool:
        authority_id = candidate.get("authority_id")
        exercised = candidate.get("exercised_by")
        value_request = candidate.get("value_request")
        authority = authorities.get(authority_id)
        if (
            authority_id not in issued
            or not isinstance(exercised, dict)
            or not isinstance(value_request, dict)
            or authority is None
            or value_request.get("version") != "keel.work_value_request.v2"
            or value_request.get("value_binding") != authority.get("value_binding")
        ):
            return False
        if authority.get("value_binding") == "declared_bounded":
            amount = value_request.get("declared_amount_minor")
            if (
                not isinstance(amount, int)
                or isinstance(amount, bool)
                or amount < 1
                or amount > authority.get("value_max_minor", 0)
                or value_request.get("currency") != authority.get("currency")
            ):
                return False
        elif set(value_request) != {"version", "value_binding"}:
            return False
        if candidate.get("root_manifest_hash") != package_hash:
            return False
        if candidate.get("authority_canonical_hash") != issued[authority_id]:
            return False
        if exercised.get("root_principal_id") != package.get("verified_root_principal_id"):
            return False
        delegation = delegation_by_authority.get(authority_id)
        if delegation is None:
            return (
                exercised.get("verified_principal_id")
                == package.get("verified_root_principal_id")
                and exercised.get("delegated_principal_id") is None
                and exercised.get("delegation_id") is None
            )
        return (
            exercised.get("verified_principal_id")
            == delegation.get("delegated_principal_id")
            and exercised.get("delegated_principal_id")
            == delegation.get("delegated_principal_id")
            and exercised.get("delegation_id") == delegation.get("delegation_id")
        )

    if not all(binding_matches(binding) for binding in bindings):
        raise ContractFailure("valid Work binding v2 does not match the signed delegation")
    swapped_credential_identity = copy.deepcopy(bindings[0])
    swapped_credential_identity["exercised_by"]["verified_principal_id"] = (
        bindings[1]["exercised_by"]["verified_principal_id"]
    )
    if binding_matches(swapped_credential_identity):
        raise ContractFailure("Work binding v2 accepted credential/principal swapping")
    changed_declared_value = copy.deepcopy(bindings[1])
    changed_declared_value["value_request"]["declared_amount_minor"] = 50_001
    if binding_matches(changed_declared_value):
        raise ContractFailure("Work binding v2 accepted a declared amount above its lane cap")
    fake_phone_value = copy.deepcopy(bindings[0])
    fake_phone_value["value_request"]["declared_amount_minor"] = 1
    fake_phone_value["value_request"]["currency"] = "USD"
    if binding_matches(fake_phone_value):
        raise ContractFailure("Work binding v2 let a non-monetary lane declare customer value")
    changed_package = copy.deepcopy(package)
    changed_package["authority_delegations"][0]["delegated_principal_id"] = (
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    )
    if digest(changed_package) == package_hash:
        raise ContractFailure("Work package delegation mutation did not change its hash")

    def value_ledger_holds(events: list[dict[str, Any]]) -> bool:
        reserved_by_id: dict[str, int] = {}
        reserved_total = 0
        consumed_total = 0
        previous_hash: str | None = None
        seen_ids: set[str] = set()
        seen_idempotency: set[str] = set()
        for expected_sequence, event in enumerate(events, start=1):
            if (
                event.get("event_id") in seen_ids
                or event.get("idempotency_key_digest") in seen_idempotency
                or event.get("root_sequence") != expected_sequence
                or event.get("previous_root_event_hash") != previous_hash
                or event.get("root_permit_id")
                != summary.get("root_permit_id")
                or event.get("currency") != pool.get("currency")
                or event.get("value_domain") != "customer_economic_value"
            ):
                return False
            authority = authorities.get(event.get("authority_id"))
            if authority is None or authority.get("value_binding") == "none":
                return False
            preimage = copy.deepcopy(event)
            event_hash = preimage.pop("event_canonical_hash", None)
            if digest(preimage) != event_hash:
                return False
            reservation_id = event.get("reservation_id")
            amount = event.get("amount_minor")
            event_type = event.get("event_type")
            if event_type == "reserved":
                if reservation_id in reserved_by_id:
                    return False
                reserved_by_id[reservation_id] = amount
                reserved_total += amount
            elif event_type in {"released", "reconciled_release"}:
                if reserved_by_id.get(reservation_id, 0) < amount:
                    return False
                reserved_by_id[reservation_id] -= amount
                reserved_total -= amount
            elif event_type in {"consumed", "reconciled_consume"}:
                if reserved_by_id.get(reservation_id, 0) < amount:
                    return False
                reserved_by_id[reservation_id] -= amount
                reserved_total -= amount
                consumed_total += amount
            else:
                return False
            remaining = pool["value_max_minor"] - reserved_total - consumed_total
            if reserved_total < 0 or consumed_total < 0 or remaining < 0:
                return False
            if event.get("root_value_state_after") != {
                "value_domain": "customer_economic_value",
                "value_max_minor": pool["value_max_minor"],
                "currency": pool["currency"],
                "reserved_value_minor": reserved_total,
                "consumed_value_minor": consumed_total,
                "remaining_value_minor": remaining,
            }:
                return False
            seen_ids.add(event["event_id"])
            seen_idempotency.add(event["idempotency_key_digest"])
            previous_hash = event_hash
        return True

    if not value_ledger_holds(value_events):
        raise ContractFailure("valid Work v2 root value ledger failed reconstruction")
    overdrawn = copy.deepcopy(value_events)
    overdrawn[0]["amount_minor"] = pool["value_max_minor"] + 1
    if value_ledger_holds(overdrawn):
        raise ContractFailure("Work v2 root value ledger accepted an overdraw")
    call_value_event = copy.deepcopy(value_events[0])
    call_value_event["authority_id"] = "phone-lane"
    if value_ledger_holds([call_value_event]):
        raise ContractFailure("non-monetary Work v2 lane consumed caller-supplied value")

    for label, signed_object in (
        ("review transition", review_transition),
        ("provider value fact", provider_value_fact),
        ("dispatch boundary", dispatch_boundary),
    ):
        preimage = copy.deepcopy(signed_object)
        canonical_hash = preimage.pop("canonical_hash")
        preimage.pop("signature")
        if digest(preimage) != canonical_hash:
            raise ContractFailure(f"Work v2 {label} has a stale canonical hash")
    if review_transition["human_outcome"] != "approve" or review_transition[
        "final_decision"
    ] != "deny":
        raise ContractFailure("Work v2 review vector no longer proves approval then denial")
    if (
        dispatch_boundary["upstream_called"] is not False
        or dispatch_boundary["pre_effect"] is not True
        or not all(dispatch_boundary["liveness"].values())
    ):
        raise ContractFailure("Work v2 dispatch boundary is not a complete pre-effect gate")
    mutated_review = copy.deepcopy(review_transition)
    mutated_review["frozen_request_digest"] = "sha256:" + "0" * 64
    review_preimage = copy.deepcopy(mutated_review)
    stale_review_hash = review_preimage.pop("canonical_hash")
    review_preimage.pop("signature")
    if digest(review_preimage) == stale_review_hash:
        raise ContractFailure("Work v2 review mutation did not fail closed")

    expected_pool_state = value_events[-1]["root_value_state_after"]
    presentation_by_semantic = {
        item["semantic_id"]: item
        for item in load_json("presentation_registry/v18.json")["profiles"]
    }
    decision_counts = {
        authority_id: {"allow": 0, "deny": 0, "challenge": 0}
        for authority_id in issued
    }
    for child in vectors["child_decisions"]:
        if child["authority_id"] not in decision_counts:
            raise ContractFailure("Work summary source names an unknown lane")
        decision_counts[child["authority_id"]][child["decision"]] += 1
    derived_lanes: list[dict[str, Any]] = []
    for authority_id in sorted(issued):
        authority = authorities[authority_id]
        delegation = delegation_by_authority.get(authority_id)
        expected_principal = (
            delegation["delegated_principal_id"]
            if delegation is not None
            else package["verified_root_principal_id"]
        )
        presentation = presentation_by_semantic.get(authority["semantic_id"])
        if presentation is None:
            raise ContractFailure(f"Work summary lane {authority_id} has no presentation")
        derived_lanes.append(
            {
                "authority_id": authority_id,
                "action": authority["trusted_action"],
                "permit_title": presentation["customer_title"],
                "principal_id": expected_principal,
                "value_binding": authority["value_binding"],
                "max_uses": authority["max_uses"],
                "child_decisions": decision_counts[authority_id],
            }
        )

    def display_minor(amount: int, currency: str) -> str:
        # The vector uses USD, whose public contract exponent is two. Runtime
        # implementations must use their pinned currency metadata rather than
        # guessing an exponent from the code alone.
        if currency == "USD":
            return f"USD {amount // 100}.{amount % 100:02d}"
        return f"{amount} minor units in {currency}"

    pool_currency = expected_pool_state["currency"]
    displayed_limit = display_minor(expected_pool_state["value_max_minor"], pool_currency)
    displayed_reserved = display_minor(
        expected_pool_state["reserved_value_minor"], pool_currency
    )
    displayed_consumed = display_minor(
        expected_pool_state["consumed_value_minor"], pool_currency
    )
    displayed_remaining = display_minor(
        expected_pool_state["remaining_value_minor"], pool_currency
    )
    derived_summary = {
        "version": "keel.work_summary.v1",
        "derivation": "verifier_from_verified_work_fields",
        "title": "AI Permit-to-Work",
        "state_label": vectors["root_state"],
        "text": (
            f"Keel authorized a bounded Work with {len(issued)} lanes. "
            f"Customer economic value is limited to {displayed_limit}; "
            f"{displayed_reserved} is reserved, {displayed_consumed} is consumed, "
            f"and {displayed_remaining} "
            "remains. AI and model compute spend is governed separately. "
            "This evidence does not establish provider completion, settlement, call content, or agreement."
        ),
        "root_permit_id": summary["root_permit_id"],
        "customer_value_pool": expected_pool_state,
        "ai_compute_budget_boundary": (
            "separate_keel_authority_not_in_work_customer_value_pool"
        ),
        "lanes": derived_lanes,
        "evidence_boundary": {
            "establishes": [
                "bounded heterogeneous Work authority",
                "signed worker delegation and child containment",
                "root customer-value conservation through the declared cutoff",
            ],
            "does_not_establish": [
                "provider completion",
                "financial settlement",
                "call answer, conversation content, or agreement",
                "AI or model compute spend",
            ],
        },
    }
    if summary != derived_summary:
        raise ContractFailure("Work summary is not the deterministic verifier projection")
    tampered_summary = copy.deepcopy(summary)
    tampered_summary["text"] += " Provider completion established."
    if tampered_summary == derived_summary:
        raise ContractFailure("Work summary mutation did not fail closed")


def validate_claim_contracts() -> None:
    registry = load_json("claim_registry/v0.json")
    claims = {claim["name"]: claim for claim in registry["claims"]}
    missing = sorted(WORK_CLAIMS - set(claims))
    if missing:
        raise ContractFailure(f"claim registry is missing Work claims: {missing}")
    if any(set(claims[name]["verdict_enum"]) != VERDICTS for name in WORK_CLAIMS):
        raise ContractFailure("Work claims changed the stable v0 verdict enum")
    semantic_files = {
        "permit.work_authority_manifest.v1": "semantics/work/authority_manifest_v1.json",
        "permit.work_child_containment.v1": "semantics/work/child_containment_v1.json",
        "permit_chain.execution_authorized_at_boundary.v1": "semantics/work/execution_authorized_at_boundary_v1.json",
        "permit.work_value_conservation.v1": "semantics/work/value_conservation_v1.json",
    }
    for claim_name, path in semantic_files.items():
        artifact = load_json(path)
        if artifact.get("body", {}).get("claim") != claim_name:
            raise ContractFailure(f"{path} does not bind claim {claim_name}")

    claims_v5_path = ROOT / "claim_registry/v5.json"
    claims_v5 = load_json("claim_registry/v5.json")
    claims_v6 = load_json("claim_registry/v6.json")
    extension = claims_v6.get("extends")
    if not isinstance(extension, dict):
        raise ContractFailure("claim_registry/v6.json must pin v5")
    if extension.get("artifact_id") != "keel.verifier_claim_registry.v5":
        raise ContractFailure("claim_registry/v6.json extends the wrong artifact")
    if extension.get("version") != claims_v5.get("version"):
        raise ContractFailure("claim_registry/v6.json extends the wrong version")
    if extension.get("sha256") != _sha256_file(claims_v5_path).removeprefix(
        "sha256:"
    ):
        raise ContractFailure("claim_registry/v6.json has a stale base digest")
    v6_claims = claims_v6.get("claims")
    if not isinstance(v6_claims, list):
        raise ContractFailure("claim_registry/v6.json must add Work v2 claims")
    v6_names = {
        claim.get("name") for claim in v6_claims if isinstance(claim, dict)
    }
    if v6_names != WORK_V2_CLAIMS:
        raise ContractFailure(
            f"claim_registry/v6.json Work v2 claim mismatch: {sorted(v6_names)}"
        )
    for claim in v6_claims:
        if set(claim.get("verdict_enum", [])) != VERDICTS:
            raise ContractFailure(
                f"{claim.get('name')} changed the stable verdict enum"
            )
        if not claim.get("does_not_establish"):
            raise ContractFailure(
                f"{claim.get('name')} lacks a claim-level evidence ceiling"
            )

    semantic_v2_files = {
        "permit.work_authority_manifest.v2": "semantics/work/authority_manifest_v2.json",
        "permit.work_child_containment.v2": "semantics/work/child_containment_v2.json",
        "permit_chain.execution_authorized_at_boundary.v2": "semantics/work/execution_authorized_at_boundary_v2.json",
        "permit.work_value_conservation.v2": "semantics/work/value_conservation_v2.json",
        "permit.work_exact_review.v1": "semantics/work/exact_review_v1.json",
    }
    for claim_name, path in semantic_v2_files.items():
        artifact = load_json(path)
        if artifact.get("body", {}).get("claim") != claim_name:
            raise ContractFailure(f"{path} does not bind claim {claim_name}")


def validate_universal_verification_contract(registry: Registry) -> dict[str, Any]:
    """Validate the composable S1 contract and its cross-repository corpus."""

    claims_v1_path = ROOT / "claim_registry/v1.json"
    claims_v1 = load_json("claim_registry/v1.json")
    claims_v2 = load_json("claim_registry/v2.json")
    extension = claims_v2.get("extends")
    if not isinstance(extension, dict):
        raise ContractFailure("claim_registry/v2.json must pin a base registry")
    if extension.get("artifact_id") != "keel.verifier_claim_registry.v1":
        raise ContractFailure("claim_registry/v2.json extends the wrong artifact")
    if extension.get("version") != claims_v1.get("version"):
        raise ContractFailure("claim_registry/v2.json extends the wrong base version")
    if extension.get("sha256") != _sha256_file(claims_v1_path).removeprefix(
        "sha256:"
    ):
        raise ContractFailure("claim_registry/v2.json has a stale base digest")

    base_claims = claims_v1.get("claims")
    added_claims = claims_v2.get("claims")
    if not isinstance(base_claims, list) or not isinstance(added_claims, list):
        raise ContractFailure("claim registries must contain claim arrays")
    base_names = [
        claim.get("name") for claim in base_claims if isinstance(claim, dict)
    ]
    added_names = [
        claim.get("name") for claim in added_claims if isinstance(claim, dict)
    ]
    if len(base_names) != len(set(base_names)):
        raise ContractFailure("claim_registry/v1.json contains duplicate claims")
    if len(added_names) != len(set(added_names)):
        raise ContractFailure("claim_registry/v2.json contains duplicate additions")
    overlap = sorted(set(base_names).intersection(added_names))
    if overlap:
        raise ContractFailure(
            f"claim_registry/v2.json redefines base claims: {overlap}"
        )
    if set(added_names) != UNIVERSAL_CLAIMS:
        missing = sorted(UNIVERSAL_CLAIMS - set(added_names))
        extra = sorted(set(added_names) - UNIVERSAL_CLAIMS)
        raise ContractFailure(
            f"claim_registry/v2.json universal claim mismatch; "
            f"missing={missing}, extra={extra}"
        )
    if set(claims_v2.get("verdict_enum", [])) != VERDICTS:
        raise ContractFailure("claim_registry/v2.json changed the stable verdict enum")
    for claim in added_claims:
        if set(claim.get("verdict_enum", [])) != VERDICTS:
            raise ContractFailure(
                f"{claim.get('name')} changed the stable verdict enum"
            )
        if not claim.get("does_not_establish"):
            raise ContractFailure(
                f"{claim.get('name')} lacks claim-level does_not_establish"
            )

    claims_v3 = load_json("claim_registry/v3.json")
    extension_v3 = claims_v3.get("extends")
    if not isinstance(extension_v3, dict):
        raise ContractFailure("claim_registry/v3.json must pin v2")
    if extension_v3.get("artifact_id") != "keel.verifier_claim_registry.v2":
        raise ContractFailure("claim_registry/v3.json extends the wrong artifact")
    if extension_v3.get("version") != claims_v2.get("version"):
        raise ContractFailure("claim_registry/v3.json extends the wrong version")
    if extension_v3.get("sha256") != _sha256_file(
        ROOT / "claim_registry/v2.json"
    ).removeprefix("sha256:"):
        raise ContractFailure("claim_registry/v3.json has a stale base digest")
    v3_claims = claims_v3.get("claims")
    if not isinstance(v3_claims, list) or [
        claim.get("name") for claim in v3_claims if isinstance(claim, dict)
    ] != ["permit.delegate_child_linkage.v1"]:
        raise ContractFailure(
            "claim_registry/v3.json must add only Delegate child linkage"
        )
    for claim in v3_claims:
        if set(claim.get("verdict_enum", [])) != VERDICTS:
            raise ContractFailure("Delegate child-linkage changed the verdict enum")
        if not claim.get("does_not_establish"):
            raise ContractFailure("Delegate child-linkage lacks an evidence ceiling")

    claims_v4 = load_json("claim_registry/v4.json")
    extension_v4 = claims_v4.get("extends")
    if not isinstance(extension_v4, dict):
        raise ContractFailure("claim_registry/v4.json must pin v3")
    if extension_v4.get("artifact_id") != "keel.verifier_claim_registry.v3":
        raise ContractFailure("claim_registry/v4.json extends the wrong artifact")
    if extension_v4.get("version") != claims_v3.get("version"):
        raise ContractFailure("claim_registry/v4.json extends the wrong version")
    if extension_v4.get("sha256") != _sha256_file(
        ROOT / "claim_registry/v3.json"
    ).removeprefix("sha256:"):
        raise ContractFailure("claim_registry/v4.json has a stale base digest")
    v4_claims = claims_v4.get("claims")
    if not isinstance(v4_claims, list):
        raise ContractFailure("claim_registry/v4.json must add consequence claims")
    v4_names = {
        claim.get("name") for claim in v4_claims if isinstance(claim, dict)
    }
    if v4_names != CONSEQUENCE_EXACT_CLAIMS:
        raise ContractFailure(
            "claim_registry/v4.json must add only Generate Text and Refund claims"
        )
    for claim in v4_claims:
        if set(claim.get("verdict_enum", [])) != VERDICTS:
            raise ContractFailure(
                f"{claim.get('name')} changed the stable verdict enum"
            )
        if not claim.get("does_not_establish"):
            raise ContractFailure(
                f"{claim.get('name')} lacks a claim-level evidence ceiling"
            )

    claims_v5 = load_json("claim_registry/v5.json")
    extension_v5 = claims_v5.get("extends")
    if not isinstance(extension_v5, dict):
        raise ContractFailure("claim_registry/v5.json must pin v4")
    if extension_v5.get("artifact_id") != "keel.verifier_claim_registry.v4":
        raise ContractFailure("claim_registry/v5.json extends the wrong artifact")
    if extension_v5.get("version") != claims_v4.get("version"):
        raise ContractFailure("claim_registry/v5.json extends the wrong version")
    if extension_v5.get("sha256") != _sha256_file(
        ROOT / "claim_registry/v4.json"
    ).removeprefix("sha256:"):
        raise ContractFailure("claim_registry/v5.json has a stale base digest")
    v5_claims = claims_v5.get("claims")
    if not isinstance(v5_claims, list):
        raise ContractFailure("claim_registry/v5.json must add enforcement claims")
    v5_names = {
        claim.get("name") for claim in v5_claims if isinstance(claim, dict)
    }
    if v5_names != ENFORCEMENT_REGIME_CLAIMS:
        raise ContractFailure(
            "claim_registry/v5.json must add only Work enforcement-regime claims"
        )
    inherited_names = set(base_names).union(added_names).union(
        claim.get("name") for claim in v3_claims if isinstance(claim, dict)
    ).union(v4_names)
    overlap_v5 = sorted(v5_names.intersection(inherited_names))
    if overlap_v5:
        raise ContractFailure(
            f"claim_registry/v5.json redefines inherited claims: {overlap_v5}"
        )
    for claim in v5_claims:
        if set(claim.get("verdict_enum", [])) != VERDICTS:
            raise ContractFailure(
                f"{claim.get('name')} changed the stable verdict enum"
            )
        if not claim.get("does_not_establish"):
            raise ContractFailure(
                f"{claim.get('name')} lacks a claim-level evidence ceiling"
            )

    universal_v2 = load_json("semantics/permit/universal_verification_v2.json")
    universal_v2_extension = universal_v2.get("extends")
    if not isinstance(universal_v2_extension, dict):
        raise ContractFailure("universal verification v2 must pin v1")
    if universal_v2_extension.get("artifact_id") != (
        "keel.permit.universal_verification.v1"
    ):
        raise ContractFailure("universal verification v2 extends the wrong artifact")
    if universal_v2_extension.get("sha256") != _sha256_file(
        ROOT / "semantics/permit/universal_verification_v1.json"
    ).removeprefix("sha256:"):
        raise ContractFailure("universal verification v2 has a stale base digest")
    conditional = universal_v2.get("body", {}).get("conditional_claims", {})
    if conditional.get("keel.action.agent_delegate.v1") != [
        "permit.delegate_child_linkage.v1"
    ]:
        raise ContractFailure(
            "universal verification v2 does not bind Delegate child linkage"
        )

    universal_v3 = load_json("semantics/permit/universal_verification_v3.json")
    universal_v3_extension = universal_v3.get("extends")
    if not isinstance(universal_v3_extension, dict):
        raise ContractFailure("universal verification v3 must pin v2")
    if universal_v3_extension.get("artifact_id") != (
        "keel.permit.universal_verification.v2"
    ):
        raise ContractFailure("universal verification v3 extends the wrong artifact")
    if universal_v3_extension.get("sha256") != _sha256_file(
        ROOT / "semantics/permit/universal_verification_v2.json"
    ).removeprefix("sha256:"):
        raise ContractFailure("universal verification v3 has a stale base digest")
    conditional_v3 = universal_v3.get("body", {}).get("conditional_claims", {})
    expected_conditional_v3 = {
        "keel.action.generate_text.v1": [
            "permit.generate_text_exact_request.v1"
        ],
        "keel.action.payment_refund.v1": [
            "permit.refund_original_payment_bound.v1"
        ],
        "keel.action.agent_delegate.v1": [
            "permit.delegate_child_linkage.v1"
        ],
    }
    if conditional_v3 != expected_conditional_v3:
        raise ContractFailure(
            "universal verification v3 consequence-claim mapping is incomplete"
        )

    universal_v4 = load_json("semantics/permit/universal_verification_v4.json")
    universal_v4_extension = universal_v4.get("extends")
    if not isinstance(universal_v4_extension, dict):
        raise ContractFailure("universal verification v4 must pin v3")
    if universal_v4_extension.get("artifact_id") != (
        "keel.permit.universal_verification.v3"
    ):
        raise ContractFailure("universal verification v4 extends the wrong artifact")
    if universal_v4_extension.get("sha256") != _sha256_file(
        ROOT / "semantics/permit/universal_verification_v3.json"
    ).removeprefix("sha256:"):
        raise ContractFailure("universal verification v4 has a stale base digest")
    if universal_v4.get("body", {}).get("claim_registry_version") != (
        "verifier-claims.v5"
    ):
        raise ContractFailure("universal verification v4 pins the wrong claim registry")
    work_claims = universal_v4.get("body", {}).get(
        "conditional_evidence_claims", {}
    ).get("program:work")
    if work_claims != {
        "issuance": ["permit.enforcement_regime_at_issuance.v1"],
        "dispatch": ["permit.enforcement_regime_at_dispatch.v1"],
    }:
        raise ContractFailure(
            "universal verification v4 Work enforcement claims are incomplete"
        )

    validate_enforcement_claim_vectors()

    consequence_vectors = load_json(
        "test-vectors/consequence_claims/v1/corpus.json"
    )
    for vector in consequence_vectors.get("vectors", []):
        semantic_id = vector.get("semantic_id")
        verdicts = vector.get("universal_verdicts")
        expected = vector.get("expected")
        if not isinstance(verdicts, dict) or not isinstance(expected, dict):
            raise ContractFailure(
                f"consequence vector {vector.get('id')} is malformed"
            )
        if semantic_id == "keel.action.generate_text.v1":
            required = (
                "permit.type.v1",
                "permit.exact_target.v1",
                "permit.material_request.v1",
                "permit.enforced_at_certified_boundary.v1",
            )
            if any(verdicts.get(claim) == "disproved" for claim in required):
                actual = ("disproved", "GENERATE_TEXT_EXACT_REQUEST_MISMATCH")
            elif not all(verdicts.get(claim) == "supported" for claim in required):
                actual = (
                    "insufficient_evidence",
                    "GENERATE_TEXT_CERTIFIED_BOUNDARY_UNPROVEN",
                )
            elif not vector.get("facts_match_certification"):
                actual = ("disproved", "GENERATE_TEXT_ADAPTER_BINDING_MISMATCH")
            else:
                actual = ("supported", "GENERATE_TEXT_EXACT_REQUEST_VERIFIED")
        elif semantic_id == "keel.action.payment_refund.v1":
            required = (
                "permit.type.v1",
                "permit.exact_target.v1",
                "permit.material_request.v1",
            )
            if any(verdicts.get(claim) == "disproved" for claim in required):
                actual = ("disproved", "REFUND_ORIGINAL_PAYMENT_BINDING_MISMATCH")
            elif not all(verdicts.get(claim) == "supported" for claim in required):
                actual = (
                    "insufficient_evidence",
                    "REFUND_AUTHORIZATION_BINDING_UNPROVEN",
                )
            elif not vector.get("facts_match_signed_limits"):
                actual = ("disproved", "REFUND_SIGNED_LIMITS_MISMATCH")
            else:
                actual = ("supported", "REFUND_ORIGINAL_PAYMENT_BOUND")
        else:
            raise ContractFailure(
                f"consequence vector {vector.get('id')} has an unknown semantic"
            )
        if actual != (expected.get("verdict"), expected.get("reason")):
            raise ContractFailure(
                f"consequence vector {vector.get('id')} got {actual}, expected "
                f"{(expected.get('verdict'), expected.get('reason'))}"
            )

    linkage_vectors = load_json(
        "test-vectors/delegate_child_linkage/v1/corpus.json"
    )
    linkage_schema = load_json("schemas/delegate-child-linkage-v1.schema.json")
    linkage_validator = jsonschema.Draft202012Validator(
        linkage_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    for vector in linkage_vectors.get("vectors", []):
        evidence = copy.deepcopy(linkage_vectors["base_evidence"])
        mutation = vector.get("mutation")
        if isinstance(mutation, dict):
            current: Any = evidence
            parts = str(mutation["path"]).removeprefix("/").split("/")
            for part in parts[:-1]:
                current = current[part]
            current[parts[-1]] = mutation.get("value")
        errors = list(linkage_validator.iter_errors(evidence))
        if errors:
            raise ContractFailure(
                f"Delegate linkage vector {vector.get('id')} is schema-invalid: "
                f"{errors[0].message}"
            )
        intended = evidence["intended_child_reference_commitment"]
        created = evidence["created_child_reference_commitment"]
        granted = evidence["authority_grant"][
            "delegate_child_reference_commitment"
        ]
        acting = evidence["acting_child"]
        if created != intended:
            actual = ("disproved", "DELEGATE_CREATED_CHILD_MISMATCH")
        elif granted != intended:
            actual = ("disproved", "DELEGATE_GRANT_CHILD_MISMATCH")
        elif acting is None:
            actual = (
                "insufficient_evidence",
                "DELEGATE_ACTING_CHILD_EVIDENCE_MISSING",
            )
        elif acting["child_reference_commitment"] != intended:
            actual = ("disproved", "DELEGATE_ACTING_CHILD_MISMATCH")
        else:
            actual = ("supported", "DELEGATE_CHILD_LINKAGE_VERIFIED")
        expected = (
            vector.get("expected_verdict"),
            vector.get("expected_reason"),
        )
        if actual != expected:
            raise ContractFailure(
                f"Delegate linkage vector {vector.get('id')} got {actual}, "
                f"expected {expected}"
            )

    fact_registry = load_json("fact_profiles/v2.json")
    validate_instance(
        fact_registry,
        "fact_profiles/v2.schema.json",
        registry,
        "fact profile registry v2",
    )
    semantic_ids = {
        entry["semantic_id"]
        for entry in load_json("semantic_registry/v3.json")["entries"]
    }
    safe_low_entropy_methods = {
        "keel.salted_sha256_jcs.v1",
        "keel.randomized_sha256_jcs.v1",
        "keel.hmac_sha256_jcs.v1",
        "keel.opaque_reference.v1",
    }
    sensitive_classes = {
        "personal_data",
        "sensitive_data",
        "secret",
        "free_text",
    }
    for profile in fact_registry["profiles"]:
        if profile["facts_schema_digest"] != _sha256_file(
            ROOT / profile["facts_schema"]
        ):
            raise ContractFailure(
                f"{profile['fact_profile_id']} v2 facts schema digest is stale"
            )
        unknown_semantics = sorted(set(profile["semantic_ids"]) - semantic_ids)
        if unknown_semantics:
            raise ContractFailure(
                f"{profile['fact_profile_id']} v2 references unknown semantics: "
                f"{unknown_semantics}"
            )
        fields = {field["path"]: field for field in profile["fields"]}
        if len(fields) != len(profile["fields"]):
            raise ContractFailure(
                f"{profile['fact_profile_id']} v2 has duplicate field paths"
            )
        referenced_paths = set(profile["target_fact_paths"]).union(
            profile["material_request_fact_paths"]
        )
        missing_paths = sorted(referenced_paths - set(fields))
        if missing_paths:
            raise ContractFailure(
                f"{profile['fact_profile_id']} v2 references unknown paths: "
                f"{missing_paths}"
            )
        for path in referenced_paths:
            if not fields[path]["required_for_authorization"]:
                raise ContractFailure(
                    f"{profile['fact_profile_id']} v2 exact path {path} is optional"
                )
        for field in fields.values():
            if (
                field["classification"] in sensitive_classes
                and field["low_entropy_possible"]
                and field["commitment_method"] not in safe_low_entropy_methods
            ):
                raise ContractFailure(
                    f"{profile['fact_profile_id']} v2 field {field['path']} "
                    "uses an unsafe low-entropy representation"
                )
            if (
                field["retention"]["erasable"]
                and field["retention"]["erasure_action"] == "retain_signed_value"
            ):
                raise ContractFailure(
                    f"{profile['fact_profile_id']} v2 field {field['path']} "
                    "marks retained signed bytes erasable"
                )

    semantics = load_json("semantics/permit/universal_verification_v1.json")
    body = semantics.get("body")
    if not isinstance(body, dict):
        raise ContractFailure("universal verification semantics body is missing")
    claim_order = body.get("claim_order")
    if not isinstance(claim_order, list):
        raise ContractFailure("universal verification claim_order is missing")
    if len(claim_order) != len(set(claim_order)):
        raise ContractFailure("universal verification claim_order has duplicates")
    if set(claim_order) != UNIVERSAL_CLAIMS.union({"permit.decision.v1"}):
        raise ContractFailure(
            "universal verification claim_order does not cover the contract"
        )

    corpus = load_json("test-vectors/universal_verification/v1/corpus.json")
    if set(corpus.get("required_claims", [])) != UNIVERSAL_CLAIMS:
        raise ContractFailure("universal vector corpus has stale required claims")
    for contract_path in corpus.get("contracts", {}).values():
        resolved = (
            ROOT
            / "test-vectors/universal_verification/v1"
            / contract_path
        ).resolve()
        if not resolved.is_file():
            raise ContractFailure(
                f"universal vector corpus references missing contract {contract_path}"
            )

    schema_instances = corpus.get("schema_instances")
    if not isinstance(schema_instances, dict):
        raise ContractFailure("universal vector corpus lacks schema instances")
    instance_schemas = {
        "semantic_binding": "schemas/permit-semantic-binding-v2.schema.json",
        "adapter_certification": "schemas/adapter-certification-v1.schema.json",
        "deployment_assurance": "schemas/deployment-assurance-v1.schema.json",
        "runtime_enforcement_proof": "schemas/runtime-enforcement-proof-v1.schema.json",
        "bounded_use": "schemas/permit-bounded-use-v1.schema.json",
        "selective_disclosure": "schemas/permit-selective-disclosure-v1.schema.json",
        "provider_receipt": "schemas/provider-receipt-v1.schema.json",
    }
    for instance_name, schema_path in instance_schemas.items():
        validate_instance(
            schema_instances.get(instance_name),
            schema_path,
            registry,
            f"universal schema instance {instance_name}",
        )

    selector_registry = load_json("semantic_registry/v3.json")
    selector_entry = one_entry(
        selector_registry["entries"],
        key="semantic_id",
        expected="keel.action.payment_execute.v1",
    )
    fact_profile = one_entry(
        fact_registry["profiles"],
        key="fact_profile_id",
        expected="keel.facts.payment_exact.v1",
    )
    payment_facts = load_json("fact_profiles/test-vectors/v1.json")["vectors"][0][
        "facts"
    ]
    universal_semantics = load_json(
        "semantics/permit/universal_verification_v1.json"
    )

    def artifact_pin(
        *,
        artifact_id: str,
        version: str,
        path: str,
    ) -> dict[str, Any]:
        content = (ROOT / path).read_bytes()
        return {
            "artifact_id": artifact_id,
            "version": version,
            "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
            "media_type": "application/json",
            "content_base64": base64.b64encode(content).decode("ascii"),
        }

    exact_pack = {
        "profile": "keel.permit_exact/v2",
        "profile_version": 2,
        "generated_at": "2026-07-30T12:30:00Z",
        "permit_id": "permit_test",
        "project_id": "project_test",
        "declared_claims": ["permit.type.v1"],
        "semantic_binding": schema_instances["semantic_binding"],
        "authorization_facts": payment_facts,
        "contract_pins": {
            "claim_registry": artifact_pin(
                artifact_id="keel.verifier_claim_registry.v2",
                version=claims_v2["version"],
                path="claim_registry/v2.json",
            ),
            "semantic_selector_registry": artifact_pin(
                artifact_id="keel.permit.semantic_selector_registry.v3",
                version=selector_registry["version"],
                path="semantic_registry/v3.json",
            ),
            "semantic_selector_entry_digest": digest(selector_entry),
            "fact_profile_registry": artifact_pin(
                artifact_id="keel.permit.fact_profile_registry.v2",
                version=fact_registry["version"],
                path="fact_profiles/v2.json",
            ),
            "fact_profile_entry_digest": digest(fact_profile),
            "authorization_facts_schema": artifact_pin(
                artifact_id="keel.permit.payment_exact_facts.v1.schema",
                version="keel.payment_exact_facts.v1",
                path="schemas/payment-exact-facts-v1.schema.json",
            ),
            "universal_semantics": artifact_pin(
                artifact_id="keel.permit.universal_verification.v1",
                version=universal_semantics["version"],
                path="semantics/permit/universal_verification_v1.json",
            ),
        },
        "permit_decision": {"claim_name": "permit.decision.v1"},
        "permit_receipt": {"action": {"resource_attributes_json": {}}},
        "decision_state": {"decision": "allow", "status": "active"},
        "review_transition": {"status": "not_present"},
        "enforcement_evidence": None,
        "bounded_use_transitions": [],
        "provider_receipts": [],
        "selective_disclosures": [],
        "scope_evidence": [],
        "does_not_establish": [
            "dispatch",
            "provider acceptance",
            "external real-world outcome",
        ],
    }
    validate_instance(
        exact_pack,
        "schemas/permit-exact-pack-v2.schema.json",
        registry,
        "universal exact pack",
    )
    for pin_name, pin in exact_pack["contract_pins"].items():
        if not isinstance(pin, dict) or "content_base64" not in pin:
            continue
        content = base64.b64decode(pin["content_base64"], validate=True)
        actual = "sha256:" + hashlib.sha256(content).hexdigest()
        if actual != pin["sha256"]:
            raise ContractFailure(
                f"universal exact pack pin {pin_name} has a stale digest"
            )
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ContractFailure(
                f"universal exact pack pin {pin_name} is not a JSON object"
            )

    invalid_instances = []
    missing_anti_bypass = copy.deepcopy(schema_instances["adapter_certification"])
    missing_anti_bypass.pop("anti_bypass_requirements")
    invalid_instances.append(
        (
            missing_anti_bypass,
            instance_schemas["adapter_certification"],
            "adapter certification missing anti-bypass requirements",
        )
    )
    missing_pre_effect = copy.deepcopy(schema_instances["runtime_enforcement_proof"])
    missing_pre_effect.pop("pre_effect")
    invalid_instances.append(
        (
            missing_pre_effect,
            instance_schemas["runtime_enforcement_proof"],
            "runtime proof missing pre-effect marker",
        )
    )
    invalid_first_transition = copy.deepcopy(schema_instances["bounded_use"])
    invalid_first_transition["previous_transition_digest"] = (
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    invalid_instances.append(
        (
            invalid_first_transition,
            instance_schemas["bounded_use"],
            "first bounded-use transition has a predecessor",
        )
    )
    transport_acceptance = copy.deepcopy(schema_instances["provider_receipt"])
    transport_acceptance["source_class"] = "keel_transport_observation"
    invalid_instances.append(
        (
            transport_acceptance,
            instance_schemas["provider_receipt"],
            "transport observation claims acceptance",
        )
    )
    for instance, schema_path, label in invalid_instances:
        schema = load_json(schema_path)
        validator = jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        )
        if not list(validator.iter_errors(instance)):
            raise ContractFailure(f"universal negative schema vector passed: {label}")

    vectors = corpus.get("vectors")
    if not isinstance(vectors, list) or len(vectors) < 20:
        raise ContractFailure(
            "universal vector corpus must contain at least 20 behavioral vectors"
        )
    vector_ids = [
        vector.get("id") for vector in vectors if isinstance(vector, dict)
    ]
    if len(vector_ids) != len(set(vector_ids)):
        raise ContractFailure("universal vector corpus contains duplicate ids")
    covered_claims = {
        vector.get("claim") for vector in vectors if isinstance(vector, dict)
    }
    required_vector_claims = {
        "permit.type.v1",
        "permit.exact_target.v1",
        "permit.material_request.v1",
        "permit.valid_at_dispatch.v1",
        "permit.revocation_at_dispatch.v1",
        "permit.enforced_at_certified_boundary.v1",
        "permit.bounded_use.v1",
        "permit.single_use.v1",
        "permit.replay_prevented.v1",
        "permit.idempotency_bound.v1",
        "provider.rejected.v1",
        "provider.accepted.v1",
        "provider.completed.v1",
    }
    missing_vector_claims = sorted(required_vector_claims - covered_claims)
    if missing_vector_claims:
        raise ContractFailure(
            f"universal vector corpus misses claims: {missing_vector_claims}"
        )
    for vector in vectors:
        expected = vector.get("expected")
        if not isinstance(expected, dict) or expected.get("verdict") not in VERDICTS:
            raise ContractFailure(
                f"universal vector {vector.get('id')} lacks a stable verdict"
            )
        if not isinstance(expected.get("reason"), str):
            raise ContractFailure(
                f"universal vector {vector.get('id')} lacks a reason code"
            )

    return exact_pack

def validate_artifact_manifest() -> None:
    manifest = load_json("artifact-manifests/permit-to-x-v1.json")
    if manifest.get("version") != "keel.permit_to_x_artifact_manifest.v1":
        raise ContractFailure("Permit-to-X artifact manifest version is invalid")
    paths: set[str] = set()
    identifiers: set[str] = set()
    for artifact in manifest.get("artifacts", []):
        path = artifact.get("path")
        artifact_id = artifact.get("id")
        if not isinstance(path, str) or not isinstance(artifact_id, str):
            raise ContractFailure("Permit-to-X artifact manifest entry is malformed")
        if path in paths or artifact_id in identifiers:
            raise ContractFailure("Permit-to-X artifact manifest contains duplicate path or id")
        paths.add(path)
        identifiers.add(artifact_id)
        resolved = (ROOT / path).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError as exc:
            raise ContractFailure(f"artifact path escapes repository: {path}") from exc
        if not resolved.is_file():
            raise ContractFailure(f"artifact manifest path is missing: {path}")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != artifact.get("sha256"):
            raise ContractFailure(f"artifact manifest hash mismatch for {path}")
    required_latest_paths = {
        "semantic_registry/v4.json",
        "semantic_registry/v4.schema.json",
        "semantic_registry/v5.json",
        "semantic_registry/v5.schema.json",
        "semantic_registry/v6.json",
        "semantic_registry/v6.schema.json",
        "semantic_registry/v7.json",
        "semantic_registry/v7.schema.json",
        "semantic_registry/v8.json",
        "semantic_registry/v8.schema.json",
        "semantic_registry/v9.json",
        "semantic_registry/v9.schema.json",
        "semantic_registry/v10.json",
        "semantic_registry/v10.schema.json",
        "semantic_registry/v11.json",
        "semantic_registry/v11.schema.json",
        "semantic_registry/v12.json",
        "semantic_registry/v12.schema.json",
        "semantic_registry/v13.json",
        "semantic_registry/v13.schema.json",
        "semantic_registry/v14.json",
        "semantic_registry/v14.schema.json",
        "semantic_registry/v15.json",
        "semantic_registry/v15.schema.json",
        "semantic_registry/v16.json",
        "semantic_registry/v16.schema.json",
        "semantic_registry/v17.json",
        "semantic_registry/v17.schema.json",
        "semantic_registry/v18.json",
        "semantic_registry/v18.schema.json",
        "presentation_registry/v4.json",
        "presentation_registry/v4.schema.json",
        "presentation_registry/v5.json",
        "presentation_registry/v5.schema.json",
        "presentation_registry/v6.json",
        "presentation_registry/v6.schema.json",
        "presentation_registry/v7.json",
        "presentation_registry/v7.schema.json",
        "presentation_registry/v8.json",
        "presentation_registry/v8.schema.json",
        "presentation_registry/v9.json",
        "presentation_registry/v9.schema.json",
        "presentation_registry/v10.json",
        "presentation_registry/v10.schema.json",
        "presentation_registry/v11.json",
        "presentation_registry/v11.schema.json",
        "presentation_registry/v12.json",
        "presentation_registry/v12.schema.json",
        "presentation_registry/v13.json",
        "presentation_registry/v13.schema.json",
        "presentation_registry/v14.json",
        "presentation_registry/v14.schema.json",
        "presentation_registry/v15.json",
        "presentation_registry/v15.schema.json",
        "presentation_registry/v16.json",
        "presentation_registry/v16.schema.json",
        "presentation_registry/v17.json",
        "presentation_registry/v17.schema.json",
        "consequence_registry/v1.json",
        "consequence_registry/v1.schema.json",
        "consequence_registry/v2.json",
        "consequence_registry/v2.schema.json",
        "consequence_registry/v3.json",
        "consequence_registry/v3.schema.json",
        "consequence_registry/v4.json",
        "consequence_registry/v4.schema.json",
        "consequence_registry/v5.json",
        "consequence_registry/v5.schema.json",
        "consequence_registry/v6.json",
        "consequence_registry/v6.schema.json",
        "consequence_registry/v7.json",
        "consequence_registry/v7.schema.json",
        "consequence_registry/v8.json",
        "consequence_registry/v8.schema.json",
        "consequence_registry/v9.json",
        "consequence_registry/v9.schema.json",
        "consequence_registry/v10.json",
        "consequence_registry/v10.schema.json",
        "consequence_registry/v11.json",
        "consequence_registry/v11.schema.json",
        "consequence_registry/v12.json",
        "consequence_registry/v12.schema.json",
        "consequence_registry/v13.json",
        "consequence_registry/v13.schema.json",
        "consequence_registry/test-vectors/v1.json",
        "consequence_registry/test-vectors/v2.json",
        "consequence_registry/test-vectors/v3.json",
        "consequence_registry/test-vectors/v4.json",
        "consequence_registry/test-vectors/v5.json",
        "consequence_registry/test-vectors/v6.json",
        "consequence_registry/test-vectors/v7.json",
        "consequence_registry/test-vectors/v8.json",
        "consequence_registry/test-vectors/v9.json",
        "consequence_registry/test-vectors/v10.json",
        "consequence_registry/test-vectors/v11.json",
        "consequence_registry/test-vectors/v12.json",
        "consequence_registry/test-vectors/v13.json",
        "consequence_registry/test-vectors/v14.json",
        "consequence_registry/test-vectors/v15.json",
        "spec/consequence-registry-v1.md",
        "presentation_registry/v2.json",
        "presentation_registry/v2.schema.json",
        "presentation_registry/v3.json",
        "presentation_registry/v3.schema.json",
        "presentation_registry/test-vectors/v2.json",
        "schemas/permit-human-artifact-v1.schema.json",
        "schemas/permit-package-manifest-v1.schema.json",
        "semantics/permit/human_summary_v1.json",
        "spec/permit-human-artifact-v1.md",
        "test-vectors/permit_human_artifact/v1/corpus.json",
        "fact_profiles/v3.json",
        "fact_profiles/v3.schema.json",
        "fact_profiles/v4.json",
        "fact_profiles/v4.schema.json",
        "fact_profiles/v5.json",
        "fact_profiles/v5.schema.json",
        "fact_profiles/v6.json",
        "fact_profiles/v6.schema.json",
        "fact_profiles/v7.json",
        "fact_profiles/v7.schema.json",
        "fact_profiles/v8.json",
        "fact_profiles/v8.schema.json",
        "fact_profiles/v9.json",
        "fact_profiles/v9.schema.json",
        "fact_profiles/v10.json",
        "fact_profiles/v10.schema.json",
        "fact_profiles/v11.json",
        "fact_profiles/v11.schema.json",
        "fact_profiles/v12.json",
        "fact_profiles/v12.schema.json",
        "fact_profiles/v13.json",
        "fact_profiles/v13.schema.json",
        "fact_profiles/v14.json",
        "fact_profiles/v14.schema.json",
        "fact_profiles/v15.json",
        "fact_profiles/v15.schema.json",
        "fact_profiles/v16.json",
        "fact_profiles/v16.schema.json",
        "schemas/goal3a-portfolio-exact-facts-v1.schema.json",
        "schemas/database-exact-facts-v1.schema.json",
        "schemas/payment-ledger-exact-facts-v1.schema.json",
        "schemas/transactional-cx-exact-facts-v1.schema.json",
        "spec/transactional-cx-exact-action-contract-v1.md",
        "schemas/release-exact-facts-v1.schema.json",
        "spec/release-exact-action-contract-v1.md",
        "schemas/coding-workspace-exact-facts-v1.schema.json",
        "spec/coding-workspace-exact-action-contract-v1.md",
        "schemas/collections-exact-facts-v1.schema.json",
        "spec/collections-exact-action-contract-v1.md",
        "schemas/insurance-claims-exact-facts-v1.schema.json",
        "spec/insurance-claims-exact-action-contract-v1.md",
        "schemas/erp-crm-exact-facts-v1.schema.json",
        "spec/erp-crm-exact-action-contract-v1.md",
        "schemas/procurement-ap-exact-facts-v1.schema.json",
        "spec/procurement-ap-exact-action-contract-v1.md",
        "schemas/commerce-regulated-exact-facts-v1.schema.json",
        "spec/commerce-regulated-exact-action-contract-v1.md",
        "schemas/wave5-breadth-exact-facts-v1.schema.json",
        "spec/wave5-breadth-exact-action-contract-v1.md",
        "schemas/identity-security-exact-facts-v1.schema.json",
        "spec/identity-security-exact-action-contract-v1.md",
        "schemas/generate-text-exact-facts-v1.schema.json",
        "schemas/refund-exact-facts-v1.schema.json",
        "schemas/delegate-exact-facts-v1.schema.json",
        "schemas/delegate-child-linkage-v1.schema.json",
        "claim_registry/v3.json",
        "semantics/permit/universal_verification_v2.json",
        "test-vectors/delegate_child_linkage/v1/corpus.json",
        "claim_registry/v4.json",
        "semantics/permit/universal_verification_v3.json",
        "test-vectors/consequence_claims/v1/corpus.json",
        "claim_registry/v5.json",
        "semantics/permit/universal_verification_v4.json",
        "test-vectors/enforcement_claims/v1/corpus.json",
    }
    missing_latest = sorted(required_latest_paths - paths)
    if missing_latest:
        raise ContractFailure(
            "Permit-to-X artifact manifest omits latest exact-action artifacts: "
            f"{missing_latest}"
        )


def validate_enforcement_claim_vectors() -> None:
    corpus = load_json("test-vectors/enforcement_claims/v1/corpus.json")
    if set(corpus.get("claims", [])) != ENFORCEMENT_REGIME_CLAIMS:
        raise ContractFailure("enforcement-claim corpus has stale claim coverage")
    seen: set[str] = set()
    covered_claims: set[str] = set()
    for vector in corpus.get("vectors", []):
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or vector_id in seen:
            raise ContractFailure("enforcement-claim vectors have duplicate or missing ids")
        seen.add(vector_id)
        expected = vector.get("expected")
        if not isinstance(expected, dict):
            raise ContractFailure(f"enforcement vector {vector_id} lacks an expectation")
        claim = vector.get("claim")
        if vector.get("surface_key") != "program:work":
            if claim is not None or expected != {"claim_required": False}:
                raise ContractFailure(
                    f"enforcement vector {vector_id} applied Work claims to another surface"
                )
            continue
        if claim not in ENFORCEMENT_REGIME_CLAIMS:
            raise ContractFailure(f"enforcement vector {vector_id} has an unknown claim")
        covered_claims.add(claim)
        if claim == "permit.enforcement_regime_at_issuance.v1":
            if not vector.get("state_present"):
                actual = (
                    "insufficient_evidence",
                    "ENFORCEMENT_REGIME_AT_ISSUANCE_NOT_RECORDED",
                )
            elif not vector.get("signed_binding_supported") or not vector.get(
                "identity_matches"
            ):
                actual = (
                    "disproved",
                    "ENFORCEMENT_ISSUANCE_BINDING_MISMATCH",
                )
            elif not vector.get("state_schema_valid"):
                actual = ("disproved", "ENFORCEMENT_ISSUANCE_STATE_INVALID")
            else:
                actual = (
                    "supported",
                    "ENFORCEMENT_REGIME_AT_ISSUANCE_VERIFIED",
                )
        else:
            proof_version = vector.get("runtime_proof_version")
            if proof_version in {None, "keel.runtime_enforcement_proof.v1"}:
                actual = (
                    "insufficient_evidence",
                    "ENFORCEMENT_REGIME_AT_DISPATCH_NOT_RECORDED",
                )
            elif proof_version != "keel.runtime_enforcement_proof.v2":
                actual = ("unverifiable_scope", "ENFORCEMENT_PROOF_VERSION_UNSUPPORTED")
            elif not vector.get("runtime_proof_signature_valid") or not vector.get(
                "runtime_proof_schema_valid"
            ):
                actual = ("disproved", "ENFORCEMENT_DISPATCH_PROOF_INVALID")
            elif not vector.get("identity_matches"):
                actual = ("disproved", "ENFORCEMENT_DISPATCH_IDENTITY_MISMATCH")
            else:
                actual = (
                    "supported",
                    "ENFORCEMENT_REGIME_AT_DISPATCH_VERIFIED",
                )
        expected_pair = (expected.get("verdict"), expected.get("reason"))
        if actual != expected_pair:
            raise ContractFailure(
                f"enforcement vector {vector_id} got {actual}, expected {expected_pair}"
            )
    if covered_claims != ENFORCEMENT_REGIME_CLAIMS:
        raise ContractFailure("enforcement-claim corpus misses a claim")


def validate_spec_document_pins() -> None:
    """Inline hash pins published in spec documents must match actual bytes.

    Third-party verifier authors pin recipes from the published claims spec,
    so a stale inline pin is a contract inconsistency even when the artifact
    manifest is correct.
    """
    spec_path = ROOT / "spec" / "verifier-claims-v0.md"
    text = spec_path.read_text(encoding="utf-8")
    pins = re.findall(
        r"`(semantics/work/[a-z0-9_]+\.json)`[^`]*`sha256:([0-9a-f]{64})`",
        text,
    )
    if not pins:
        raise ContractFailure(
            "spec/verifier-claims-v0.md contains no work semantic hash pins"
        )
    for path, pinned in pins:
        resolved = (ROOT / path).resolve()
        if not resolved.is_file():
            raise ContractFailure(f"spec pin references missing file: {path}")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != pinned:
            raise ContractFailure(
                f"spec/verifier-claims-v0.md pin for {path} is stale: "
                f"pinned sha256:{pinned}, actual sha256:{actual}"
            )


def validate_short_term_exact_profiles(registry: Registry) -> None:
    semantics = load_json("semantic_registry/v4.json")
    facts = load_json("fact_profiles/v3.json")
    presentation = load_json("presentation_registry/v3.json")
    validate_instance(
        semantics,
        "semantic_registry/v4.schema.json",
        registry,
        "semantic registry v4",
    )
    validate_instance(
        facts,
        "fact_profiles/v3.schema.json",
        registry,
        "fact profile registry v3",
    )
    validate_instance(
        presentation,
        "presentation_registry/v3.schema.json",
        registry,
        "presentation registry v3",
    )
    semantic_by_id = {entry["semantic_id"]: entry for entry in semantics["entries"]}
    profile_by_id = {
        profile["fact_profile_id"]: profile for profile in facts["profiles"]
    }
    presented = {profile["semantic_id"] for profile in presentation["profiles"]}
    if presented != set(semantic_by_id):
        raise ContractFailure("presentation v3 must cover every v4 semantic exactly")
    expected = {
        "keel.action.generate_text.v1": "keel.facts.generate_text_exact.v1",
        "keel.action.payment_refund.v1": "keel.facts.refund_exact.v1",
        "keel.action.agent_delegate.v1": "keel.facts.delegate_exact.v1",
    }
    for semantic_id, profile_id in expected.items():
        entry = semantic_by_id.get(semantic_id)
        profile = profile_by_id.get(profile_id)
        if entry is None or entry.get("fact_profile_id") != profile_id:
            raise ContractFailure(f"{semantic_id} is not bound to {profile_id}")
        if profile is None or semantic_id not in profile.get("semantic_ids", []):
            raise ContractFailure(f"{profile_id} does not admit {semantic_id}")
        schema_path = str(profile["facts_schema"])
        actual = "sha256:" + hashlib.sha256((ROOT / schema_path).read_bytes()).hexdigest()
        if profile.get("facts_schema_digest") != actual:
            raise ContractFailure(f"{profile_id} facts schema digest is stale")


def validate_enforcement_state_vectors() -> None:
    """Execute every enforcement-state golden vector.

    Registering the corpus by hash proves only that the bytes did not drift. It
    does not prove the documents still verify, so this executes each expected
    verdict on every run. An empty or unreadable corpus is a failure, never a
    silent pass.
    """

    corpus_path = ROOT / "test-vectors" / "enforcement_state" / "v1" / "corpus.json"
    if not corpus_path.is_file():
        raise ContractFailure(f"missing enforcement-state corpus: {corpus_path}")
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    vectors = corpus.get("vectors") or []
    if not vectors:
        raise ContractFailure("enforcement-state corpus declares no vectors")

    schemas: dict[str, Any] = {}
    for name in (
        "permit-enforcement-state-v1",
        "runtime-enforcement-proof-v1",
        "runtime-enforcement-proof-v2",
    ):
        schema_path = ROOT / "schemas" / f"{name}.schema.json"
        if not schema_path.is_file():
            raise ContractFailure(f"missing enforcement schema: {schema_path}")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        schemas[name] = schema

    seen_ids: set[str] = set()
    for vector in vectors:
        vector_id = str(vector.get("id") or "")
        if not vector_id or vector_id in seen_ids:
            raise ContractFailure(f"enforcement-state vector id missing or duplicated: {vector_id!r}")
        seen_ids.add(vector_id)
        schema_name = str(vector.get("schema") or "")
        if schema_name not in schemas:
            raise ContractFailure(f"{vector_id}: unknown schema {schema_name!r}")
        expected = str(vector.get("expected") or "")
        if expected not in {"valid", "invalid"}:
            raise ContractFailure(f"{vector_id}: expected must be valid or invalid")
        validator = jsonschema.Draft202012Validator(
            schemas[schema_name],
            format_checker=jsonschema.FormatChecker(),
        )
        is_valid = validator.is_valid(vector.get("document"))
        if is_valid != (expected == "valid"):
            raise ContractFailure(
                f"{vector_id}: expected {expected}, schema said "
                f"{'valid' if is_valid else 'invalid'}"
            )

    positives = sum(1 for v in vectors if v.get("expected") == "valid")
    if positives == 0 or positives == len(vectors):
        raise ContractFailure(
            "enforcement-state corpus must carry both positive and negative vectors"
        )


def _enforcement_proof_fixture(version: str) -> dict[str, Any]:
    """Minimal runtime enforcement proof for pack compatibility checks."""

    digest = "sha256:" + "0" * 64
    proof: dict[str, Any] = {
        "version": f"keel.runtime_enforcement_proof.{version}",
        "proof_id": "b7a1c0de-0000-4000-8000-0000000000aa",
        "permit_id": "0acadb95-eced-4a3a-84ee-6fe408216871",
        "project_id": "40a5edbc-8869-4579-80a3-26c739de30d0",
        "dispatch_id": "d1a5pa7c-0000-4000-8000-0000000000aa",
        "semantic_id": "keel.context.work.v1",
        "exact_request_digest": digest,
        "adapter_certification_id": "keel.adapter.work.v1",
        "adapter_certification_digest": digest,
        "deployment_assurance_id": "keel.deployment.work.v1",
        "deployment_assurance_digest": digest,
        "gate_id": "work.final_dispatch",
        "gate_revision": "1",
        "gate_result": "allow",
        "pre_effect": True,
        "evaluated_at": "2026-08-02T07:05:00Z",
        "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
        "issuer_key_id": "keel-export-2026",
        "canonical_hash": digest,
        "signature": "ed25519:AAAA",
    }
    if version == "v2":
        proof.update(
            {
                "effective_mode": "enforce",
                "global_ceiling": "enforce",
                "project_rung": "enforce",
                "mapping_version": "keel.enforcement_rung_mapping.v1",
                "enforcement_surface_key": "program:work",
                "dispatch_attempted": True,
                "upstream_called": True,
            }
        )
    return proof


def validate_pack_v3_compatibility(
    registry: Registry, exact_pack: dict[str, Any]
) -> None:
    """Prove the pack v3 contract itself, not only its component schemas.

    Pack v3 exists so one pack may carry either the historical v1 runtime proof
    or the v2 proof that records the enforcement regime. Cases run against the
    same real pack the universal contract check builds, so this cannot drift
    from the shipped pack shape, and through the shared registry so every
    external reference resolves.
    """

    schema_path = ROOT / "schemas" / "permit-exact-pack-v3.schema.json"
    if not schema_path.is_file():
        raise ContractFailure(f"missing pack schema: {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )

    base = copy.deepcopy(exact_pack)
    base["profile"] = "keel.permit_exact/v3"
    base["profile_version"] = 3
    # The shipped fixture carries enforcement_evidence: null, so synthesize the
    # block under test and attach it to the otherwise real pack. Only the
    # enforcement branch is synthetic; every other field stays as shipped.
    digest = "sha256:" + "0" * 64
    signed = {
        "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
        "issuer_key_id": "keel-export-2026",
        "canonical_hash": digest,
        "signature": "ed25519:AAAA",
    }
    base["enforcement_evidence"] = {
        "adapter_certification": {
            "version": "keel.adapter_certification.v1",
            "certification_id": "keel.adapter.work.v1",
            "adapter_id": "managed.work.dispatch",
            "adapter_version": "v1",
            "semantic_ids": ["keel.context.work.v1"],
            "governed_surfaces": ["work"],
            "conformance_vector_set_digest": digest,
            "negative_test_results_digest": digest,
            "anti_bypass_requirements": ["pre_effect_gate"],
            "issued_at": "2026-07-01T00:00:00Z",
            "expires_at": "2027-07-01T00:00:00Z",
            "revoked_at": None,
            "revocation_event_digest": None,
            **signed,
        },
        "deployment_assurance": {
            "version": "keel.deployment_assurance.v1",
            "assurance_id": "keel.deployment.work.v1",
            "project_id": "40a5edbc-8869-4579-80a3-26c739de30d0",
            "deployment_id": "keel-api",
            "deployment_revision": "f" * 40,
            "adapter_certification_id": "keel.adapter.work.v1",
            "adapter_certification_digest": digest,
            "adapter_id": "managed.work.dispatch",
            "adapter_version": "v1",
            "governed_surface": "work",
            "semantic_ids": ["keel.context.work.v1"],
            "anti_bypass_evidence_digest": digest,
            "verified_at": "2026-08-01T00:00:00Z",
            "expires_at": "2027-08-01T00:00:00Z",
            "revoked_at": None,
            "revocation_event_digest": None,
            **signed,
        },
        "runtime_enforcement_proof": _enforcement_proof_fixture("v1"),
    }

    with_v1 = copy.deepcopy(base)
    with_v1["enforcement_evidence"]["runtime_enforcement_proof"] = (
        _enforcement_proof_fixture("v1")
    )
    with_v2 = copy.deepcopy(base)
    with_v2["enforcement_evidence"]["runtime_enforcement_proof"] = (
        _enforcement_proof_fixture("v2")
    )

    stale_identity = copy.deepcopy(with_v2)
    stale_identity["profile"] = "keel.permit_exact/v2"
    stale_identity["profile_version"] = 2

    mixed = copy.deepcopy(with_v2)
    mixed["enforcement_evidence"]["runtime_enforcement_proof"]["version"] = (
        "keel.runtime_enforcement_proof.v1"
    )

    malformed = copy.deepcopy(with_v2)
    malformed["enforcement_evidence"]["runtime_enforcement_proof"].pop("effective_mode")

    cases: list[tuple[str, dict[str, Any], bool]] = [
        ("pack v3 carrying runtime proof v1", with_v1, True),
        ("pack v3 carrying runtime proof v2", with_v2, True),
        ("pack v3 claiming the v2 profile identity", stale_identity, False),
        ("pack v3 carrying a mixed v1/v2 proof", mixed, False),
        ("pack v3 carrying a malformed v2 proof", malformed, False),
    ]

    for label, document, expected_valid in cases:
        is_valid = validator.is_valid(document)
        if is_valid != expected_valid:
            raise ContractFailure(
                f"{label}: expected {'valid' if expected_valid else 'invalid'}, "
                f"schema said {'valid' if is_valid else 'invalid'}"
            )


def main() -> int:
    try:
        registry = schema_registry()
        validate_semantics_and_presentation(registry)
        validate_transactional_cx_contract(registry)
        validate_release_contract(registry)
        validate_identity_security_contract(registry)
        validate_coding_workspace_contract(registry)
        validate_collections_contract(registry)
        validate_insurance_claims_contract(registry)
        validate_erp_crm_contract(registry)
        validate_procurement_ap_contract(registry)
        validate_commerce_regulated_contract(registry)
        validate_wave5_breadth_contract(registry)
        validate_goal3a_portfolio_contract(registry)
        validate_human_artifact_contract(registry)
        validate_fact_profiles(registry)
        validate_work_contract(registry)
        validate_work_authority_v2_contract(registry)
        validate_concierge_semantic_contract(registry)
        validate_work_v2_contract_objects(registry)
        validate_claim_contracts()
        exact_pack = validate_universal_verification_contract(registry)
        validate_short_term_exact_profiles(registry)
        validate_artifact_manifest()
        validate_spec_document_pins()
        validate_enforcement_state_vectors()
        validate_pack_v3_compatibility(registry, exact_pack)
    except (ContractFailure, jsonschema.SchemaError) as exc:
        print(f"Permit-to-X contract check failed: {exc}")
        return 1
    print("Permit-to-X contract artifacts passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
