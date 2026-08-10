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
        if vector.get("pinned_profile") and (
            profile is None
            or profile["presentation_profile_id"] != vector["pinned_profile"]
        ):
            profile = fallback_by_id[vector["fallback"]]
        elif profile is None:
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
            if field["classification"] in {"personal_data", "free_text", "secret"}:
                if field["bulk_export_disclosure"] != "omit":
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
        "presentation_registry/v4.json",
        "presentation_registry/v4.schema.json",
        "presentation_registry/v5.json",
        "presentation_registry/v5.schema.json",
        "presentation_registry/v6.json",
        "presentation_registry/v6.schema.json",
        "presentation_registry/v7.json",
        "presentation_registry/v7.schema.json",
        "consequence_registry/v1.json",
        "consequence_registry/v1.schema.json",
        "consequence_registry/v2.json",
        "consequence_registry/v2.schema.json",
        "consequence_registry/v3.json",
        "consequence_registry/v3.schema.json",
        "consequence_registry/test-vectors/v1.json",
        "consequence_registry/test-vectors/v2.json",
        "consequence_registry/test-vectors/v3.json",
        "consequence_registry/test-vectors/v4.json",
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
        "schemas/database-exact-facts-v1.schema.json",
        "schemas/payment-ledger-exact-facts-v1.schema.json",
        "schemas/transactional-cx-exact-facts-v1.schema.json",
        "spec/transactional-cx-exact-action-contract-v1.md",
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
        validate_human_artifact_contract(registry)
        validate_fact_profiles(registry)
        validate_work_contract(registry)
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
