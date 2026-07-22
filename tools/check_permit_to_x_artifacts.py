#!/usr/bin/env python3
"""Validate the bounded Work and Permit-to-X public contract artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
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
TRUSTED_SOURCE_KINDS = {
    "work_request_server_reconciled",
    "action_verb_execute",
    "realtime_session_service",
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


def schema_registry() -> Registry:
    registry = Registry()
    schema_paths = list((ROOT / "schemas").glob("*.schema.json"))
    schema_paths.extend(
        [
            ROOT / "semantic_registry/v1.schema.json",
            ROOT / "presentation_registry/v1.schema.json",
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
    if candidate.get("governed_surface") not in match["required_surfaces"]:
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
    presentations = load_json("presentation_registry/v1.json")
    validate_instance(
        semantics,
        "semantic_registry/v1.schema.json",
        registry,
        "semantic registry",
    )
    validate_instance(
        presentations,
        "presentation_registry/v1.schema.json",
        registry,
        "presentation registry",
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

    allowed_fields = set(presentations["allowed_leading_fields"])
    allowed_sections = set(presentations["allowed_evidence_sections"])
    forbidden_keys = {"claims", "verdict", "authorization_conditions", "policy_conditions"}
    for profile in presentations["profiles"]:
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


def main() -> int:
    try:
        registry = schema_registry()
        validate_semantics_and_presentation(registry)
        validate_work_contract(registry)
        validate_claim_contracts()
        validate_artifact_manifest()
    except (ContractFailure, jsonschema.SchemaError) as exc:
        print(f"Permit-to-X contract check failed: {exc}")
        return 1
    print("Permit-to-X contract artifacts passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
