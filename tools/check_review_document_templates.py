#!/usr/bin/env python3
"""Validate the review document templates against their schema and the registries.

A review document template says which already-bound facts a reviewer sees and
how each one is labelled. It is presentation: it cannot create, alter or
complete a fact, and it never decides whether an action is allowed. This check
makes sure every template points at facts that exist:

- the file validates against its strict JSON Schema;
- each template's semantic, presentation profile and fact profile exist in
  the newest semantic, presentation and fact-profile registries, and agree
  with each other;
- every `exact_facts` field is a property of the fact profile's schema def;
- value labels cover exactly the values that fact can take;
- every `commitment` names a salted-commitment target fact;
- the beneficiary is a committed subject fact, and the protected values are
  values of the named fact's enum;
- every provenance and source id resolves to a declared kind.

Negative cases run after the positive pass so a weakened check fails loudly.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_PATH = "review_document_templates/v1.json"
SCHEMA_PATH = "review_document_templates/v1.schema.json"
SALTED_COMMITMENT_REF = "#/$defs/saltedCommitment"
VERSIONED_FILE = re.compile(r"^v([1-9][0-9]*)\.json$")


class TemplateFailure(RuntimeError):
    """Raised when a review document template is inconsistent."""


def load(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def newest(directory: str) -> str:
    """Return the path of the highest-numbered vN.json in a registry directory."""

    versions = [
        int(match.group(1))
        for entry in (ROOT / directory).iterdir()
        if (match := VERSIONED_FILE.match(entry.name))
    ]
    if not versions:
        raise TemplateFailure(f"{directory} has no versioned registry")
    return f"{directory}/v{max(versions)}.json"


def one(values: list[dict[str, Any]], key: str, expected: str, where: str) -> dict[str, Any]:
    matches = [value for value in values if value.get(key) == expected]
    if len(matches) != 1:
        raise TemplateFailure(f"{where}: expected exactly one {key}={expected}, found {len(matches)}")
    return matches[0]


def schema_validate(document: dict[str, Any], schema: dict[str, Any]) -> None:
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise TemplateFailure(f"{TEMPLATES_PATH} fails its schema at {location}: {first.message}")


def facts_def_for(fact_profile: dict[str, Any]) -> dict[str, Any]:
    """Return the facts-schema def whose fact_profile_id const is this profile."""

    schema_path = fact_profile["facts_schema"]
    raw = (ROOT / schema_path).read_bytes()
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != fact_profile.get("facts_schema_digest"):
        raise TemplateFailure(f"{schema_path} does not match the fact profile's facts_schema_digest")
    schema = json.loads(raw.decode("utf-8"))
    profile_id = fact_profile["fact_profile_id"]
    candidates = [
        definition
        for definition in schema.get("$defs", {}).values()
        if isinstance(definition, dict)
        and definition.get("properties", {}).get("fact_profile_id", {}).get("const") == profile_id
    ]
    if len(candidates) != 1:
        raise TemplateFailure(f"{schema_path} must define exactly one def for {profile_id}")
    return candidates[0]


def value_domain(prop: dict[str, Any]) -> set[str] | None:
    """Return the label keys a fact property can take, or None when unbounded."""

    def key(value: Any) -> str:
        return json.dumps(value) if isinstance(value, bool) else str(value)

    if "const" in prop:
        return {key(prop["const"])}
    if "enum" in prop:
        return {key(value) for value in prop["enum"]}
    if prop.get("type") == "boolean":
        return {"false", "true"}
    return None


def validate_template(
    template: dict[str, Any],
    registries: dict[str, dict[str, Any]],
    document: dict[str, Any],
) -> None:
    where = template["template_id"]
    semantic = one(registries["semantic"]["entries"], "semantic_id", template["semantic_id"], where)
    if semantic.get("fact_profile_id") != template["fact_profile_id"]:
        raise TemplateFailure(f"{where}: semantic {template['semantic_id']} selects a different fact profile")
    presentation = one(
        registries["presentation"]["profiles"],
        "presentation_profile_id",
        template["presentation_profile_id"],
        where,
    )
    if presentation.get("semantic_id") != template["semantic_id"]:
        raise TemplateFailure(f"{where}: presentation profile belongs to a different semantic")
    fact_profile = one(registries["facts"]["profiles"], "fact_profile_id", template["fact_profile_id"], where)
    if template["semantic_id"] not in fact_profile.get("semantic_ids", []):
        raise TemplateFailure(f"{where}: fact profile does not list semantic {template['semantic_id']}")
    facts_def = facts_def_for(fact_profile)
    properties = facts_def["properties"]
    target_paths = set(fact_profile.get("target_fact_paths", []))

    provenance_ids = {kind["id"] for kind in document["provenance_kinds"]}
    source_ids = {source["id"] for source in document["fact_sources"]}

    section_ids: set[str] = set()
    fields: dict[str, dict[str, Any]] = {}
    commitments: set[str] = set()
    for section in template["sections"]:
        if section["section_id"] in section_ids:
            raise TemplateFailure(f"{where}: duplicate section {section['section_id']}")
        section_ids.add(section["section_id"])
        for field in section["fields"]:
            field_id = field["field_id"]
            label = f"{where}: field {field_id}"
            if field_id in fields:
                raise TemplateFailure(f"{label} appears more than once")
            fields[field_id] = field
            if field["provenance"] not in provenance_ids:
                raise TemplateFailure(f"{label} has undeclared provenance {field['provenance']}")
            if field["source"] not in source_ids:
                raise TemplateFailure(f"{label} has undeclared source {field['source']}")

            if field["source"] == "exact_facts":
                if field_id not in properties:
                    raise TemplateFailure(f"{label} is not a property of {template['fact_profile_id']}")
                domain = value_domain(properties[field_id])
                if "values" in field:
                    if domain is None:
                        raise TemplateFailure(f"{label} labels values of an unbounded fact")
                    if set(field["values"]) != domain:
                        raise TemplateFailure(
                            f"{label} value labels {sorted(field['values'])} must equal the fact's values "
                            f"{sorted(domain)}"
                        )

            if "commitment" in field:
                commitment = field["commitment"]
                if properties.get(commitment, {}).get("$ref") != SALTED_COMMITMENT_REF:
                    raise TemplateFailure(f"{label} commitment {commitment} is not a saltedCommitment fact")
                if f"/{commitment}" not in target_paths:
                    raise TemplateFailure(f"{label} commitment {commitment} is not a target fact path")
                if commitment in commitments:
                    raise TemplateFailure(f"{label} reuses commitment {commitment}")
                commitments.add(commitment)

    if not any(field["essential"] for field in fields.values()):
        raise TemplateFailure(f"{where}: at least one field must be essential")

    explanation = template["requester_explanation"]
    if explanation["provenance"] not in provenance_ids:
        raise TemplateFailure(f"{where}: requester explanation has undeclared provenance")

    overlap = set(template["status_outside_digest"]) & set(fields)
    if overlap:
        raise TemplateFailure(f"{where}: status outside the digest overlaps document fields {sorted(overlap)}")

    beneficiary = fields.get(template["beneficiary"]["field_id"])
    if beneficiary is None:
        raise TemplateFailure(f"{where}: beneficiary is not a field of the template")
    if beneficiary["source"] != "subject_facts" or "commitment" not in beneficiary:
        raise TemplateFailure(f"{where}: beneficiary must be a committed subject fact")

    rule = template.get("protected_class_rule")
    if rule is not None:
        fact = fields.get(rule["fact"])
        if fact is None or fact["source"] != "exact_facts":
            raise TemplateFailure(f"{where}: protected-class fact must be an exact_facts field of the template")
        enum = properties[rule["fact"]].get("enum")
        if not isinstance(enum, list):
            raise TemplateFailure(f"{where}: protected-class fact {rule['fact']} is not an enum")
        unknown = sorted(set(rule["protected_values"]) - set(enum))
        if unknown:
            raise TemplateFailure(f"{where}: protected values {unknown} are not values of {rule['fact']}")


def validate(document: dict[str, Any], schema: dict[str, Any], registries: dict[str, dict[str, Any]]) -> None:
    schema_validate(document, schema)
    for key in ("provenance_kinds", "fact_sources"):
        ids = [item["id"] for item in document[key]]
        if len(ids) != len(set(ids)):
            raise TemplateFailure(f"{key} ids are not distinct")
    template_ids = [template["template_id"] for template in document["templates"]]
    if len(template_ids) != len(set(template_ids)):
        raise TemplateFailure("template ids are not distinct")
    for template in document["templates"]:
        validate_template(template, registries, document)


def expect_failure(
    mutate: Callable[[dict[str, Any]], None],
    needle: str,
    document: dict[str, Any],
    schema: dict[str, Any],
    registries: dict[str, dict[str, Any]],
) -> None:
    broken = copy.deepcopy(document)
    mutate(broken)
    try:
        validate(broken, schema, registries)
    except TemplateFailure as exc:
        if needle not in str(exc):
            raise AssertionError(f"expected {needle!r} in failure, got: {exc}") from exc
        return
    raise AssertionError(f"mutation expected to fail with {needle!r} passed validation")


def field(document: dict[str, Any], field_id: str) -> dict[str, Any]:
    return next(
        item
        for section in document["templates"][0]["sections"]
        for item in section["fields"]
        if item["field_id"] == field_id
    )


def negative_cases(document: dict[str, Any], schema: dict[str, Any], registries: dict[str, dict[str, Any]]) -> None:
    cases: list[tuple[Callable[[dict[str, Any]], None], str]] = [
        (lambda d: field(d, "group_privilege_class").update(field_id="group_privilege_tier"), "is not a property"),
        (lambda d: d["templates"][0].update(presentation_profile_id="identity_group_access_grant.r9"), "exactly one"),
        (lambda d: d["templates"][0].update(semantic_id="keel.action.identity_disable.v1"), "different"),
        (lambda d: d["templates"][0].update(fact_profile_id="keel.facts.identity_disable_exact.v1"), "different"),
        (lambda d: field(d, "group.id").update(commitment="group_state_commitment"), "not a saltedCommitment"),
        (lambda d: field(d, "tenant.host").update(commitment="group_reference_commitment"), "reuses commitment"),
        (lambda d: field(d, "current_membership")["values"].update({"true": "Member"}), "must equal"),
        (lambda d: field(d, "group_privilege_class")["values"].pop("standard"), "must equal"),
        (lambda d: field(d, "current_group_member_count").update(values={"1": "One"}), "unbounded"),
        (lambda d: d["templates"][0]["protected_class_rule"]["protected_values"].append("superuser"), "not values"),
        (lambda d: d["templates"][0]["protected_class_rule"].update(fact="current_membership"), "not an enum"),
        (lambda d: d["templates"][0]["beneficiary"].update(field_id="target_user.display_name"), "committed"),
        (lambda d: field(d, "cause").update(provenance="agent_reported"), "fails its schema"),
        (lambda d: field(d, "request_digest").update(provenance="gateway_reported"), "fails its schema"),
        (lambda d: field(d, "group.name").update(source="witness"), "fails its schema"),
        (lambda d: field(d, "access_duration").pop("constant"), "fails its schema"),
        (lambda d: d["templates"][0]["requester_explanation"].update(authoritative=True), "fails its schema"),
        (lambda d: d["templates"][0].update(extra=True), "fails its schema"),
        (lambda d: d["provenance_kinds"].pop(), "undeclared provenance"),
        (lambda d: d["templates"][0]["status_outside_digest"].append("filing_state"), "fails its schema"),
    ]
    for mutate, needle in cases:
        expect_failure(mutate, needle, document, schema, registries)


def main() -> int:
    schema = load(SCHEMA_PATH)
    jsonschema.Draft202012Validator.check_schema(schema)
    document = load(TEMPLATES_PATH)
    registry_paths = {
        "semantic": newest("semantic_registry"),
        "presentation": newest("presentation_registry"),
        "facts": newest("fact_profiles"),
    }
    registries = {name: load(path) for name, path in registry_paths.items()}
    try:
        validate(document, schema, registries)
        negative_cases(document, schema, registries)
    except (TemplateFailure, AssertionError) as exc:
        print(f"Review document template check failed: {exc}")
        return 1
    pinned = ", ".join(registry_paths.values())
    print(f"Review document templates passed ({len(document['templates'])} template(s) against {pinned}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
