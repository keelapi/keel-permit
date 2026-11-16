#!/usr/bin/env python3
"""Validate the review document templates (v1, v2 and v3) against their schemas and the registries.

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

v2 adds the generic rule set. It pins the semantic, presentation and
fact-profile registries it reads by digest, and this check:

- validates `v2.json` against `v2.schema.json` and resolves its tailored
  templates against the pinned registries;
- checks the pins, the fallback presentation profile, the omitted fact keys
  and the generic sections;
- applies the generic plan to every pinned fact profile without a tailored
  template and fails if any commitment, target fact, non-cleartext fact or
  personal, sensitive or free-text fact would be shown in clear;
- recomputes `test-vectors/v2.json` with `tools/review_document_reference.py`.

v3 keeps v2's generic rule set and adds tailored templates with field formats,
sentence variants and cards (phase 3). Every v2 check runs on v3 too, plus
the format, sentence and card checks and their negative cases.

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


def schema_validate(document: dict[str, Any], schema: dict[str, Any], path: str = TEMPLATES_PATH) -> None:
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise TemplateFailure(f"{path} fails its schema at {location}: {first.message}")


def facts_def_for(fact_profile: dict[str, Any]) -> dict[str, Any]:
    """Return the facts-schema def whose fact_profile_id const is this profile."""

    schema_path = fact_profile["facts_schema"]
    raw = (ROOT / schema_path).read_bytes()
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != fact_profile.get("facts_schema_digest"):
        raise TemplateFailure(f"{schema_path} does not match the fact profile's facts_schema_digest")
    schema = json.loads(raw.decode("utf-8"))
    profile_id = fact_profile["fact_profile_id"]
    # A schema defines a profile at its top level (payment, refund v1, generate
    # text), as a $defs entry, or as one branch of an allOf composition.
    candidates: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("properties", {}).get("fact_profile_id", {}).get("const") == profile_id:
                candidates.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
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
    if template["presentation_profile_id"] is None:
        # Only a semantic the presentation registry does not describe may omit it.
        if any(p.get("semantic_id") == template["semantic_id"] for p in registries["presentation"]["profiles"]):
            raise TemplateFailure(f"{where}: semantic has a presentation profile the template must name")
    else:
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
                domain = value_domain(resolve(properties[field_id], load(fact_profile["facts_schema"]))[0])
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

    if template["beneficiary"] is not None:
        beneficiary = fields.get(template["beneficiary"]["field_id"])
        if beneficiary is None:
            raise TemplateFailure(f"{where}: beneficiary is not a field of the template")
        if beneficiary["source"] != "subject_facts" or "commitment" not in beneficiary:
            raise TemplateFailure(f"{where}: beneficiary must be a committed subject fact")

    validate_tailored_presentation(template, fact_profile, properties, fields)

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


# ---------------------------------------------------------------------------
# Phase 3: field formats, sentences and cards of tailored templates (v2)
# ---------------------------------------------------------------------------

FORMAT_KINDS = {
    "amount": {"integer"},
    "byte_count": {"integer"},
    "count": {"integer"},
    "hidden": {"commitment"},
    "recorded": {"digest", "raw_digest"},
    "request_code": {"digest"},
    "text": {"string"},
    "timestamp_utc": {"timestamp"},
}
SLOT_PATTERN = re.compile(r"\{([a-z_]+)\}")


def resolve(prop: dict[str, Any], schema: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Follow local $refs; return the target and every ref name passed through."""

    refs: list[str] = []
    while "$ref" in prop and prop["$ref"].startswith("#/") and prop["$ref"] not in refs:
        refs.append(prop["$ref"])
        node: Any = schema
        for part in prop["$ref"][2:].split("/"):
            node = node[part]
        prop = node
    return prop, refs


def fact_kind(prop: dict[str, Any], schema: dict[str, Any]) -> str:
    """Classify one facts-schema property by the shape a format can read."""

    target, refs = resolve(prop, schema)
    method = target.get("properties", {}).get("method", {}).get("const")
    if SALTED_COMMITMENT_REF in refs or method == "keel.salted_sha256_jcs.v1":
        return "commitment"
    prop = {**target, "$ref": refs[-1] if refs else ""}
    ref = prop.get("$ref", "")
    if ref == SALTED_COMMITMENT_REF:
        return "commitment"
    if ref.endswith("/rawDigest"):
        return "raw_digest"
    if ref.endswith("/digest") or prop.get("pattern", "").startswith("^sha256:"):
        return "digest"
    if ref.endswith("/timestamp") or prop.get("format") == "date-time":
        return "timestamp"
    const = prop.get("const")
    if prop.get("type") == "integer" or (isinstance(const, int) and not isinstance(const, bool)):
        return "integer"
    if prop.get("type") == "boolean" or isinstance(const, bool):
        return "boolean"
    if prop.get("type") == "string" or "enum" in prop or isinstance(prop.get("const"), str):
        return "string"
    return "other"


def check_value_spec(spec: dict[str, Any], properties: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    """A sentence slot, card side or field: its fact exists and its format or labels fit it."""

    if "constant" in spec:
        return
    fact = spec["field_id"]
    if fact not in properties:
        raise TemplateFailure(f"{label} reads {fact}, which is not a fact of the profile")
    kind = fact_kind(properties[fact], schema)
    prop, _ = resolve(properties[fact], schema)
    if "format" in spec and kind not in FORMAT_KINDS[spec["format"]]:
        raise TemplateFailure(f"{label} format {spec['format']} cannot read {kind} fact {fact}")
    if spec.get("format") == "amount" and "minor" not in fact.split("_"):
        raise TemplateFailure(f"{label} amount format needs a *_minor fact, not {fact}")
    if "values" in spec:
        domain = value_domain(prop)
        if domain is None:
            raise TemplateFailure(f"{label} labels values of an unbounded fact {fact}")
        if set(spec["values"]) != domain:
            raise TemplateFailure(
                f"{label} value labels {sorted(spec['values'])} must equal the fact's values {sorted(domain)}"
            )
    if kind == "commitment" and spec.get("format") != "hidden":
        raise TemplateFailure(f"{label} shows commitment {fact} without the hidden format")


def validate_tailored_presentation(
    template: dict[str, Any],
    fact_profile: dict[str, Any],
    properties: dict[str, Any],
    fields: dict[str, dict[str, Any]],
) -> None:
    where = template["template_id"]
    schema = load(fact_profile["facts_schema"])
    for field_id, field in fields.items():
        shows_fact = field["source"] == "exact_facts"
        if shows_fact and ("format" in field or fact_kind(properties[field_id], schema) == "commitment"):
            check_value_spec(
                {key: field[key] for key in ("field_id", "format", "values") if key in field},
                properties,
                schema,
                f"{where}: field {field_id}",
            )
    has_money = any(field.get("format") == "amount" for field in fields.values())
    if has_money and "currency" not in properties:
        raise TemplateFailure(f"{where}: amount format needs a currency fact in the profile")

    def repeated(fact: str, label: str, *, essential: bool) -> None:
        # Sentence and cards only repeat facts the sections show.
        field = fields.get(fact)
        if field is None or field["source"] != "exact_facts":
            raise TemplateFailure(f"{label} uses {fact}, which no section shows")
        if essential and not field["essential"]:
            raise TemplateFailure(f"{label} uses {fact}, which is not an essential field")

    sentence = template.get("sentence")
    if isinstance(sentence, dict):
        variants = sentence["variants"]
        if "when" in variants[-1] or any("when" not in item for item in variants[:-1]):
            raise TemplateFailure(f"{where}: only the last sentence variant has no condition")
        used: set[str] = set()
        for index, item in enumerate(variants):
            label = f"{where}: sentence variant {index}"
            for fact, expected in item.get("when", {}).items():
                repeated(fact, label, essential=True)
                domain = value_domain(resolve(properties[fact], schema)[0])
                key = json.dumps(expected) if isinstance(expected, bool) else str(expected)
                if domain is not None and key not in domain:
                    raise TemplateFailure(f"{label} condition {fact}={expected!r} is not a value of the fact")
            names = SLOT_PATTERN.findall(item["text"])
            unknown = sorted(set(names) - set(sentence["slots"]))
            if unknown:
                raise TemplateFailure(f"{label} names undefined slots {unknown}")
            if re.sub(SLOT_PATTERN, "", item["text"]).count("{") or re.sub(SLOT_PATTERN, "", item["text"]).count("}"):
                raise TemplateFailure(f"{label} has a malformed slot")
            used.update(names)
        unused = sorted(set(sentence["slots"]) - used)
        if unused:
            raise TemplateFailure(f"{where}: sentence slots {unused} are never used")
        for name, spec in sentence["slots"].items():
            label = f"{where}: sentence slot {name}"
            if "constant" in spec:
                raise TemplateFailure(f"{label} is a constant; write it into the sentence")
            check_value_spec(spec, properties, schema, label)
            repeated(spec["field_id"], label, essential=True)

    card_ids: set[str] = set()
    for card in template.get("cards", []):
        label = f"{where}: card {card['card_id']}"
        if card["card_id"] in card_ids:
            raise TemplateFailure(f"{label} appears more than once")
        card_ids.add(card["card_id"])
        if card["kind"] == "amount":
            sides = [{"field_id": card["field_id"], "format": "amount"}]
        else:
            sides = [card["from"], card["to"]]
        if not any("field_id" in side for side in sides):
            raise TemplateFailure(f"{label} shows no fact")
        # The review sheet's strict contract: a change card names two facts and
        # carries no Hidden side.
        if card["kind"] == "change" and not all("field_id" in side for side in sides):
            raise TemplateFailure(f"{label} change card must compare two facts")
        if any(side.get("format") == "hidden" for side in sides):
            raise TemplateFailure(f"{label} cards show no Hidden facts")
        for side in sides:
            check_value_spec(side, properties, schema, label)
            if "field_id" in side:
                repeated(side["field_id"], label, essential=False)


def validate(document: dict[str, Any], schema: dict[str, Any], registries: dict[str, dict[str, Any]]) -> None:
    schema_validate(document, schema)
    validate_templates(document, registries)


def validate_templates(document: dict[str, Any], registries: dict[str, dict[str, Any]]) -> None:
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


# ---------------------------------------------------------------------------
# v2: tailored templates plus the generic rule set
# ---------------------------------------------------------------------------

V2_TEMPLATES_PATH = "review_document_templates/v2.json"
V2_SCHEMA_PATH = "review_document_templates/v2.schema.json"
V2_VECTORS_PATH = "review_document_templates/test-vectors/v2.json"
GENERIC_VERSIONS = (2, 3)
SOURCE_KEYS = {"semantic_registry": "semantic", "presentation_registry": "presentation", "fact_profiles": "facts"}
NOT_CLEAR_CLASSIFICATIONS = {"personal_data", "sensitive_data", "free_text"}


def pinned_registries(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Load the registries v2 pins, checking each file's digest and version."""

    registries: dict[str, dict[str, Any]] = {}
    for name, pin in document["source_registries"].items():
        path = ROOT / pin["path"]
        if not path.is_file():
            raise TemplateFailure(f"source registry {pin['path']} does not exist")
        raw = path.read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != pin["digest"]:
            raise TemplateFailure(f"source registry {pin['path']} does not match its pinned digest")
        registry = json.loads(raw.decode("utf-8"))
        if registry.get("version") != pin["version"]:
            raise TemplateFailure(f"source registry {pin['path']} is not {pin['version']}")
        registries[SOURCE_KEYS[name]] = registry
    return registries


def disclosure_audit(document: dict[str, Any], registries: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Apply the generic plan to every pinned profile and check nothing private is shown in clear."""

    from review_document_reference import GenericPlan, label_for

    rules = document["generic"]
    tailored = {(t["semantic_id"], t["fact_profile_id"]) for t in document["templates"]}
    selects = {
        entry["semantic_id"]: entry.get("fact_profile_id") for entry in registries["semantic"]["entries"]
    }
    presentation_ids = {p.get("semantic_id") for p in registries["presentation"]["profiles"]}
    totals = {"profiles": 0, "clear": 0, "hidden": 0, "omitted": 0, "fallback_title": 0}
    for profile in registries["facts"]["profiles"]:
        semantics = [s for s in profile["semantic_ids"] if selects.get(s) == profile["fact_profile_id"]]
        semantics = [s for s in semantics if (s, profile["fact_profile_id"]) not in tailored]
        if not semantics:
            continue
        totals["profiles"] += 1
        totals["fallback_title"] += sum(1 for s in semantics if s not in presentation_ids)
        plan = GenericPlan(rules, profile)
        where = profile["fact_profile_id"]
        for fact in plan.fields:
            key = fact["key"]
            label = label_for(key, rules["labels"])
            if not 1 <= len(label) <= 80:
                raise TemplateFailure(f"{where}: label for {key} is empty or too long")
            if plan.omitted(key):
                totals["omitted"] += 1
                continue
            if not plan.clear(key):
                totals["hidden"] += 1
                continue
            totals["clear"] += 1
            if fact["value_type"] == "commitment" or key.endswith("_commitment"):
                raise TemplateFailure(f"{where}: commitment {key} would be shown in clear")
            if fact["classification"] in NOT_CLEAR_CLASSIFICATIONS:
                raise TemplateFailure(f"{where}: {fact['classification']} fact {key} would be shown in clear")
            if fact["disclosure"]["authorized"] != "cleartext":
                raise TemplateFailure(f"{where}: {key} is not authorized in cleartext but would be shown")
            if f"/{key}" in profile["target_fact_paths"]:
                raise TemplateFailure(f"{where}: target fact {key} would be shown in clear")
    return totals


def validate_generic(document: dict[str, Any], registries: dict[str, dict[str, Any]]) -> dict[str, int]:
    rules = document["generic"]
    if rules["template_id"] in {t["template_id"] for t in document["templates"]}:
        raise TemplateFailure("generic template id collides with a tailored template id")
    fallback = [
        p
        for p in registries["presentation"]["fallback_profiles"]
        if p["presentation_profile_id"] == rules["fallback_presentation_profile_id"]
    ]
    if len(fallback) != 1:
        fallback_id = rules["fallback_presentation_profile_id"]
        raise TemplateFailure(f"fallback presentation profile {fallback_id} is not defined")
    all_keys = {f["path"][1:] for p in registries["facts"]["profiles"] for f in p["fields"]}
    unknown = sorted(set(rules["omit"]["fact_keys"]) - all_keys)
    if unknown:
        raise TemplateFailure(f"omitted fact keys {unknown} are not facts of any pinned profile")
    if rules["amount"]["currency_fact"] not in all_keys:
        raise TemplateFailure("the currency fact is not a fact of any pinned profile")
    contents = [section["content"] for section in rules["sections"]]
    if contents.count("exact_facts") != 1:
        raise TemplateFailure("the generic rule set must have exactly one exact_facts section")
    section_ids = [section["section_id"] for section in rules["sections"]]
    if len(section_ids) != len(set(section_ids)):
        raise TemplateFailure("generic section ids are not distinct")
    provenance_ids = {kind["id"] for kind in document["provenance_kinds"]}
    for section in rules["sections"]:
        for spec in section.get("fields", []):
            if spec["provenance"] not in provenance_ids:
                raise TemplateFailure(f"generic field {spec['field_id']} has undeclared provenance")
    card_ids = {kind["id"] for kind in document["card_kinds"]}
    if card_ids != {"amount", "change"}:
        raise TemplateFailure("card kinds must be amount and change")
    return disclosure_audit(document, registries)


def validate_v2(
    document: dict[str, Any], schema: dict[str, Any], path: str = V2_TEMPLATES_PATH
) -> dict[str, int]:
    schema_validate(document, schema, path)
    registries = pinned_registries(document)
    validate_templates(document, registries)
    return validate_generic(document, registries)


def negative_cases_v2(document: dict[str, Any], schema: dict[str, Any], *, tailored: bool = False) -> None:
    def generic(d: dict[str, Any]) -> dict[str, Any]:
        return d["generic"]

    def pins(d: dict[str, Any], name: str) -> dict[str, Any]:
        return d["source_registries"][name]

    def collide(d: dict[str, Any]) -> None:
        d["templates"][0].update(template_id=generic(d)["template_id"])

    def two_field_sections(d: dict[str, Any]) -> None:
        generic(d)["sections"][0].update(content="fields", fields=generic(d)["sections"][1]["fields"])

    cases: list[tuple[Callable[[dict[str, Any]], None], str]] = [
        (lambda d: generic(d)["disclosure"].update(hide_target_fact_paths=False), "fails its schema"),
        (lambda d: generic(d)["disclosure"]["clear_classifications"].append("personal_data"), "fails its schema"),
        (lambda d: generic(d)["disclosure"].update(hidden_value_types=["digest"]), "fails its schema"),
        (lambda d: generic(d)["disclosure"].update(audience="private"), "fails its schema"),
        (lambda d: generic(d).update(extra=True), "fails its schema"),
        (lambda d: d.update(document_format="keel.review_document.v1"), "fails its schema"),
        (lambda d: pins(d, "fact_profiles").update(digest="sha256:" + "0" * 64), "pinned digest"),
        (lambda d: pins(d, "presentation_registry").update(path="presentation_registry/v23.json"), "pinned digest"),
        (lambda d: pins(d, "semantic_registry").update(path="semantic_registry/v99.json"), "does not exist"),
        (lambda d: generic(d).update(fallback_presentation_profile_id="no_such_profile"), "not defined"),
        (lambda d: generic(d)["omit"]["fact_keys"].append("no_such_fact"), "not facts of any"),
        (lambda d: generic(d)["amount"].update(currency_fact="no_currency"), "currency fact"),
        (collide, "collides"),
        (two_field_sections, "exactly one"),
        (lambda d: generic(d)["sections"][1].update(section_id="checked_facts"), "not distinct"),
        (lambda d: generic(d)["sections"][1]["fields"][0].update(source="exact_facts"), "fails its schema"),
        (lambda d: field(d, "group_privilege_class").update(field_id="group_privilege_tier"), "is not a property"),
        *(tailored_negative_cases() if tailored else []),
    ]
    for mutate, needle in cases:
        broken = copy.deepcopy(document)
        mutate(broken)
        try:
            validate_v2(broken, schema)
        except TemplateFailure as exc:
            if needle not in str(exc):
                raise AssertionError(f"expected {needle!r} in v2 failure, got: {exc}") from exc
            continue
        raise AssertionError(f"v2 mutation expected to fail with {needle!r} passed validation")


def tailored_negative_cases() -> list[tuple[Callable[[dict[str, Any]], None], str]]:
    """Phase 3: a weakened format, sentence or card rule must fail loudly."""

    def tpl(d: dict[str, Any], template_id: str) -> dict[str, Any]:
        return next(t for t in d["templates"] if t["template_id"] == template_id)

    def pay(d: dict[str, Any]) -> dict[str, Any]:
        return tpl(d, "payment_execute.review.r1")

    def release(d: dict[str, Any]) -> dict[str, Any]:
        return tpl(d, "healthcare_records_release.review.r1")

    def pay_field(d: dict[str, Any], field_id: str) -> dict[str, Any]:
        return next(f for s in pay(d)["sections"] for f in s["fields"] if f["field_id"] == field_id)

    def release_field(d: dict[str, Any], field_id: str) -> dict[str, Any]:
        return next(f for s in release(d)["sections"] for f in s["fields"] if f["field_id"] == field_id)

    def unhide_patient(d: dict[str, Any]) -> None:
        release_field(d, "patient_reference_commitment").pop("format")

    def demote_amount(d: dict[str, Any]) -> None:
        pay_field(d, "amount_minor").update(essential=False)

    def drop_amount_field(d: dict[str, Any]) -> None:
        for section in pay(d)["sections"]:
            section["fields"] = [f for f in section["fields"] if f["field_id"] != "amount_minor"] or section["fields"]

    def unconditional_first(d: dict[str, Any]) -> None:
        release(d)["sentence"]["variants"][0].pop("when")

    def foreign_condition(d: dict[str, Any]) -> None:
        release(d)["sentence"]["variants"][0]["when"] = {"record_is_synthetic": False}

    def constant_change_side(d: dict[str, Any]) -> None:
        side = {"field_id": "amount_minor", "format": "amount"}
        pay(d)["cards"].append({"card_id": "x", "kind": "change", "label": "X", "from": side, "to": {"constant": "0"}})

    def hidden_change_side(d: dict[str, Any]) -> None:
        hidden_side = {"field_id": "recipient_reference_commitment", "format": "hidden"}
        amount_side = {"field_id": "amount_minor", "format": "amount"}
        pay(d)["cards"].append({"card_id": "x", "kind": "change", "label": "X", "from": amount_side, "to": hidden_side})

    return [
        (unhide_patient, "without the hidden format"),
        (lambda d: release_field(d, "total_bytes").update(format="timestamp_utc"), "cannot read"),
        (lambda d: release_field(d, "request_digest").update(format="hidden"), "cannot read"),
        (lambda d: pay_field(d, "payment_rail").update(format="amount"), "cannot read"),
        (lambda d: release_field(d, "record_is_synthetic").update(values={"false": "No"}), "must equal"),
        (lambda d: pay(d)["sentence"]["variants"][0].update(text="Pay {total} to one recipient."), "undefined slots"),
        (lambda d: pay(d)["sentence"]["variants"][0].update(text="Pay {amount to one."), "malformed slot"),
        (lambda d: pay(d)["sentence"]["slots"].update(rail={"field_id": "payment_rail"}), "never used"),
        (demote_amount, "not an essential field"),
        (drop_amount_field, "which no section shows"),
        (unconditional_first, "only the last sentence variant"),
        (foreign_condition, "is not a value of the fact"),
        (lambda d: pay(d)["cards"].append(dict(pay(d)["cards"][0])), "appears more than once"),
        (constant_change_side, "must compare two facts"),
        (hidden_change_side, "cards show no Hidden facts"),
        (lambda d: pay(d).update(presentation_profile_id=None), "must name"),
        (lambda d: pay_field(d, "amount_minor").update(source="review", field_id="cause"), "fails its schema"),
        (lambda d: pay_field(d, "currency").update(values={"USD": "US dollar"}), "fails its schema"),
    ]


def check_v2(version: int = 2) -> str:
    from review_document_reference import run_vectors

    templates_path = f"review_document_templates/v{version}.json"
    schema = load(f"review_document_templates/v{version}.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    document = load(templates_path)
    totals = validate_v2(document, schema, templates_path)
    negative_cases_v2(document, schema, tailored=version >= 3)
    if run_vectors(ROOT, version=version) != 0:
        vectors = f"review_document_templates/test-vectors/v{version}.json"
        raise TemplateFailure(f"{vectors} does not match the reference builder")
    return (
        f"v{version}: {len(document['templates'])} tailored template(s) and the generic rule set over "
        f"{totals['profiles']} profile(s): {totals['clear']} facts in clear, {totals['hidden']} Hidden, "
        f"{totals['omitted']} left out; {totals['fallback_title']} semantic(s) use the fallback title"
    )


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
        summaries = [check_v2(version) for version in GENERIC_VERSIONS]
    except (TemplateFailure, AssertionError) as exc:
        print(f"Review document template check failed: {exc}")
        return 1
    pinned = ", ".join(registry_paths.values())
    print(f"Review document templates passed ({len(document['templates'])} v1 template(s) against {pinned}).")
    for summary in summaries:
        print(f"Review document templates {summary}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
