#!/usr/bin/env python3
"""Validate additive Aidbox selectors/profiles and minimized schema examples."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = {
    "healthcare.patient.mailing_address.update",
    "healthcare.appointment.reschedule",
    "healthcare.records.release",
}
SCHEMA = "schemas/aidbox-fhir-exact-facts-v1.schema.json"


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def additive(before, after, field, identity):
    previous = {entry[identity]: entry for entry in before[field]}
    current = {entry[identity]: entry for entry in after[field]}
    require(len(current) == len(after[field]), f"{field}: duplicate identity")
    require(
        all(current.get(key) == value for key, value in previous.items()),
        f"{field}: historical entries dropped or reinterpreted",
    )
    return [entry for entry in after[field] if entry[identity] not in previous]


def validate_aidbox_contract():
    pairs = (
        ("semantic_registry", 22, 23, "entries", "semantic_id"),
        ("fact_profiles", 19, 20, "profiles", "fact_profile_id"),
    )
    additions = {}
    for directory, old, new, field, identity in pairs:
        before = load(f"{directory}/v{old}.json")
        after = load(f"{directory}/v{new}.json")
        validator = jsonschema.Draft202012Validator(load(f"{directory}/v{new}.schema.json"))
        validator.validate(after)
        additions[field] = additive(before, after, field, identity)
        require(len(additions[field]) == 3, f"{field}: expected exactly three Aidbox additions")
        # Permanent sibling regressions: both registry classes reject drops, rewrites and duplicates.
        for mode in ("drop", "rewrite", "duplicate"):
            damaged = copy.deepcopy(after)
            if mode == "drop":
                damaged[field] = damaged[field][1:]
            elif mode == "rewrite":
                damaged[field][0]["release_state"] = "changed"
            else:
                damaged[field].append(copy.deepcopy(damaged[field][0]))
            try:
                additive(before, damaged, field, identity)
            except ValueError:
                pass
            else:
                raise ValueError(f"{field}: {mode} regression escaped")
    require(
        {entry["match"]["action_names"][0] for entry in additions["entries"]} == ACTIONS,
        "Aidbox selectors must bind only the exact three action names",
    )
    require(
        {entry["authorized_action"] for entry in additions["profiles"]} == ACTIONS,
        "Aidbox profiles must bind only the exact three actions",
    )
    require(
        load("fact_profiles/v20.json")["disclosure_contract"] == load("fact_profiles/v19.json")["disclosure_contract"],
        "disclosure contract changed",
    )
    digest = "sha256:" + hashlib.sha256((ROOT / SCHEMA).read_bytes()).hexdigest()
    profiles = {entry["authorized_action"]: entry for entry in additions["profiles"]}
    for entry in additions["entries"]:
        action = entry["match"]["action_names"][0]
        profile = profiles[action]
        require(profile["fact_profile_id"] == entry["fact_profile_id"], "selector/profile identity mismatch")
        require(
            profile["facts_schema"] == SCHEMA and profile["facts_schema_digest"] == digest,
            "Aidbox facts schema pin mismatch",
        )
        require(entry["semantic_id"] in profile["semantic_ids"], "semantic missing from profile")
        require(
            entry["trusted_source_kinds"] == ["action_verb_execute"] and entry["match"]["operations"] == ["call.tools"],
            "untrusted selector source",
        )
        require("cost_permit" in entry["excluded_permit_products"], "cost authority expanded")
    schema = load(SCHEMA)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    vectors = load("fact_profiles/test-vectors/aidbox-v1.json")["cases"]
    require({case["action"] for case in vectors} == ACTIONS, "schema examples omit an action")
    for case in vectors:
        facts = case["facts"]
        validator.validate(facts)
        require(facts["fact_profile_id"] == profiles[case["action"]]["fact_profile_id"], "example profile mismatch")
        definition = next(
            v
            for v in schema["$defs"].values()
            if isinstance(v, dict) and v.get("properties", {}).get("action", {}).get("const") == case["action"]
        )
        for key in definition["required"]:
            missing = copy.deepcopy(facts)
            missing.pop(key)
            require(not validator.is_valid(missing), f"missing {key} accepted")
        for key, value in (
            ("max_uses", True),
            ("identity_verified", "true"),
            ("provider_environment", "production"),
            ("action", "healthcare.database.export"),
        ):
            wrong = copy.deepcopy(facts)
            wrong[key] = value
            require(not validator.is_valid(wrong), f"malformed {key} accepted")
    # Schema conformance describes facts, never a positive authorization or provider outcome.


if __name__ == "__main__":
    validate_aidbox_contract()
    print("Aidbox additive artifact and schema checks passed.")
