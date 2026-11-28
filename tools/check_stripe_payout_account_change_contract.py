#!/usr/bin/env python3
"""Validate the additive Stripe payout-account-change selector, profile and schema."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
ACTION = "stripe.external_account.create"
SCHEMA = "schemas/stripe-payout-account-change-exact-facts-v1.schema.json"
VECTORS = "fact_profiles/test-vectors/stripe-payout-account-change-v1.json"
#: Facts that must come from Stripe or the gateway, never the agent's arguments.
PROVIDER_READ_FACTS = (
    "connected_account_reference_commitment",
    "connected_account_state_digest",
    "new_account_fingerprint_commitment",
    "new_account_is_new_to_customer",
    "new_account_last4",
    "new_account_country",
    "new_account_currency",
    "previous_default_account_last4",
    "existing_external_account_count",
    "change_channel",
)


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


def validate_stripe_payout_account_change_contract():
    pairs = (
        ("semantic_registry", 23, 24, "entries", "semantic_id"),
        ("fact_profiles", 20, 21, "profiles", "fact_profile_id"),
    )
    additions = {}
    for directory, old, new, field, identity in pairs:
        before = load(f"{directory}/v{old}.json")
        after = load(f"{directory}/v{new}.json")
        jsonschema.Draft202012Validator(load(f"{directory}/v{new}.schema.json")).validate(after)
        additions[field] = additive(before, after, field, identity)
        require(len(additions[field]) == 1, f"{field}: expected exactly one payout-account addition")
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
        load("fact_profiles/v21.json")["disclosure_contract"]
        == load("fact_profiles/v20.json")["disclosure_contract"],
        "disclosure contract changed",
    )
    (entry,) = additions["entries"]
    (profile,) = additions["profiles"]
    require(entry["match"]["action_names"] == [ACTION], "selector must bind only the exact action")
    require(profile["authorized_action"] == ACTION, "profile must bind only the exact action")
    require(profile["fact_profile_id"] == entry["fact_profile_id"], "selector/profile identity mismatch")
    require(entry["semantic_id"] in profile["semantic_ids"], "semantic missing from profile")
    require(
        entry["trusted_source_kinds"] == ["action_verb_execute"]
        and entry["match"]["operations"] == ["call.tools"],
        "untrusted selector source",
    )
    require("cost_permit" in entry["excluded_permit_products"], "cost authority expanded")
    digest = "sha256:" + hashlib.sha256((ROOT / SCHEMA).read_bytes()).hexdigest()
    require(
        profile["facts_schema"] == SCHEMA and profile["facts_schema_digest"] == digest,
        "payout-account facts schema pin mismatch",
    )
    profile_paths = {field["path"] for field in profile["fields"]}
    for fact in PROVIDER_READ_FACTS:
        require(f"/{fact}" in profile_paths, f"profile omits provider-read fact {fact}")
        require(
            f"/{fact}" in profile["material_request_fact_paths"]
            or f"/{fact}" in profile["target_fact_paths"],
            f"{fact} is not bound as a target or material fact",
        )
    schema = load(SCHEMA)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    (case,) = load(VECTORS)["cases"]
    facts = case["facts"]
    require(case["action"] == ACTION, "schema example omits the action")
    validator.validate(facts)
    require(facts["fact_profile_id"] == profile["fact_profile_id"], "example profile mismatch")
    for key in schema["$defs"]["stripe_external_account_create"]["required"]:
        missing = copy.deepcopy(facts)
        missing.pop(key)
        require(not validator.is_valid(missing), f"missing {key} accepted")
    for key, value in (
        ("max_uses", True),
        ("max_uses", 2),
        ("default_for_currency", False),
        ("new_account_is_new_to_customer", "true"),
        ("new_account_is_new_to_customer", None),
        ("new_account_last4", "678"),
        ("new_account_last4", 6789),
        ("new_account_last4", "1234567890"),
        ("new_account_country", "us"),
        ("new_account_currency", "usd"),
        ("previous_default_account_last4", ""),
        ("existing_external_account_count", -1),
        ("existing_external_account_count", True),
        ("change_channel", "unknown"),
        ("change_channel", ""),
        ("provider_environment", "production"),
        ("target_is_dedicated_demo", False),
        ("action", "stripe.transfer.create"),
    ):
        wrong = copy.deepcopy(facts)
        wrong[key] = value
        require(not validator.is_valid(wrong), f"malformed {key}={value!r} accepted")
    extra = copy.deepcopy(facts)
    extra["routing_number"] = "110000000"
    require(not validator.is_valid(extra), "raw bank details accepted as an extra fact")
    built = subprocess.run(
        [sys.executable, str(ROOT / "tools/build_stripe_payout_account_change_registries.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    require(built.returncode == 0, "payout-account artifacts differ from a fresh build: " + built.stdout)
    # Schema conformance describes facts, never a positive authorization or provider outcome.


if __name__ == "__main__":
    validate_stripe_payout_account_change_contract()
    print("Stripe payout-account-change additive artifact and schema checks passed.")
