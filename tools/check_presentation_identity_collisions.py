#!/usr/bin/env python3
"""Fail when canonical Permit presentation identities collide."""

import copy

from build_presentation_acronym_registry import (
    V23,
    V24,
    acronym_for,
    validate_acronyms,
    validate_v23_acronyms,
    validate_v24_acronyms,
)
from build_presentation_identity_registry import validate_identity_collisions
from build_presentation_registry_v25 import ADDED_PROFILES, SEMANTIC_REGISTRY_VERSION, V25
from build_transactional_cx_registries import load


def expect_failure(check, registry: dict, needle: str, message: str) -> None:
    try:
        check(registry)
    except RuntimeError as exc:
        assert needle in str(exc), str(exc)
    else:
        raise AssertionError(message)


def check_v22() -> None:
    registry = load("presentation_registry/v22.json")
    validate_identity_collisions(registry)

    acronym_collision = copy.deepcopy(registry)
    profiles = acronym_collision["profiles"]
    profiles[0]["acronym"] = "AI-PTZ"
    profiles[1]["acronym"] = "AI-PTZ"
    expect_failure(
        validate_identity_collisions,
        acronym_collision,
        "acronym collisions",
        "Duplicate acronyms must fail validation",
    )

    title_collision = copy.deepcopy(registry)
    title_profiles = title_collision["profiles"]
    title_profiles[0]["customer_title"] = "AI Permit-to-Collide"
    title_profiles[1]["customer_title"] = "AI Permit-to-Collide"
    expect_failure(
        validate_identity_collisions,
        title_collision,
        "title collisions",
        "Unallowlisted duplicate titles must fail validation",
    )


def check_v23() -> None:
    registry = load("presentation_registry/v23.json")
    validate_v23_acronyms(registry)

    # Every profile's stored acronym is exactly the one the rule gives it.
    for profile in registry["profiles"]:
        assert profile.get("acronym") == acronym_for(profile, V23.prefix), profile["presentation_profile_id"]

    stale = copy.deepcopy(registry)
    work = next(p for p in stale["profiles"] if p["presentation_profile_id"] == "permit_to_work.r1")
    work["acronym"] = "AI-PTW"
    expect_failure(validate_v23_acronyms, stale, "v23 rule", "A v22-style acronym must fail v23 validation")

    alias = copy.deepcopy(registry)
    refund_v1 = next(p for p in alias["profiles"] if p["presentation_profile_id"] == "permit_to_refund_payment.r1")
    refund_v1["acronym"] = "AI-P2RPV"
    expect_failure(validate_v23_acronyms, alias, "v23 rule", "A second acronym on a shared title must fail")

    clash = copy.deepcopy(registry)
    machine = next(p for p in clash["profiles"] if p["customer_title"] == "AI Permit-to-Restart-Machine")
    machine["acronym"] = "AI-P2RM"
    expect_failure(validate_v23_acronyms, clash, "AI-P2RM", "A clashing acronym must fail v23 validation")


def check_v24() -> None:
    registry = load("presentation_registry/v24.json")
    validate_v24_acronyms(registry)

    for profile in registry["profiles"]:
        assert profile.get("acronym") == acronym_for(profile, V24.prefix), profile["presentation_profile_id"]

    # v24 keeps the three acronyms v22 published.
    v22 = {p["presentation_profile_id"]: p.get("acronym") for p in load("presentation_registry/v22.json")["profiles"]}
    for profile in registry["profiles"]:
        published = v22.get(profile["presentation_profile_id"])
        if published:
            assert profile["acronym"] == published, profile["presentation_profile_id"]

    # Only the acronym (and the registry's own version) differ from v23.
    v23 = load("presentation_registry/v23.json")
    for old, new in zip(v23["profiles"], registry["profiles"], strict=True):
        assert {k: v for k, v in old.items() if k != "acronym"} == {
            k: v for k, v in new.items() if k != "acronym"
        }, new["presentation_profile_id"]

    stale = copy.deepcopy(registry)
    work = next(p for p in stale["profiles"] if p["presentation_profile_id"] == "permit_to_work.r1")
    work["acronym"] = "AI-P2W"
    expect_failure(validate_v24_acronyms, stale, "v24 rule", "A v23-style acronym must fail v24 validation")

    alias = copy.deepcopy(registry)
    refund_v1 = next(p for p in alias["profiles"] if p["presentation_profile_id"] == "permit_to_refund_payment.r1")
    refund_v1["acronym"] = "AI-PTRPV"
    expect_failure(validate_v24_acronyms, alias, "v24 rule", "A second acronym on a shared title must fail")

    clash = copy.deepcopy(registry)
    machine = next(p for p in clash["profiles"] if p["customer_title"] == "AI Permit-to-Restart-Machine")
    machine["acronym"] = "AI-PTRM"
    expect_failure(validate_v24_acronyms, clash, "AI-PTRM", "A clashing acronym must fail v24 validation")


def check_v25() -> None:
    registry = load("presentation_registry/v25.json")
    validate_acronyms(registry, V25)

    # v25 is v24 plus the three Aidbox profiles, appended in order.
    v24 = load("presentation_registry/v24.json")
    kept = registry["profiles"][: len(v24["profiles"])]
    assert kept == v24["profiles"], "v25 must keep every v24 profile unchanged"
    added = registry["profiles"][len(v24["profiles"]) :]
    assert [p["semantic_id"] for p in added] == [p["semantic_id"] for p in ADDED_PROFILES]
    assert registry["semantic_registry_version"] == SEMANTIC_REGISTRY_VERSION
    for key in ("allowed_leading_fields", "allowed_evidence_sections", "human_artifact_contract", "fallback_profiles"):
        assert registry[key] == v24[key], key

    # Each added profile names a semantic of semantic registry v23 that no
    # earlier profile titles, and uses only allowed fields and sections.
    semantics = {e["semantic_id"] for e in load("semantic_registry/v23.json")["entries"]}
    titled = {p["semantic_id"] for p in v24["profiles"]}
    for profile in added:
        where = profile["presentation_profile_id"]
        assert profile["semantic_id"] in semantics, where
        assert profile["semantic_id"] not in titled, where
        assert {f["field"] for f in profile["leading_fields"]} <= set(registry["allowed_leading_fields"]), where
        assert set(profile["evidence_sections"]) <= set(registry["allowed_evidence_sections"]), where
        assert "immutable" not in profile["type_definition"].lower(), where
        assert profile["acronym"] == acronym_for(profile, V25.prefix), where

    clash = copy.deepcopy(registry)
    clash["profiles"][-1]["acronym"] = "AI-PTRP"
    expect_failure(
        lambda r: validate_acronyms(r, V25), clash, "acronym collisions", "A reused acronym must fail v25 validation"
    )


def main() -> None:
    check_v22()
    check_v23()
    check_v24()
    check_v25()


if __name__ == "__main__":
    main()
