#!/usr/bin/env python3
"""Fail when canonical Permit presentation identities collide."""

import copy

from build_presentation_acronym_registry import (
    V23,
    V24,
    acronym_for,
    validate_v23_acronyms,
    validate_v24_acronyms,
)
from build_presentation_identity_registry import validate_identity_collisions
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


def main() -> None:
    check_v22()
    check_v23()
    check_v24()


if __name__ == "__main__":
    main()
