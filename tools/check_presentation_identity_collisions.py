#!/usr/bin/env python3
"""Fail when canonical Permit presentation identities collide."""

import copy

from build_presentation_acronym_registry import acronym_for, validate_v23_acronyms
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
        assert profile.get("acronym") == acronym_for(profile), profile["presentation_profile_id"]

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


def main() -> None:
    check_v22()
    check_v23()


if __name__ == "__main__":
    main()
