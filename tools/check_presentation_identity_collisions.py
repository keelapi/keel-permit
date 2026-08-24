#!/usr/bin/env python3
"""Fail when canonical Permit presentation identities collide."""

import copy

from build_presentation_identity_registry import validate_identity_collisions
from build_transactional_cx_registries import load


def main() -> None:
    registry = load("presentation_registry/v22.json")
    validate_identity_collisions(registry)

    acronym_collision = copy.deepcopy(registry)
    profiles = acronym_collision["profiles"]
    profiles[0]["acronym"] = "AI-PTZ"
    profiles[1]["acronym"] = "AI-PTZ"
    try:
        validate_identity_collisions(acronym_collision)
    except RuntimeError as exc:
        assert "acronym collisions" in str(exc)
    else:
        raise AssertionError("Duplicate acronyms must fail validation")

    title_collision = copy.deepcopy(registry)
    title_profiles = title_collision["profiles"]
    title_profiles[0]["customer_title"] = "AI Permit-to-Collide"
    title_profiles[1]["customer_title"] = "AI Permit-to-Collide"
    try:
        validate_identity_collisions(title_collision)
    except RuntimeError as exc:
        assert "title collisions" in str(exc)
    else:
        raise AssertionError("Unallowlisted duplicate titles must fail validation")


if __name__ == "__main__":
    main()
