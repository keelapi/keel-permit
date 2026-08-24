#!/usr/bin/env python3
"""Build the additive canonical Permit presentation identity contract.

Presentation identity is deliberately non-authorizing. Acronyms are explicit
registry data and are never derived from action names by a consumer.
"""

from __future__ import annotations

import copy

from build_transactional_cx_registries import load, sha256, write

IDENTITIES = {
    "permit_to_work.r1": ("AI-PTW", "AI Permit-to-Work"),
    "permit_to_pay.r1": ("AI-PTP", "AI Permit-to-Pay"),
    "stripe_connect_transfer_send.r1": ("AI-PTT", "AI Permit-to-Transfer"),
}

# These profiles intentionally preserve historical titles for compatible
# semantic aliases. Every duplicate title must be named here; acronyms have no
# aliases and are always globally unique.
TITLE_ALIAS_ALLOWLIST = {
    "AI Permit-to-Create-Calendar-Event": frozenset(
        {"calendar_event_create.r1", "calendar_event_create_gateway.r1"}
    ),
    "AI Permit-to-Refund-Payment": frozenset(
        {"permit_to_refund_payment.r1", "payment_refund_execute.r1"}
    ),
}


def validate_identity_collisions(registry: dict) -> None:
    by_acronym: dict[str, set[str]] = {}
    by_title: dict[str, set[str]] = {}
    for profile in registry["profiles"]:
        profile_id = profile["presentation_profile_id"]
        acronym = profile.get("acronym")
        if acronym:
            by_acronym.setdefault(acronym, set()).add(profile_id)
        title = profile.get("customer_title")
        if title:
            by_title.setdefault(title, set()).add(profile_id)

    acronym_collisions = {
        value: sorted(profile_ids)
        for value, profile_ids in by_acronym.items()
        if len(profile_ids) > 1
    }
    if acronym_collisions:
        raise RuntimeError(f"Presentation acronym collisions: {acronym_collisions}")

    title_collisions = {}
    for value, profile_ids in by_title.items():
        if len(profile_ids) < 2:
            continue
        if TITLE_ALIAS_ALLOWLIST.get(value) == frozenset(profile_ids):
            continue
        title_collisions[value] = sorted(profile_ids)
    if title_collisions:
        raise RuntimeError(f"Presentation title collisions: {title_collisions}")


def main() -> None:
    registry = copy.deepcopy(load("presentation_registry/v21.json"))
    registry["$schema"] = "./v22.schema.json"
    registry["version"] = "keel.presentation_registry.v22"

    found: set[str] = set()
    for profile in registry["profiles"]:
        identity = IDENTITIES.get(profile["presentation_profile_id"])
        if identity is None:
            continue
        profile["acronym"], profile["customer_title"] = identity
        found.add(profile["presentation_profile_id"])

    missing = sorted(set(IDENTITIES) - found)
    if missing:
        raise RuntimeError(f"Presentation profiles not found: {missing}")

    validate_identity_collisions(registry)

    write("presentation_registry/v22.json", registry)

    schema = copy.deepcopy(load("presentation_registry/v21.schema.json"))
    schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "presentation_registry/v22.schema.json"
    )
    schema["title"] = "Keel Permit presentation registry v22"
    schema["properties"]["version"]["const"] = registry["version"]
    schema["$defs"]["profile"]["properties"]["acronym"] = {
        "type": "string",
        "pattern": "^AI-PT[A-Z]{1,4}$",
    }
    write("presentation_registry/v22.schema.json", schema)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.presentation_registry.v22", "presentation_registry/v22.json"),
        (
            "keel.permit.presentation_registry.v22.schema",
            "presentation_registry/v22.schema.json",
        ),
    ]
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        value = {"id": artifact_id, "path": path, "sha256": sha256(path)}
        if path in existing:
            existing[path].update(value)
        else:
            manifest["artifacts"].append(value)
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
