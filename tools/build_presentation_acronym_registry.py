#!/usr/bin/env python3
"""Build presentation registry v23: one explicit AI-P2 acronym per canonical title.

v22 gave three profiles an acronym in the AI-PT style. v23 gives every
canonical Permit-to title an acronym in one AI-P2 style, so consumers read the
acronym from the registry instead of deriving it. Acronyms remain explicit,
non-authorizing registry data and are globally unique.

Rules, applied to the v22 bytes:

* ``AI Permit-to-<Words>`` becomes ``AI-P2`` plus the initial of each word.
* When two different titles would share an acronym, the title named in
  ``CLASH_OVERRIDES`` takes the first two letters of its verb instead.
* A title shared by compatible semantic aliases (``TITLE_ALIAS_ALLOWLIST``)
  gets its acronym on exactly one profile, named in ``ALIAS_ACRONYM_OWNER``.
  Acronyms have no aliases.
* Titles outside the ``AI Permit-to-`` pattern carry no acronym.

Titles, definitions, leading fields, evidence sections and fallbacks are
unchanged. v22 stays byte-identical.
"""

from __future__ import annotations

import copy
import re

from build_presentation_identity_registry import (
    TITLE_ALIAS_ALLOWLIST,
    validate_identity_collisions,
)
from build_transactional_cx_registries import load, sha256, write

SOURCE = "presentation_registry/v22.json"
TARGET = "presentation_registry/v23.json"
TARGET_SCHEMA = "presentation_registry/v23.schema.json"
VERSION = "keel.presentation_registry.v23"
ACRONYM_PATTERN = r"^AI-P2[A-Z]{1,4}$"

TITLE_PATTERN = re.compile(r"^AI Permit-to-(.+)$")

# The other title of each pair keeps its plain initials.
CLASH_OVERRIDES = {
    "AI Permit-to-Reconcile-Payment": "AI-P2REP",  # Refund-Payment keeps AI-P2RP
    "AI Permit-to-Purchase-Item": "AI-P2PUI",  # Pay-Invoice keeps AI-P2PI
    "AI Permit-to-Deploy-Commit": "AI-P2DEC",  # Decide-Claim keeps AI-P2DC
    "AI Permit-to-Restart-Machine": "AI-P2REM",  # Reset-MFA keeps AI-P2RM
    "AI Permit-to-Publish-Content": "AI-P2PUC",  # Pay-Claim keeps AI-P2PC
    "AI Permit-to-Send-Agreement": "AI-P2SEA",  # Schedule-Appointment keeps AI-P2SA
    "AI Permit-to-Stop-Machine": "AI-P2STM",  # Send-Message keeps AI-P2SM
}

# The current profile of each shared title carries the acronym; the
# historical or variant alias keeps the title only.
ALIAS_ACRONYM_OWNER = {
    "AI Permit-to-Refund-Payment": "payment_refund_execute.r1",
    "AI Permit-to-Create-Calendar-Event": "calendar_event_create.r1",
}


def derived_acronym(title: str) -> str | None:
    match = TITLE_PATTERN.match(title)
    if not match:
        return None
    words = [word for word in re.split(r"[-\s]+", match.group(1)) if word]
    return "AI-P2" + "".join(word[0].upper() for word in words)


def acronym_for(profile: dict) -> str | None:
    title = profile["customer_title"]
    owner = ALIAS_ACRONYM_OWNER.get(title)
    if owner is not None and profile["presentation_profile_id"] != owner:
        return None
    return CLASH_OVERRIDES.get(title) or derived_acronym(title)


def validate_v23_acronyms(registry: dict) -> None:
    """Pattern, completeness and alias-owner checks on top of collisions."""

    validate_identity_collisions(registry)
    pattern = re.compile(ACRONYM_PATTERN)
    if set(ALIAS_ACRONYM_OWNER) != set(TITLE_ALIAS_ALLOWLIST):
        raise RuntimeError("Every allowlisted shared title needs exactly one acronym owner")
    for profile in registry["profiles"]:
        profile_id = profile["presentation_profile_id"]
        acronym = profile.get("acronym")
        expected = acronym_for(profile)
        if acronym != expected:
            raise RuntimeError(f"{profile_id}: acronym {acronym!r} does not follow the v23 rule ({expected!r})")
        if acronym is not None and not pattern.match(acronym):
            raise RuntimeError(f"{profile_id}: acronym {acronym!r} does not match {ACRONYM_PATTERN}")
    for title, owner in ALIAS_ACRONYM_OWNER.items():
        owners = [
            profile["presentation_profile_id"]
            for profile in registry["profiles"]
            if profile["customer_title"] == title and profile.get("acronym")
        ]
        if owners != [owner]:
            raise RuntimeError(f"{title}: acronym owners {owners} != [{owner}]")
    unused = set(CLASH_OVERRIDES) - {profile["customer_title"] for profile in registry["profiles"]}
    if unused:
        raise RuntimeError(f"Clash overrides name unknown titles: {sorted(unused)}")


def main() -> None:
    registry = copy.deepcopy(load(SOURCE))
    registry["$schema"] = "./v23.schema.json"
    registry["version"] = VERSION

    for profile in registry["profiles"]:
        # Same key position as v22: the acronym is the last profile key.
        profile.pop("acronym", None)
        acronym = acronym_for(profile)
        if acronym is not None:
            profile["acronym"] = acronym

    validate_v23_acronyms(registry)
    write(TARGET, registry)

    schema = copy.deepcopy(load("presentation_registry/v22.schema.json"))
    schema["$id"] = "https://github.com/keelapi/keel-permit/presentation_registry/v23.schema.json"
    schema["title"] = "Keel Permit presentation registry v23"
    schema["properties"]["version"]["const"] = VERSION
    schema["$defs"]["profile"]["properties"]["acronym"] = {
        "type": "string",
        "pattern": ACRONYM_PATTERN,
    }
    write(TARGET_SCHEMA, schema)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.presentation_registry.v23", TARGET),
        ("keel.permit.presentation_registry.v23.schema", TARGET_SCHEMA),
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
