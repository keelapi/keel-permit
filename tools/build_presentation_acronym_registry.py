#!/usr/bin/env python3
"""Build presentation registries v23 and v24: one explicit acronym per canonical title.

v22 gave three profiles an acronym in the AI-PT style. v23 gave every
canonical Permit-to title an acronym in an AI-P2 style. v24 keeps v23's rule
and returns to the AI-PT prefix: it matches the established Permit-to-Work
(PTW) convention, avoids reading Permit-to-Pay as "P2P" (peer-to-peer,
procure-to-pay), and keeps the three acronyms v22 published unchanged.
Consumers read the acronym from the registry instead of deriving it.
Acronyms remain explicit, non-authorizing registry data and are globally
unique.

Rules, applied to the previous registry's bytes (v22 for v23, v23 for v24):

* ``AI Permit-to-<Words>`` becomes the prefix plus the initial of each word.
* When two different titles would share an acronym, the title named in
  ``CLASH_SUFFIXES`` takes the first two letters of its verb instead.
* A title shared by compatible semantic aliases (``TITLE_ALIAS_ALLOWLIST``)
  gets its acronym on exactly one profile, named in ``ALIAS_ACRONYM_OWNER``.
  Acronyms have no aliases.
* Titles outside the ``AI Permit-to-`` pattern carry no acronym.

Titles, definitions, leading fields, evidence sections and fallbacks are
unchanged. Earlier registries stay byte-identical.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass

from build_presentation_identity_registry import (
    TITLE_ALIAS_ALLOWLIST,
    validate_identity_collisions,
)
from build_transactional_cx_registries import load, sha256, write


@dataclass(frozen=True)
class AcronymRegistry:
    number: int
    prefix: str
    source: str

    @property
    def target(self) -> str:
        return f"presentation_registry/v{self.number}.json"

    @property
    def target_schema(self) -> str:
        return f"presentation_registry/v{self.number}.schema.json"

    @property
    def source_schema(self) -> str:
        return self.source.replace(".json", ".schema.json")

    @property
    def version(self) -> str:
        return f"keel.presentation_registry.v{self.number}"

    @property
    def pattern(self) -> str:
        return rf"^{self.prefix}[A-Z]{{1,4}}$"


V23 = AcronymRegistry(number=23, prefix="AI-P2", source="presentation_registry/v22.json")
V24 = AcronymRegistry(number=24, prefix="AI-PT", source="presentation_registry/v23.json")
REGISTRIES = (V23, V24)

# Kept for consumers of the v23 module surface.
ACRONYM_PATTERN = V23.pattern

TITLE_PATTERN = re.compile(r"^AI Permit-to-(.+)$")

# The other title of each pair keeps its plain initials (shown in v24 form).
CLASH_SUFFIXES = {
    "AI Permit-to-Reconcile-Payment": "REP",  # Refund-Payment keeps AI-PTRP
    "AI Permit-to-Purchase-Item": "PUI",  # Pay-Invoice keeps AI-PTPI
    "AI Permit-to-Deploy-Commit": "DEC",  # Decide-Claim keeps AI-PTDC
    "AI Permit-to-Restart-Machine": "REM",  # Reset-MFA keeps AI-PTRM
    "AI Permit-to-Publish-Content": "PUC",  # Pay-Claim keeps AI-PTPC
    "AI Permit-to-Send-Agreement": "SEA",  # Schedule-Appointment keeps AI-PTSA
    "AI Permit-to-Stop-Machine": "STM",  # Send-Message keeps AI-PTSM
}

# The current profile of each shared title carries the acronym; the
# historical or variant alias keeps the title only.
ALIAS_ACRONYM_OWNER = {
    "AI Permit-to-Refund-Payment": "payment_refund_execute.r1",
    "AI Permit-to-Create-Calendar-Event": "calendar_event_create.r1",
}


def derived_acronym(title: str, prefix: str = V23.prefix) -> str | None:
    match = TITLE_PATTERN.match(title)
    if not match:
        return None
    words = [word for word in re.split(r"[-\s]+", match.group(1)) if word]
    return prefix + "".join(word[0].upper() for word in words)


def acronym_for(profile: dict, prefix: str = V23.prefix) -> str | None:
    title = profile["customer_title"]
    owner = ALIAS_ACRONYM_OWNER.get(title)
    if owner is not None and profile["presentation_profile_id"] != owner:
        return None
    suffix = CLASH_SUFFIXES.get(title)
    return prefix + suffix if suffix else derived_acronym(title, prefix)


def validate_acronyms(registry: dict, spec: AcronymRegistry) -> None:
    """Pattern, completeness and alias-owner checks on top of collisions."""

    validate_identity_collisions(registry)
    if registry.get("version") != spec.version:
        raise RuntimeError(f"registry version {registry.get('version')!r} != {spec.version!r}")
    pattern = re.compile(spec.pattern)
    if set(ALIAS_ACRONYM_OWNER) != set(TITLE_ALIAS_ALLOWLIST):
        raise RuntimeError("Every allowlisted shared title needs exactly one acronym owner")
    for profile in registry["profiles"]:
        profile_id = profile["presentation_profile_id"]
        acronym = profile.get("acronym")
        expected = acronym_for(profile, spec.prefix)
        if acronym != expected:
            raise RuntimeError(
                f"{profile_id}: acronym {acronym!r} does not follow the v{spec.number} rule ({expected!r})"
            )
        if acronym is not None and not pattern.match(acronym):
            raise RuntimeError(f"{profile_id}: acronym {acronym!r} does not match {spec.pattern}")
    for title, owner in ALIAS_ACRONYM_OWNER.items():
        owners = [
            profile["presentation_profile_id"]
            for profile in registry["profiles"]
            if profile["customer_title"] == title and profile.get("acronym")
        ]
        if owners != [owner]:
            raise RuntimeError(f"{title}: acronym owners {owners} != [{owner}]")
    unused = set(CLASH_SUFFIXES) - {profile["customer_title"] for profile in registry["profiles"]}
    if unused:
        raise RuntimeError(f"Clash overrides name unknown titles: {sorted(unused)}")


def validate_v23_acronyms(registry: dict) -> None:
    validate_acronyms(registry, V23)


def validate_v24_acronyms(registry: dict) -> None:
    validate_acronyms(registry, V24)


def build(spec: AcronymRegistry) -> None:
    registry = copy.deepcopy(load(spec.source))
    registry["$schema"] = f"./v{spec.number}.schema.json"
    registry["version"] = spec.version

    for profile in registry["profiles"]:
        # Same key position as v22: the acronym is the last profile key.
        profile.pop("acronym", None)
        acronym = acronym_for(profile, spec.prefix)
        if acronym is not None:
            profile["acronym"] = acronym

    validate_acronyms(registry, spec)
    write(spec.target, registry)

    schema = copy.deepcopy(load(spec.source_schema))
    schema["$id"] = f"https://github.com/keelapi/keel-permit/presentation_registry/v{spec.number}.schema.json"
    schema["title"] = f"Keel Permit presentation registry v{spec.number}"
    schema["properties"]["version"]["const"] = spec.version
    schema["$defs"]["profile"]["properties"]["acronym"] = {
        "type": "string",
        "pattern": spec.pattern,
    }
    write(spec.target_schema, schema)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        (f"keel.permit.presentation_registry.v{spec.number}", spec.target),
        (f"keel.permit.presentation_registry.v{spec.number}.schema", spec.target_schema),
    ]
    existing = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        value = {"id": artifact_id, "path": path, "sha256": sha256(path)}
        if path in existing:
            existing[path].update(value)
        else:
            manifest["artifacts"].append(value)
    write(manifest_path, manifest)


def main() -> None:
    # v23 is rebuilt to prove its published bytes are reproducible; it must
    # come out unchanged.
    for spec in REGISTRIES:
        build(spec)


if __name__ == "__main__":
    main()
