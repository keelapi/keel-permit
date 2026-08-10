#!/usr/bin/env python3
"""Build additive semantic and presentation registries from consequences."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write(path: str, value: dict) -> None:
    destination = ROOT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def semantic_entry(consequence: dict) -> dict:
    return {
        "semantic_id": consequence["semantic_id"],
        "semantic_kind": "exact_action",
        "trusted_source_kinds": ["action_verb_execute"],
        "match": {
            "action_names": consequence["tool_names"],
            "operations": ["call.tools"],
            "allowed_chain_roles": ["session_root", "action_child"],
            "required_evidence_capabilities": [
                "authorization",
                "dispatch",
                "provider_outcome",
            ],
        },
        "excluded_permit_products": ["cost_permit"],
        "release_state": "eligible",
    }


def presentation_profile(consequence: dict) -> dict:
    return {
        "semantic_id": consequence["semantic_id"],
        "presentation_profile_id": (
            consequence["consequence_type"].removesuffix(".v1").replace(".", "_")
            + ".r1"
        ),
        "customer_title": consequence["customer_title"],
        "type_definition": consequence["type_definition"],
        "leading_fields": consequence["leading_fields"],
        "evidence_sections": consequence["evidence_sections"],
        "does_not_establish": consequence["does_not_establish"],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    }


def main() -> None:
    consequence_registry = load("consequence_registry/v1.json")
    semantic = copy.deepcopy(load("semantic_registry/v4.json"))
    semantic["$schema"] = "./v5.schema.json"
    semantic["version"] = "keel.semantic_selector_registry.v5"
    semantic["entries"].extend(
        semantic_entry(item) for item in consequence_registry["consequences"]
    )
    write("semantic_registry/v5.json", semantic)

    semantic_schema = copy.deepcopy(load("semantic_registry/v4.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v5.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v5"
    semantic_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v5"
    )
    write("semantic_registry/v5.schema.json", semantic_schema)

    presentation = copy.deepcopy(load("presentation_registry/v3.json"))
    presentation["$schema"] = "./v4.schema.json"
    presentation["version"] = "keel.presentation_registry.v4"
    presentation["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v5"
    )
    presentation["profiles"].extend(
        presentation_profile(item)
        for item in consequence_registry["consequences"]
    )
    write("presentation_registry/v4.json", presentation)

    presentation_schema = copy.deepcopy(load("presentation_registry/v3.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v4.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v4"
    presentation_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v4"
    )
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v5"
    )
    write("presentation_registry/v4.schema.json", presentation_schema)

    consequence_vectors = {
        "version": "keel.consequence_registry.test_vectors.v1",
        "consequence_registry_version": consequence_registry["version"],
        "semantic_registry_version": semantic["version"],
        "presentation_registry_version": presentation["version"],
        "vectors": [
            {
                "id": item["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": item["tool_names"][0],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "expected_semantic_id": item["semantic_id"],
                "expected_title": item["customer_title"],
            }
            for item in consequence_registry["consequences"]
        ],
    }
    write("consequence_registry/test-vectors/v1.json", consequence_vectors)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v1", "consequence_registry/v1.json"),
        (
            "keel.permit.consequence_registry.v1.schema",
            "consequence_registry/v1.schema.json",
        ),
        (
            "keel.permit.consequence_registry.v1.spec",
            "spec/consequence-registry-v1.md",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v1",
            "consequence_registry/test-vectors/v1.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v5",
            "semantic_registry/v5.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v5.schema",
            "semantic_registry/v5.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v4",
            "presentation_registry/v4.json",
        ),
        (
            "keel.permit.presentation_registry.v4.schema",
            "presentation_registry/v4.schema.json",
        ),
    ]
    existing_by_path = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        if path in existing_by_path:
            existing_by_path[path]["id"] = artifact_id
            existing_by_path[path]["sha256"] = sha256(path)
            continue
        manifest["artifacts"].append(
            {"id": artifact_id, "path": path, "sha256": sha256(path)}
        )
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
