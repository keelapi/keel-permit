#!/usr/bin/env python3
"""Build additive exact-action artifacts for the Coding Workspace habitat."""

from __future__ import annotations

import copy
from typing import Any

from build_transactional_cx_registries import commitment, load, sha256, write

FACT_SCHEMA = "schemas/coding-workspace-exact-facts-v1.schema.json"

COMMON_FACT_PATHS = [
    "/connector_identity",
    "/connector_contract_hash",
    "/tool_schema_hash",
    "/decision_trace_hash",
    "/tool_arguments_hash",
    "/request_digest",
    "/provider_environment",
    "/provider_api_version",
    "/preflight_observed_at",
    "/preflight_expires_at",
    "/preflight_snapshot_digest",
    "/idempotency_digest",
    "/max_uses",
]


ACTION_DEFS: list[dict[str, Any]] = [
    {
        "consequence_type": "code.package.install.v1",
        "semantic_id": "keel.action.code_package_install.v1",
        "action": "code.package.install",
        "connector_identity": "npm",
        "customer_title": "AI Permit-to-Install-Package",
        "type_definition": (
            "Exact authorization to install one allowlisted public package at one "
            "exact version with lifecycle scripts disabled in one disposable workspace"
        ),
        "provider_mapping": {
            "provider": "npm",
            "operation": "packages.install.exact_without_scripts",
        },
        "specific_paths": [
            "/workspace_reference_commitment",
            "/workspace_is_disposable",
            "/workspace_state_digest",
            "/package_reference_commitment",
            "/package_name",
            "/package_allowlisted",
            "/package_metadata_digest",
            "/package_tarball_integrity",
            "/registry_origin",
            "/dependency_class",
            "/current_dependency_version",
            "/target_dependency_version",
            "/package_manifest_state_digest",
            "/package_lock_present",
            "/package_lock_state_digest",
            "/install_mode",
            "/lifecycle_scripts_disabled",
            "/install_command_digest",
        ],
        "target_paths": [
            "/workspace_reference_commitment",
            "/package_reference_commitment",
        ],
        "material_paths": [
            "/workspace_is_disposable",
            "/workspace_state_digest",
            "/package_name",
            "/package_allowlisted",
            "/package_metadata_digest",
            "/package_tarball_integrity",
            "/registry_origin",
            "/dependency_class",
            "/current_dependency_version",
            "/target_dependency_version",
            "/package_manifest_state_digest",
            "/package_lock_present",
            "/package_lock_state_digest",
            "/install_mode",
            "/lifecycle_scripts_disabled",
            "/install_command_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_workspace_allowlist",
            "gateway_package_version_allowlist",
            "provider_package_metadata_preflight",
            "provider_tarball_integrity_preflight",
            "gateway_workspace_state_preflight",
            "lifecycle_script_suppression",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.code.package.install.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Disposable workspace"},
            {"field": "target_digest", "label": "Exact package and version"},
            {"field": "provider", "label": "Package registry"},
            {"field": "effective_at", "label": "Authorized at"},
        ],
        "does_not_establish": [
            "package_safety_maintainer_identity_or_absence_of_malicious_content",
            "successful_application_build_tests_or_runtime_behavior",
            "changes_outside_the_named_disposable_workspace",
        ],
        "risk_tags": ["source_change", "software_supply_chain", "local_execution"],
    },
    {
        "consequence_type": "repository.branch.push.v1",
        "semantic_id": "keel.action.repository_branch_push.v1",
        "action": "repository.branch.push",
        "connector_identity": "github",
        "customer_title": "AI Permit-to-Push-Branch",
        "type_definition": (
            "Exact authorization to publish one bounded gateway-derived workspace tree "
            "as one new commit on one absent non-protected GitHub branch"
        ),
        "provider_mapping": {
            "provider": "github",
            "operation": "git.refs.create_with_exact_commit",
        },
        "specific_paths": [
            "/repository_reference_commitment",
            "/workspace_reference_commitment",
            "/workspace_state_digest",
            "/base_branch",
            "/base_commit_sha",
            "/base_tree_sha",
            "/base_branch_protected",
            "/target_branch",
            "/target_branch_exists",
            "/target_branch_protected",
            "/target_tree_digest",
            "/changed_paths_digest",
            "/workspace_file_count",
            "/workspace_total_bytes",
            "/protected_path_change_count",
            "/commit_message_commitment",
            "/push_mode",
            "/force_push",
        ],
        "target_paths": [
            "/repository_reference_commitment",
            "/target_branch",
            "/target_tree_digest",
        ],
        "material_paths": [
            "/workspace_reference_commitment",
            "/workspace_state_digest",
            "/base_branch",
            "/base_commit_sha",
            "/base_tree_sha",
            "/base_branch_protected",
            "/target_branch_exists",
            "/target_branch_protected",
            "/changed_paths_digest",
            "/workspace_file_count",
            "/workspace_total_bytes",
            "/protected_path_change_count",
            "/commit_message_commitment",
            "/push_mode",
            "/force_push",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_repository_allowlist",
            "gateway_workspace_state_preflight",
            "provider_base_ref_preflight",
            "provider_target_ref_absence_preflight",
            "provider_branch_protection_preflight",
            "deterministic_workspace_tree_derivation",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.repository.branch.push.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Repository and target branch"},
            {"field": "target_digest", "label": "Exact workspace tree"},
            {"field": "provider", "label": "Source provider"},
            {"field": "effective_at", "label": "Authorized at"},
        ],
        "does_not_establish": [
            "github_acceptance_or_visible_branch_without_provider_readback",
            "code_correctness_review_approval_or_passing_checks",
            "pull_request_merge_deployment_or_runtime_behavior",
        ],
        "risk_tags": ["source_change", "remote_branch", "software_supply_chain"],
    },
    {
        "consequence_type": "repository.pull_request.create.v1",
        "semantic_id": "keel.action.repository_pull_request_create.v1",
        "action": "repository.pull_request.create",
        "connector_identity": "github",
        "customer_title": "AI Permit-to-Create-Pull-Request",
        "type_definition": (
            "Exact authorization to open one pull request from one provider-observed "
            "head commit into one provider-observed protected base branch"
        ),
        "provider_mapping": {"provider": "github", "operation": "pulls.create"},
        "specific_paths": [
            "/repository_reference_commitment",
            "/head_branch",
            "/head_commit_sha",
            "/head_ref_exists",
            "/base_branch",
            "/base_commit_sha",
            "/base_branch_protected",
            "/same_repository",
            "/compare_state_digest",
            "/compare_status",
            "/ahead_by",
            "/behind_by",
            "/changed_files_count",
            "/additions_count",
            "/deletions_count",
            "/changed_paths_digest",
            "/protected_path_change_count",
            "/existing_open_pull_request_count",
            "/pull_request_title_commitment",
            "/pull_request_body_commitment",
            "/draft",
            "/merge_authorized",
        ],
        "target_paths": [
            "/repository_reference_commitment",
            "/head_commit_sha",
            "/base_commit_sha",
        ],
        "material_paths": [
            "/head_branch",
            "/head_ref_exists",
            "/base_branch",
            "/base_branch_protected",
            "/same_repository",
            "/compare_state_digest",
            "/compare_status",
            "/ahead_by",
            "/behind_by",
            "/changed_files_count",
            "/additions_count",
            "/deletions_count",
            "/changed_paths_digest",
            "/protected_path_change_count",
            "/existing_open_pull_request_count",
            "/pull_request_title_commitment",
            "/pull_request_body_commitment",
            "/draft",
            "/merge_authorized",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "gateway_repository_allowlist",
            "provider_head_and_base_ref_preflight",
            "provider_base_branch_protection_preflight",
            "provider_compare_preflight",
            "provider_existing_pull_request_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.repository.pull_request.create.canonical.v1",
        "leading_fields": [
            {"field": "resource", "label": "Repository, head, and base"},
            {"field": "request_digest", "label": "Exact pull request"},
            {"field": "provider", "label": "Source provider"},
            {"field": "effective_at", "label": "Authorized at"},
        ],
        "does_not_establish": [
            "github_acceptance_or_open_pull_request_without_provider_readback",
            "review_approval_passing_checks_or_mergeability",
            "merge_deployment_code_correctness_or_runtime_behavior",
        ],
        "risk_tags": ["source_change", "pull_request", "external_communication"],
    },
]

INTEGER_FIELDS = {
    "workspace_file_count",
    "workspace_total_bytes",
    "protected_path_change_count",
    "ahead_by",
    "behind_by",
    "changed_files_count",
    "additions_count",
    "deletions_count",
    "existing_open_pull_request_count",
    "max_uses",
}
BOOLEAN_FIELDS = {
    "workspace_is_disposable",
    "package_allowlisted",
    "package_lock_present",
    "lifecycle_scripts_disabled",
    "base_branch_protected",
    "target_branch_exists",
    "target_branch_protected",
    "force_push",
    "head_ref_exists",
    "same_repository",
    "draft",
    "merge_authorized",
}
TIMESTAMP_FIELDS = {"preflight_observed_at", "preflight_expires_at"}


def fact_profile_id(action_def: dict[str, Any]) -> str:
    return "keel.facts." + action_def["action"].replace(".", "_") + "_exact.v1"


def semantic_entry(action_def: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_id": action_def["semantic_id"],
        "semantic_kind": "exact_action",
        "trusted_source_kinds": ["action_verb_execute"],
        "match": {
            "action_names": [action_def["action"]],
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
        "fact_profile_id": fact_profile_id(action_def),
    }


def presentation_profile(action_def: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_id": action_def["semantic_id"],
        "presentation_profile_id": (
            action_def["consequence_type"].rsplit(".v", 1)[0].replace(".", "_") + ".r1"
        ),
        "customer_title": action_def["customer_title"],
        "type_definition": action_def["type_definition"],
        "leading_fields": action_def["leading_fields"],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "evidence_scope",
        ],
        "does_not_establish": action_def["does_not_establish"],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    }


def fact_field(path: str) -> dict[str, Any]:
    name = path.removeprefix("/")
    is_commitment = name.endswith("_commitment")
    is_digest = name.endswith("_digest") or name.endswith("_hash")
    value_type = (
        "commitment"
        if is_commitment
        else "digest"
        if is_digest
        else "integer"
        if name in INTEGER_FIELDS
        else "boolean"
        if name in BOOLEAN_FIELDS
        else "timestamp"
        if name in TIMESTAMP_FIELDS
        else "string"
    )
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": "sensitive_data" if is_commitment else "operational",
        "low_entropy_possible": not is_digest,
        "disclosure": {
            "verifier_safe": "commitment" if is_commitment else "cleartext",
            "authorized": (
                "commitment_with_optional_opening" if is_commitment else "cleartext"
            ),
            "private": (
                "commitment_with_optional_opening" if is_commitment else "cleartext"
            ),
        },
        "retention": {
            "class": "deletable_identity" if is_commitment else "permit_evidence",
            "max_days": None,
            "erasable": is_commitment,
            "erasure_action": (
                "erase_opening" if is_commitment else "retain_signed_value"
            ),
        },
        "commitment_method": (
            "keel.salted_sha256_jcs.v1" if is_commitment else "signed_cleartext"
        ),
    }


def fact_profile(action_def: dict[str, Any], schema_digest: str) -> dict[str, Any]:
    paths = list(dict.fromkeys([*COMMON_FACT_PATHS, *action_def["specific_paths"]]))
    return {
        "fact_profile_id": fact_profile_id(action_def),
        "semantic_ids": [action_def["semantic_id"]],
        "authorized_action": action_def["action"],
        "facts_schema": FACT_SCHEMA,
        "facts_schema_digest": f"sha256:{schema_digest}",
        "target_fact_paths": action_def["target_paths"],
        "material_request_fact_paths": [
            *action_def["material_paths"],
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "fields": [fact_field(path) for path in paths],
        "release_state": "eligible",
    }


def consequence(action_def: dict[str, Any]) -> dict[str, Any]:
    fields = list(
        dict.fromkeys(
            path.removeprefix("/")
            for path in [*action_def["target_paths"], *action_def["material_paths"]]
        )
    )
    return {
        "consequence_type": action_def["consequence_type"],
        "semantic_id": action_def["semantic_id"],
        "tool_names": [action_def["action"]],
        "customer_title": action_def["customer_title"],
        "type_definition": action_def["type_definition"],
        "required_material_fields": fields,
        "trusted_fact_requirements": action_def["trusted_facts"],
        "canonicalizer": action_def["canonicalizer"],
        "provider_mappings": [action_def["provider_mapping"]],
        "leading_fields": action_def["leading_fields"],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "evidence_scope",
        ],
        "does_not_establish": action_def["does_not_establish"],
        "risk_tags": action_def["risk_tags"],
    }


def common_schema() -> dict[str, Any]:
    digest = {"$ref": "#/$defs/digest"}
    raw_digest = {"$ref": "#/$defs/rawDigest"}
    timestamp = {"$ref": "#/$defs/timestamp"}
    return {
        "version": {"const": "keel.coding_workspace_exact_facts.v1"},
        "fact_profile_id": {"type": "string"},
        "action": {"type": "string"},
        "operation": {"const": "call.tools"},
        "connector_identity": {"enum": ["npm", "github"]},
        "connector_contract_hash": raw_digest,
        "tool_schema_hash": raw_digest,
        "decision_trace_hash": raw_digest,
        "tool_arguments_hash": raw_digest,
        "request_digest": digest,
        "enforcement_mode": {"const": "enforced_in_path"},
        "provider_environment": {"const": "dedicated_demo"},
        "provider_api_version": {"type": "string", "minLength": 1, "maxLength": 128},
        "preflight_observed_at": timestamp,
        "preflight_expires_at": timestamp,
        "preflight_snapshot_digest": digest,
        "idempotency_digest": digest,
        "max_uses": {"const": 1},
    }


def action_schema(action_def: dict[str, Any]) -> dict[str, Any]:
    digest = {"$ref": "#/$defs/digest"}
    commitment_schema = {"$ref": "#/$defs/saltedCommitment"}
    git_sha = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    branch = {"type": "string", "pattern": "^[A-Za-z0-9._/-]{1,255}$"}
    properties: dict[str, Any] = {
        "fact_profile_id": {"const": fact_profile_id(action_def)},
        "action": {"const": action_def["action"]},
        "connector_identity": {"const": action_def["connector_identity"]},
    }
    action = action_def["action"]
    if action == "code.package.install":
        properties.update(
            {
                "workspace_reference_commitment": commitment_schema,
                "workspace_is_disposable": {"const": True},
                "workspace_state_digest": digest,
                "package_reference_commitment": commitment_schema,
                "package_name": {"type": "string", "minLength": 1, "maxLength": 214},
                "package_allowlisted": {"const": True},
                "package_metadata_digest": digest,
                "package_tarball_integrity": {
                    "type": "string",
                    "pattern": "^sha512-[A-Za-z0-9+/]+={0,2}$",
                },
                "registry_origin": {"const": "https://registry.npmjs.org"},
                "dependency_class": {"enum": ["runtime", "development"]},
                "current_dependency_version": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "target_dependency_version": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "package_manifest_state_digest": digest,
                "package_lock_present": {"type": "boolean"},
                "package_lock_state_digest": digest,
                "install_mode": {"const": "save_exact"},
                "lifecycle_scripts_disabled": {"const": True},
                "install_command_digest": digest,
            }
        )
    elif action == "repository.branch.push":
        properties.update(
            {
                "repository_reference_commitment": commitment_schema,
                "workspace_reference_commitment": commitment_schema,
                "workspace_state_digest": digest,
                "base_branch": branch,
                "base_commit_sha": git_sha,
                "base_tree_sha": git_sha,
                "base_branch_protected": {"const": True},
                "target_branch": branch,
                "target_branch_exists": {"const": False},
                "target_branch_protected": {"const": False},
                "target_tree_digest": digest,
                "changed_paths_digest": digest,
                "workspace_file_count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 32,
                },
                "workspace_total_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1048576,
                },
                "protected_path_change_count": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 32,
                },
                "commit_message_commitment": commitment_schema,
                "push_mode": {"const": "create_ref_only"},
                "force_push": {"const": False},
            }
        )
    else:
        properties.update(
            {
                "repository_reference_commitment": commitment_schema,
                "head_branch": branch,
                "head_commit_sha": git_sha,
                "head_ref_exists": {"const": True},
                "base_branch": branch,
                "base_commit_sha": git_sha,
                "base_branch_protected": {"const": True},
                "same_repository": {"const": True},
                "compare_state_digest": digest,
                "compare_status": {"const": "ahead"},
                "ahead_by": {"type": "integer", "minimum": 1, "maximum": 100},
                "behind_by": {"type": "integer", "minimum": 0, "maximum": 100},
                "changed_files_count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
                "additions_count": {"type": "integer", "minimum": 0, "maximum": 100000},
                "deletions_count": {"type": "integer", "minimum": 0, "maximum": 100000},
                "changed_paths_digest": digest,
                "protected_path_change_count": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                },
                "existing_open_pull_request_count": {"const": 0},
                "pull_request_title_commitment": commitment_schema,
                "pull_request_body_commitment": commitment_schema,
                "draft": {"type": "boolean"},
                "merge_authorized": {"const": False},
            }
        )
    return properties


def build_schema() -> dict[str, Any]:
    common = common_schema()
    definitions: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    for action_def in ACTION_DEFS:
        name = action_def["action"].replace(".", "_")
        properties = copy.deepcopy(common)
        properties.update(copy.deepcopy(action_schema(action_def)))
        definitions[name] = {
            "type": "object",
            "additionalProperties": False,
            "required": list(properties),
            "properties": properties,
        }
        refs.append({"$ref": f"#/$defs/{name}"})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/keelapi/keel-permit/schemas/"
            "coding-workspace-exact-facts-v1.schema.json"
        ),
        "title": "Keel exact Coding Workspace authorization facts v1",
        "oneOf": refs,
        "$defs": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "rawDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "pattern": (
                    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
                    "[0-9]{2}(?:\\.[0-9]{1,9})?Z$"
                ),
            },
            "saltedCommitment": {
                "type": "object",
                "additionalProperties": False,
                "required": ["method", "digest"],
                "properties": {
                    "method": {"const": "keel.salted_sha256_jcs.v1"},
                    "digest": {"$ref": "#/$defs/digest"},
                },
            },
            **definitions,
        },
    }


def fact_vector(action_def: dict[str, Any]) -> dict[str, Any]:
    action = action_def["action"]
    common: dict[str, Any] = {
        "version": "keel.coding_workspace_exact_facts.v1",
        "fact_profile_id": fact_profile_id(action_def),
        "action": action,
        "operation": "call.tools",
        "connector_identity": action_def["connector_identity"],
        "connector_contract_hash": "0" * 64,
        "tool_schema_hash": "1" * 64,
        "decision_trace_hash": "2" * 64,
        "tool_arguments_hash": "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "enforcement_mode": "enforced_in_path",
        "provider_environment": "dedicated_demo",
        "provider_api_version": (
            "npm-registry-v1"
            if action_def["connector_identity"] == "npm"
            else "2022-11-28"
        ),
        "preflight_observed_at": "2026-08-10T12:00:00Z",
        "preflight_expires_at": "2026-08-10T12:05:00Z",
        "preflight_snapshot_digest": "sha256:" + "5" * 64,
        "idempotency_digest": "sha256:" + "6" * 64,
        "max_uses": 1,
    }
    specifics: dict[str, dict[str, Any]] = {
        "code.package.install": {
            "workspace_reference_commitment": commitment("7"),
            "workspace_is_disposable": True,
            "workspace_state_digest": "sha256:" + "8" * 64,
            "package_reference_commitment": commitment("9"),
            "package_name": "is-odd",
            "package_allowlisted": True,
            "package_metadata_digest": "sha256:" + "a" * 64,
            "package_tarball_integrity": "sha512-" + "A" * 86 + "==",
            "registry_origin": "https://registry.npmjs.org",
            "dependency_class": "runtime",
            "current_dependency_version": "absent",
            "target_dependency_version": "3.0.1",
            "package_manifest_state_digest": "sha256:" + "b" * 64,
            "package_lock_present": True,
            "package_lock_state_digest": "sha256:" + "c" * 64,
            "install_mode": "save_exact",
            "lifecycle_scripts_disabled": True,
            "install_command_digest": "sha256:" + "d" * 64,
        },
        "repository.branch.push": {
            "repository_reference_commitment": commitment("7"),
            "workspace_reference_commitment": commitment("8"),
            "workspace_state_digest": "sha256:" + "9" * 64,
            "base_branch": "main",
            "base_commit_sha": "a" * 40,
            "base_tree_sha": "b" * 40,
            "base_branch_protected": True,
            "target_branch": "keel/package-demo",
            "target_branch_exists": False,
            "target_branch_protected": False,
            "target_tree_digest": "sha256:" + "c" * 64,
            "changed_paths_digest": "sha256:" + "d" * 64,
            "workspace_file_count": 3,
            "workspace_total_bytes": 4096,
            "protected_path_change_count": 0,
            "commit_message_commitment": commitment("e"),
            "push_mode": "create_ref_only",
            "force_push": False,
        },
        "repository.pull_request.create": {
            "repository_reference_commitment": commitment("7"),
            "head_branch": "keel/package-demo",
            "head_commit_sha": "a" * 40,
            "head_ref_exists": True,
            "base_branch": "main",
            "base_commit_sha": "b" * 40,
            "base_branch_protected": True,
            "same_repository": True,
            "compare_state_digest": "sha256:" + "c" * 64,
            "compare_status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
            "changed_files_count": 2,
            "additions_count": 24,
            "deletions_count": 1,
            "changed_paths_digest": "sha256:" + "d" * 64,
            "protected_path_change_count": 0,
            "existing_open_pull_request_count": 0,
            "pull_request_title_commitment": commitment("e"),
            "pull_request_body_commitment": commitment("f"),
            "draft": False,
            "merge_authorized": False,
        },
    }
    return {**common, **specifics[action]}


def main() -> None:
    write(FACT_SCHEMA, build_schema())

    consequence_v6 = copy.deepcopy(load("consequence_registry/v5.json"))
    consequence_v6["$schema"] = "./v6.schema.json"
    consequence_v6["version"] = "keel.consequence_registry.v6"
    consequence_v6["consequences"].extend(consequence(item) for item in ACTION_DEFS)
    write("consequence_registry/v6.json", consequence_v6)

    consequence_schema = copy.deepcopy(load("consequence_registry/v5.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v6.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v6"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v6"
    )
    write("consequence_registry/v6.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v9 = copy.deepcopy(load("fact_profiles/v8.json"))
    facts_v9["$schema"] = "./v9.schema.json"
    facts_v9["version"] = "keel.fact_profile_registry.v9"
    facts_v9["profiles"].extend(
        fact_profile(item, facts_digest) for item in ACTION_DEFS
    )
    write("fact_profiles/v9.json", facts_v9)

    facts_schema = copy.deepcopy(load("fact_profiles/v8.schema.json"))
    facts_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v9.schema.json"
    )
    facts_schema["title"] = "Keel Permit fact profile registry v9"
    facts_schema["properties"]["version"]["const"] = "keel.fact_profile_registry.v9"
    write("fact_profiles/v9.schema.json", facts_schema)

    semantics_v11 = copy.deepcopy(load("semantic_registry/v10.json"))
    semantics_v11["$schema"] = "./v11.schema.json"
    semantics_v11["version"] = "keel.semantic_selector_registry.v11"
    semantics_v11["entries"].extend(semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v11.json", semantics_v11)

    semantic_schema = copy.deepcopy(load("semantic_registry/v10.schema.json"))
    semantic_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v11.schema.json"
    )
    semantic_schema["title"] = "Keel Permit semantic selector registry v11"
    semantic_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v11"
    )
    write("semantic_registry/v11.schema.json", semantic_schema)

    presentation_v10 = copy.deepcopy(load("presentation_registry/v9.json"))
    presentation_v10["$schema"] = "./v10.schema.json"
    presentation_v10["version"] = "keel.presentation_registry.v10"
    presentation_v10["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v11"
    )
    presentation_v10["profiles"].extend(
        presentation_profile(item) for item in ACTION_DEFS
    )
    write("presentation_registry/v10.json", presentation_v10)

    presentation_schema = copy.deepcopy(load("presentation_registry/v9.schema.json"))
    presentation_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v10.schema.json"
    )
    presentation_schema["title"] = "Keel Permit presentation registry v10"
    presentation_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v10"
    )
    presentation_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v11"
    )
    write("presentation_registry/v10.schema.json", presentation_schema)

    vectors_v7 = copy.deepcopy(load("consequence_registry/test-vectors/v6.json"))
    vectors_v7["version"] = "keel.consequence_registry.test_vectors.v7"
    vectors_v7["consequence_registry_version"] = consequence_v6["version"]
    vectors_v7["semantic_registry_version"] = semantics_v11["version"]
    vectors_v7["presentation_registry_version"] = presentation_v10["version"]
    for action_def in ACTION_DEFS:
        vectors_v7["vectors"].append(
            {
                "id": action_def["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": action_def["action"],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "expected_semantic_id": action_def["semantic_id"],
                "expected_title": action_def["customer_title"],
                "expected_fact_profile_id": fact_profile_id(action_def),
                "valid_authorization_facts": fact_vector(action_def),
            }
        )
    write("consequence_registry/test-vectors/v7.json", vectors_v7)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v6", "consequence_registry/v6.json"),
        (
            "keel.permit.consequence_registry.v6.schema",
            "consequence_registry/v6.schema.json",
        ),
        ("keel.permit.coding_workspace_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v9", "fact_profiles/v9.json"),
        (
            "keel.permit.fact_profile_registry.v9.schema",
            "fact_profiles/v9.schema.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v11",
            "semantic_registry/v11.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v11.schema",
            "semantic_registry/v11.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v10",
            "presentation_registry/v10.json",
        ),
        (
            "keel.permit.presentation_registry.v10.schema",
            "presentation_registry/v10.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v7",
            "consequence_registry/test-vectors/v7.json",
        ),
        (
            "keel.permit.coding_workspace_exact_action_contract.v1.spec",
            "spec/coding-workspace-exact-action-contract-v1.md",
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
