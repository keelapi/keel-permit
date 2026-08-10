#!/usr/bin/env python3
"""Build the additive Merge-to-Production exact-action artifacts."""

from __future__ import annotations

import copy

from build_transactional_cx_registries import commitment, load, sha256, write


FACT_SCHEMA = "schemas/release-exact-facts-v1.schema.json"


CONSEQUENCES = [
    {
        "consequence_type": "repository.pull_request.merge.v1",
        "semantic_id": "keel.action.repository_pull_request_merge.v1",
        "tool_names": ["repository.pull_request.merge"],
        "customer_title": "AI Permit-to-Merge-Pull-Request",
        "type_definition": (
            "Exact authorization to merge one provider-verified pull-request head "
            "into one protected base branch"
        ),
        "required_material_fields": [
            "repository_reference_commitment",
            "pull_request_number",
            "head_commit_sha",
            "base_branch",
            "base_branch_tip_sha",
            "merge_method",
            "branch_protection_state_digest",
            "pull_request_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_pull_request_preflight",
            "provider_branch_protection_preflight",
            "provider_checks_and_reviews_preflight",
            "expected_head_sha",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.repository.pull_request.merge.canonical.v1",
        "provider_mappings": [
            {"provider": "github", "operation": "pulls.merge"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Repository and pull request"},
            {"field": "request_digest", "label": "Exact merge request"},
            {"field": "provider", "label": "Source provider"},
            {"field": "effective_at", "label": "Authorized at"},
        ],
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
        "does_not_establish": [
            "github_acceptance_or_successful_merge_without_provider_receipt",
            "resulting_branch_tip_or_merge_commit_after_authorization",
            "deployment_or_runtime_behavior",
        ],
        "risk_tags": ["source_change", "protected_branch", "production_release"],
    },
    {
        "consequence_type": "deployment.commit.deploy.v1",
        "semantic_id": "keel.action.deployment_commit_deploy.v1",
        "tool_names": ["deployment.commit.deploy"],
        "customer_title": "AI Permit-to-Deploy-Commit",
        "type_definition": (
            "Exact authorization to replace one production Fly Machine image with "
            "one immutable OCI image whose revision metadata names the source commit"
        ),
        "required_material_fields": [
            "source_repository_reference_commitment",
            "source_commit_sha",
            "target_image_digest",
            "artifact_revision_sha",
            "fly_app_reference_commitment",
            "fly_machine_reference_commitment",
            "current_instance_id",
            "current_config_digest",
            "target_config_digest",
            "release_record_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_source_commit_preflight",
            "immutable_artifact_digest",
            "oci_revision_to_source_commit_binding",
            "provider_machine_preflight",
            "machine_lease_and_current_version",
            "durable_prior_config_snapshot",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.deployment.commit.deploy.canonical.v1",
        "provider_mappings": [
            {"provider": "fly", "operation": "machines.update"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Production machine"},
            {"field": "target_digest", "label": "Commit and image"},
            {"field": "provider", "label": "Deployment provider"},
            {"field": "environment", "label": "Environment"},
        ],
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
        "does_not_establish": [
            "fly_acceptance_or_successful_machine_update_without_provider_receipt",
            "started_healthy_or_traffic_serving_application_without_provider_readback",
            "independent_build_provenance_beyond_the_bound_registry_metadata",
        ],
        "risk_tags": ["production_deployment", "infrastructure", "runtime_change"],
    },
    {
        "consequence_type": "deployment.rollback.v1",
        "semantic_id": "keel.action.deployment_rollback.v1",
        "tool_names": ["deployment.rollback"],
        "customer_title": "AI Permit-to-Roll-Back-Deployment",
        "type_definition": (
            "Exact authorization to replace one production Fly Machine configuration "
            "with one gateway-recorded prior release configuration"
        ),
        "required_material_fields": [
            "fly_app_reference_commitment",
            "fly_machine_reference_commitment",
            "current_release_instance_id",
            "current_image_digest",
            "current_config_digest",
            "prior_release_instance_id",
            "rollback_target_image_digest",
            "rollback_target_config_digest",
            "failed_release_record_digest",
            "rollback_target_release_record_digest",
            "rollback_reason_commitment",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_machine_preflight",
            "durable_prior_release_ledger",
            "provider_state_matches_failed_release",
            "machine_lease_and_current_version",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.deployment.rollback.canonical.v1",
        "provider_mappings": [
            {"provider": "fly", "operation": "machines.update"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Production machine"},
            {"field": "target_digest", "label": "Prior release"},
            {"field": "provider", "label": "Deployment provider"},
            {"field": "reason", "label": "Rollback reason"},
        ],
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
        "does_not_establish": [
            "fly_acceptance_or_successful_machine_update_without_provider_receipt",
            "restored_application_health_traffic_or_data",
            "reversal_of_external_effects_caused_by_the_failed_release",
        ],
        "risk_tags": ["production_rollback", "infrastructure", "runtime_change"],
    },
]


FACT_PROFILES = {
    "repository.pull_request.merge.v1": {
        "fact_profile_id": "keel.facts.repository_pull_request_merge_exact.v1",
        "target_fact_paths": [
            "/repository_reference_commitment",
            "/pull_request_number",
            "/head_commit_sha",
            "/base_branch",
        ],
        "material_request_fact_paths": [
            "/base_branch_tip_sha",
            "/merge_method",
            "/branch_protection_state_digest",
            "/pull_request_state_digest",
            "/checks_state_digest",
            "/reviews_state_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/repository_reference_commitment",
            "/pull_request_number",
            "/head_commit_sha",
            "/base_branch",
            "/base_branch_tip_sha",
            "/pull_request_state",
            "/draft",
            "/mergeable",
            "/mergeable_state",
            "/merge_method",
            "/branch_protection_source",
            "/strict_status_checks",
            "/required_status_checks_count",
            "/required_status_checks_state",
            "/required_approving_reviews",
            "/observed_approving_reviews",
            "/dismiss_stale_reviews",
            "/require_last_push_approval",
            "/required_conversation_resolution",
            "/enforce_admins",
            "/branch_protection_state_digest",
            "/pull_request_state_digest",
            "/checks_state_digest",
            "/reviews_state_digest",
        ],
    },
    "deployment.commit.deploy.v1": {
        "fact_profile_id": "keel.facts.deployment_commit_deploy_exact.v1",
        "target_fact_paths": [
            "/source_repository_reference_commitment",
            "/source_commit_sha",
            "/target_image_digest",
            "/fly_app_reference_commitment",
            "/fly_machine_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/artifact_revision_sha",
            "/current_instance_id",
            "/current_image_digest",
            "/current_config_digest",
            "/target_config_digest",
            "/release_record_digest",
            "/rollback_snapshot_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/source_repository_reference_commitment",
            "/source_commit_sha",
            "/source_commit_signature_verified",
            "/artifact_registry",
            "/artifact_repository_reference_commitment",
            "/target_image_reference_commitment",
            "/target_image_digest",
            "/artifact_revision_sha",
            "/artifact_revision_matches_source_commit",
            "/artifact_metadata_digest",
            "/fly_app_reference_commitment",
            "/fly_machine_reference_commitment",
            "/deployment_environment",
            "/current_instance_id",
            "/current_machine_state",
            "/current_image_digest",
            "/current_config_digest",
            "/target_config_digest",
            "/config_delta",
            "/target_image_differs",
            "/target_machine_state",
            "/expected_health_check_count",
            "/concurrency_control",
            "/machine_lease_required",
            "/release_record_digest",
            "/rollback_snapshot_digest",
        ],
    },
    "deployment.rollback.v1": {
        "fact_profile_id": "keel.facts.deployment_rollback_exact.v1",
        "target_fact_paths": [
            "/fly_app_reference_commitment",
            "/fly_machine_reference_commitment",
            "/rollback_target_image_digest",
        ],
        "material_request_fact_paths": [
            "/current_release_instance_id",
            "/current_image_digest",
            "/current_config_digest",
            "/prior_release_instance_id",
            "/rollback_target_config_digest",
            "/failed_release_record_digest",
            "/rollback_target_release_record_digest",
            "/rollback_reason_commitment",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/fly_app_reference_commitment",
            "/fly_machine_reference_commitment",
            "/deployment_environment",
            "/current_release_instance_id",
            "/current_machine_state",
            "/current_image_digest",
            "/current_config_digest",
            "/prior_release_instance_id",
            "/rollback_target_image_digest",
            "/rollback_target_config_digest",
            "/failed_release_record_digest",
            "/rollback_target_release_record_digest",
            "/rollback_reason_commitment",
            "/release_ledger_version",
            "/config_delta",
            "/target_machine_state",
            "/expected_health_check_count",
            "/concurrency_control",
            "/machine_lease_required",
        ],
    },
}


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


INTEGER_FIELDS = {
    "pull_request_number",
    "required_status_checks_count",
    "required_approving_reviews",
    "observed_approving_reviews",
    "expected_health_check_count",
    "max_uses",
}
BOOLEAN_FIELDS = {
    "draft",
    "mergeable",
    "strict_status_checks",
    "dismiss_stale_reviews",
    "require_last_push_approval",
    "required_conversation_resolution",
    "enforce_admins",
    "source_commit_signature_verified",
    "artifact_revision_matches_source_commit",
    "target_image_differs",
    "machine_lease_required",
}
TIMESTAMP_FIELDS = {"preflight_observed_at", "preflight_expires_at"}


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
        "fact_profile_id": FACT_PROFILES[consequence["consequence_type"]][
            "fact_profile_id"
        ],
    }


def presentation_profile(consequence: dict) -> dict:
    return {
        "semantic_id": consequence["semantic_id"],
        "presentation_profile_id": (
            consequence["consequence_type"].rsplit(".v", 1)[0].replace(".", "_")
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


def fact_field(path: str) -> dict:
    name = path.removeprefix("/")
    is_commitment = name.endswith("_commitment")
    is_digest = name.endswith("_digest") or name.endswith("_hash")
    if is_commitment:
        value_type = "commitment"
    elif is_digest:
        value_type = "digest"
    elif name in INTEGER_FIELDS:
        value_type = "integer"
    elif name in BOOLEAN_FIELDS:
        value_type = "boolean"
    elif name in TIMESTAMP_FIELDS:
        value_type = "timestamp"
    else:
        value_type = "string"
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
            "erasure_action": "erase_opening" if is_commitment else "retain_signed_value",
        },
        "commitment_method": (
            "keel.salted_sha256_jcs.v1" if is_commitment else "signed_cleartext"
        ),
    }


def fact_profile(consequence: dict, schema_digest: str) -> dict:
    contract = FACT_PROFILES[consequence["consequence_type"]]
    paths = list(dict.fromkeys([*COMMON_FACT_PATHS, *contract["field_paths"]]))
    return {
        "fact_profile_id": contract["fact_profile_id"],
        "semantic_ids": [consequence["semantic_id"]],
        "authorized_action": consequence["tool_names"][0],
        "facts_schema": FACT_SCHEMA,
        "facts_schema_digest": f"sha256:{schema_digest}",
        "target_fact_paths": contract["target_fact_paths"],
        "material_request_fact_paths": contract["material_request_fact_paths"],
        "fields": [fact_field(path) for path in paths],
        "release_state": "eligible",
    }


def build_schema() -> dict:
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    raw_digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    git_sha = {"type": "string", "pattern": "^(?:[0-9a-f]{40}|[0-9a-f]{64})$"}
    timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": (
            "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
            "[0-9]{2}(?:\\.[0-9]{1,9})?Z$"
        ),
    }
    commitment_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["method", "digest"],
        "properties": {
            "method": {"const": "keel.salted_sha256_jcs.v1"},
            "digest": {"$ref": "#/$defs/digest"},
        },
    }
    common = {
        "version": {"const": "keel.release_exact_facts.v1"},
        "fact_profile_id": {"type": "string"},
        "action": {"type": "string"},
        "operation": {"const": "call.tools"},
        "connector_identity": {"enum": ["github", "fly"]},
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
    common_required = list(common)
    action_properties = {
        "repositoryPullRequestMerge": {
            "fact_profile_id": {"const": "keel.facts.repository_pull_request_merge_exact.v1"},
            "action": {"const": "repository.pull_request.merge"},
            "connector_identity": {"const": "github"},
            "repository_reference_commitment": commitment_schema,
            "pull_request_number": {"type": "integer", "minimum": 1},
            "head_commit_sha": git_sha,
            "base_branch": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$",
            },
            "base_branch_tip_sha": git_sha,
            "pull_request_state": {"const": "open"},
            "draft": {"const": False},
            "mergeable": {"const": True},
            "mergeable_state": {"const": "clean"},
            "merge_method": {"enum": ["merge", "squash", "rebase"]},
            "branch_protection_source": {"const": "branch_protection"},
            "strict_status_checks": {"const": True},
            "required_status_checks_count": {"type": "integer", "minimum": 1},
            "required_status_checks_state": {"const": "success"},
            "required_approving_reviews": {"type": "integer", "minimum": 1},
            "observed_approving_reviews": {"type": "integer", "minimum": 1},
            "dismiss_stale_reviews": {"const": True},
            "require_last_push_approval": {"const": True},
            "required_conversation_resolution": {"const": True},
            "enforce_admins": {"const": True},
            "branch_protection_state_digest": digest,
            "pull_request_state_digest": digest,
            "checks_state_digest": digest,
            "reviews_state_digest": digest,
        },
        "deploymentCommitDeploy": {
            "fact_profile_id": {"const": "keel.facts.deployment_commit_deploy_exact.v1"},
            "action": {"const": "deployment.commit.deploy"},
            "connector_identity": {"const": "fly"},
            "source_repository_reference_commitment": commitment_schema,
            "source_commit_sha": git_sha,
            "source_commit_signature_verified": {"const": True},
            "artifact_registry": {"const": "ghcr.io"},
            "artifact_repository_reference_commitment": commitment_schema,
            "target_image_reference_commitment": commitment_schema,
            "target_image_digest": digest,
            "artifact_revision_sha": git_sha,
            "artifact_revision_matches_source_commit": {"const": True},
            "artifact_metadata_digest": digest,
            "fly_app_reference_commitment": commitment_schema,
            "fly_machine_reference_commitment": commitment_schema,
            "deployment_environment": {"const": "production"},
            "current_instance_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "current_machine_state": {"const": "started"},
            "current_image_digest": digest,
            "current_config_digest": digest,
            "target_config_digest": digest,
            "config_delta": {"const": "image_only"},
            "target_image_differs": {"const": True},
            "target_machine_state": {"const": "started"},
            "expected_health_check_count": {"type": "integer", "minimum": 1},
            "concurrency_control": {"const": "lease_and_current_version"},
            "machine_lease_required": {"const": True},
            "release_record_digest": digest,
            "rollback_snapshot_digest": digest,
        },
        "deploymentRollback": {
            "fact_profile_id": {"const": "keel.facts.deployment_rollback_exact.v1"},
            "action": {"const": "deployment.rollback"},
            "connector_identity": {"const": "fly"},
            "fly_app_reference_commitment": commitment_schema,
            "fly_machine_reference_commitment": commitment_schema,
            "deployment_environment": {"const": "production"},
            "current_release_instance_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "current_machine_state": {"enum": ["started", "stopped", "suspended"]},
            "current_image_digest": digest,
            "current_config_digest": digest,
            "prior_release_instance_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "rollback_target_image_digest": digest,
            "rollback_target_config_digest": digest,
            "failed_release_record_digest": digest,
            "rollback_target_release_record_digest": digest,
            "rollback_reason_commitment": commitment_schema,
            "release_ledger_version": {"const": "keel.release_ledger.v1"},
            "config_delta": {"const": "prior_release_snapshot"},
            "target_machine_state": {"const": "started"},
            "expected_health_check_count": {"type": "integer", "minimum": 1},
            "concurrency_control": {"const": "lease_and_current_version"},
            "machine_lease_required": {"const": True},
        },
    }
    definitions = {}
    for name, specific in action_properties.items():
        properties = copy.deepcopy(common)
        properties.update(copy.deepcopy(specific))
        definitions[name] = {
            "type": "object",
            "additionalProperties": False,
            "required": [*common_required, *[key for key in specific if key not in common]],
            "properties": properties,
        }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/keelapi/keel-permit/schemas/"
            "release-exact-facts-v1.schema.json"
        ),
        "title": "Keel exact Merge-to-Production authorization facts v1",
        "oneOf": [
            {"$ref": "#/$defs/repositoryPullRequestMerge"},
            {"$ref": "#/$defs/deploymentCommitDeploy"},
            {"$ref": "#/$defs/deploymentRollback"},
        ],
        "$defs": {
            "digest": digest,
            "rawDigest": raw_digest,
            "gitSha": git_sha,
            "timestamp": timestamp,
            "saltedCommitment": commitment_schema,
            **definitions,
        },
    }


def fact_vector(consequence: dict) -> dict:
    action = consequence["tool_names"][0]
    common = {
        "version": "keel.release_exact_facts.v1",
        "fact_profile_id": FACT_PROFILES[consequence["consequence_type"]][
            "fact_profile_id"
        ],
        "action": action,
        "operation": "call.tools",
        "connector_identity": "github" if action.startswith("repository.") else "fly",
        "connector_contract_hash": "0" * 64,
        "tool_schema_hash": "1" * 64,
        "decision_trace_hash": "2" * 64,
        "tool_arguments_hash": "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "enforcement_mode": "enforced_in_path",
        "provider_environment": "dedicated_demo",
        "provider_api_version": "2026-03-10" if action.startswith("repository.") else "v1",
        "preflight_observed_at": "2026-08-10T12:00:00Z",
        "preflight_expires_at": "2026-08-10T12:05:00Z",
        "preflight_snapshot_digest": "sha256:" + "a" * 64,
        "idempotency_digest": "sha256:" + "9" * 64,
        "max_uses": 1,
    }
    specific = {
        "repository.pull_request.merge": {
            "repository_reference_commitment": commitment("5"),
            "pull_request_number": 42,
            "head_commit_sha": "b" * 40,
            "base_branch": "main",
            "base_branch_tip_sha": "c" * 40,
            "pull_request_state": "open",
            "draft": False,
            "mergeable": True,
            "mergeable_state": "clean",
            "merge_method": "squash",
            "branch_protection_source": "branch_protection",
            "strict_status_checks": True,
            "required_status_checks_count": 2,
            "required_status_checks_state": "success",
            "required_approving_reviews": 1,
            "observed_approving_reviews": 1,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": True,
            "required_conversation_resolution": True,
            "enforce_admins": True,
            "branch_protection_state_digest": "sha256:" + "d" * 64,
            "pull_request_state_digest": "sha256:" + "e" * 64,
            "checks_state_digest": "sha256:" + "f" * 64,
            "reviews_state_digest": "sha256:" + "6" * 64,
        },
        "deployment.commit.deploy": {
            "source_repository_reference_commitment": commitment("5"),
            "source_commit_sha": "b" * 40,
            "source_commit_signature_verified": True,
            "artifact_registry": "ghcr.io",
            "artifact_repository_reference_commitment": commitment("6"),
            "target_image_reference_commitment": commitment("7"),
            "target_image_digest": "sha256:" + "c" * 64,
            "artifact_revision_sha": "b" * 40,
            "artifact_revision_matches_source_commit": True,
            "artifact_metadata_digest": "sha256:" + "d" * 64,
            "fly_app_reference_commitment": commitment("8"),
            "fly_machine_reference_commitment": commitment("e"),
            "deployment_environment": "production",
            "current_instance_id": "01J5CURRENTVERSION",
            "current_machine_state": "started",
            "current_image_digest": "sha256:" + "f" * 64,
            "current_config_digest": "sha256:" + "6" * 64,
            "target_config_digest": "sha256:" + "7" * 64,
            "config_delta": "image_only",
            "target_image_differs": True,
            "target_machine_state": "started",
            "expected_health_check_count": 1,
            "concurrency_control": "lease_and_current_version",
            "machine_lease_required": True,
            "release_record_digest": "sha256:" + "8" * 64,
            "rollback_snapshot_digest": "sha256:" + "e" * 64,
        },
        "deployment.rollback": {
            "fly_app_reference_commitment": commitment("5"),
            "fly_machine_reference_commitment": commitment("6"),
            "deployment_environment": "production",
            "current_release_instance_id": "01J5FAILEDVERSION",
            "current_machine_state": "started",
            "current_image_digest": "sha256:" + "b" * 64,
            "current_config_digest": "sha256:" + "c" * 64,
            "prior_release_instance_id": "01J5PRIORVERSION",
            "rollback_target_image_digest": "sha256:" + "d" * 64,
            "rollback_target_config_digest": "sha256:" + "e" * 64,
            "failed_release_record_digest": "sha256:" + "f" * 64,
            "rollback_target_release_record_digest": "sha256:" + "6" * 64,
            "rollback_reason_commitment": commitment("7"),
            "release_ledger_version": "keel.release_ledger.v1",
            "config_delta": "prior_release_snapshot",
            "target_machine_state": "started",
            "expected_health_check_count": 1,
            "concurrency_control": "lease_and_current_version",
            "machine_lease_required": True,
        },
    }
    return {**common, **specific[action]}


def main() -> None:
    write(FACT_SCHEMA, build_schema())

    consequence_v3 = load("consequence_registry/v3.json")
    consequence_v4 = copy.deepcopy(consequence_v3)
    consequence_v4["$schema"] = "./v4.schema.json"
    consequence_v4["version"] = "keel.consequence_registry.v4"
    consequence_v4["consequences"].extend(copy.deepcopy(CONSEQUENCES))
    write("consequence_registry/v4.json", consequence_v4)

    consequence_schema = copy.deepcopy(load("consequence_registry/v3.schema.json"))
    consequence_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/consequence_registry/v4.schema.json"
    )
    consequence_schema["title"] = "Keel consequence registry v4"
    consequence_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v4"
    )
    write("consequence_registry/v4.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v6 = load("fact_profiles/v6.json")
    facts_v7 = copy.deepcopy(facts_v6)
    facts_v7["$schema"] = "./v7.schema.json"
    facts_v7["version"] = "keel.fact_profile_registry.v7"
    facts_v7["profiles"].extend(
        fact_profile(item, facts_digest) for item in CONSEQUENCES
    )
    write("fact_profiles/v7.json", facts_v7)

    facts_schema_v7 = copy.deepcopy(load("fact_profiles/v6.schema.json"))
    facts_schema_v7["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v7.schema.json"
    )
    facts_schema_v7["title"] = "Keel Permit fact profile registry v7"
    facts_schema_v7["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v7"
    )
    write("fact_profiles/v7.schema.json", facts_schema_v7)

    semantics_v8 = load("semantic_registry/v8.json")
    semantics_v9 = copy.deepcopy(semantics_v8)
    semantics_v9["$schema"] = "./v9.schema.json"
    semantics_v9["version"] = "keel.semantic_selector_registry.v9"
    semantics_v9["entries"].extend(semantic_entry(item) for item in CONSEQUENCES)
    write("semantic_registry/v9.json", semantics_v9)

    semantic_schema_v9 = copy.deepcopy(load("semantic_registry/v8.schema.json"))
    semantic_schema_v9["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v9.schema.json"
    )
    semantic_schema_v9["title"] = "Keel Permit semantic selector registry v9"
    semantic_schema_v9["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v9"
    )
    write("semantic_registry/v9.schema.json", semantic_schema_v9)

    presentation_v7 = load("presentation_registry/v7.json")
    presentation_v8 = copy.deepcopy(presentation_v7)
    presentation_v8["$schema"] = "./v8.schema.json"
    presentation_v8["version"] = "keel.presentation_registry.v8"
    presentation_v8["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v9"
    )
    presentation_v8["profiles"].extend(
        presentation_profile(item) for item in CONSEQUENCES
    )
    write("presentation_registry/v8.json", presentation_v8)

    presentation_schema_v8 = copy.deepcopy(
        load("presentation_registry/v7.schema.json")
    )
    presentation_schema_v8["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v8.schema.json"
    )
    presentation_schema_v8["title"] = "Keel Permit presentation registry v8"
    presentation_schema_v8["properties"]["version"]["const"] = (
        "keel.presentation_registry.v8"
    )
    presentation_schema_v8["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v9"
    )
    write("presentation_registry/v8.schema.json", presentation_schema_v8)

    vectors_v4 = load("consequence_registry/test-vectors/v4.json")
    vectors_v5 = copy.deepcopy(vectors_v4)
    vectors_v5["version"] = "keel.consequence_registry.test_vectors.v5"
    vectors_v5["consequence_registry_version"] = consequence_v4["version"]
    vectors_v5["semantic_registry_version"] = semantics_v9["version"]
    vectors_v5["presentation_registry_version"] = presentation_v8["version"]
    for consequence in CONSEQUENCES:
        vectors_v5["vectors"].append(
            {
                "id": consequence["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": consequence["tool_names"][0],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": [
                        "authorization",
                        "dispatch",
                        "provider_outcome",
                    ],
                },
                "expected_semantic_id": consequence["semantic_id"],
                "expected_title": consequence["customer_title"],
                "expected_fact_profile_id": FACT_PROFILES[
                    consequence["consequence_type"]
                ]["fact_profile_id"],
                "valid_authorization_facts": fact_vector(consequence),
            }
        )
    write("consequence_registry/test-vectors/v5.json", vectors_v5)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v4", "consequence_registry/v4.json"),
        (
            "keel.permit.consequence_registry.v4.schema",
            "consequence_registry/v4.schema.json",
        ),
        ("keel.permit.release_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v7", "fact_profiles/v7.json"),
        (
            "keel.permit.fact_profile_registry.v7.schema",
            "fact_profiles/v7.schema.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v9",
            "semantic_registry/v9.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v9.schema",
            "semantic_registry/v9.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v8",
            "presentation_registry/v8.json",
        ),
        (
            "keel.permit.presentation_registry.v8.schema",
            "presentation_registry/v8.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v5",
            "consequence_registry/test-vectors/v5.json",
        ),
        (
            "keel.permit.release_exact_action_contract.v1.spec",
            "spec/release-exact-action-contract-v1.md",
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
