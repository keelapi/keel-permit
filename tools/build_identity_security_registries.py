#!/usr/bin/env python3
"""Build additive exact-action artifacts for the identity/security rail."""

from __future__ import annotations

import copy
from typing import Any

from build_transactional_cx_registries import commitment, load, sha256, write


FACT_SCHEMA = "schemas/identity-security-exact-facts-v1.schema.json"


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


IDENTITY_COMMON_PATHS = [
    "/tenant_reference_commitment",
    "/user_reference_commitment",
    "/provider_identity_type",
    "/current_user_status",
    "/user_state_digest",
    "/target_is_privileged_admin",
    "/admin_role_assignments_digest",
]


ACTION_DEFS: list[dict[str, Any]] = [
    {
        "consequence_type": "identity.mfa.reset.v1",
        "semantic_id": "keel.action.identity_mfa_reset.v1",
        "action": "identity.mfa.reset",
        "connector_identity": "okta",
        "customer_title": "AI Permit-to-Reset-MFA",
        "type_definition": (
            "Exact authorization to reset every enrolled MFA factor for one "
            "provider-verified identity"
        ),
        "provider_mapping": {"provider": "okta", "operation": "users.lifecycle.reset_factors"},
        "specific_paths": [
            *IDENTITY_COMMON_PATHS,
            "/enrolled_factor_count",
            "/factor_enrollment_state_digest",
            "/reset_scope",
            "/target_user_status",
        ],
        "target_paths": [
            "/tenant_reference_commitment",
            "/user_reference_commitment",
        ],
        "material_paths": [
            "/current_user_status",
            "/user_state_digest",
            "/target_is_privileged_admin",
            "/admin_role_assignments_digest",
            "/enrolled_factor_count",
            "/factor_enrollment_state_digest",
            "/reset_scope",
            "/target_user_status",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "provider_user_preflight",
            "provider_factor_enrollment_preflight",
            "provider_admin_role_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.identity.mfa.reset.canonical.v1",
        "does_not_establish": [
            "okta_acceptance_or_completed_factor_reset_without_provider_receipt",
            "future_successful_mfa_reenrollment",
            "revocation_of_sessions_or_oauth_tokens",
        ],
        "risk_tags": ["identity", "credential_reset", "account_takeover_risk"],
    },
    {
        "consequence_type": "identity.sessions.revoke.v1",
        "semantic_id": "keel.action.identity_sessions_revoke.v1",
        "action": "identity.sessions.revoke",
        "connector_identity": "okta",
        "customer_title": "AI Permit-to-Revoke-Sessions",
        "type_definition": (
            "Exact authorization to clear every Okta session and revoke OAuth "
            "tokens for one provider-verified identity"
        ),
        "provider_mapping": {"provider": "okta", "operation": "users.sessions.clear"},
        "specific_paths": [
            *IDENTITY_COMMON_PATHS,
            "/session_revocation_scope",
            "/revoke_oauth_tokens",
            "/active_sessions_enumerable",
        ],
        "target_paths": [
            "/tenant_reference_commitment",
            "/user_reference_commitment",
        ],
        "material_paths": [
            "/current_user_status",
            "/user_state_digest",
            "/target_is_privileged_admin",
            "/admin_role_assignments_digest",
            "/session_revocation_scope",
            "/revoke_oauth_tokens",
            "/active_sessions_enumerable",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "provider_user_preflight",
            "provider_admin_role_preflight",
            "provider_session_capability_contract",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.identity.sessions.revoke.canonical.v1",
        "does_not_establish": [
            "okta_acceptance_or_completed_session_revocation_without_provider_receipt",
            "logout_from_applications_that_do_not_honor_okta_token_revocation",
            "absence_of_non_okta_sessions",
        ],
        "risk_tags": ["identity", "session_revocation", "security_response"],
    },
    {
        "consequence_type": "identity.disable.v1",
        "semantic_id": "keel.action.identity_disable.v1",
        "action": "identity.disable",
        "connector_identity": "okta",
        "customer_title": "AI Permit-to-Disable-Identity",
        "type_definition": (
            "Exact authorization to deprovision one active Okta identity after "
            "provider verification of its current assignments and privilege"
        ),
        "provider_mapping": {"provider": "okta", "operation": "users.lifecycle.deactivate"},
        "specific_paths": [
            *IDENTITY_COMMON_PATHS,
            "/target_user_status",
            "/destructive_deprovisioning_acknowledged",
            "/app_assignment_state_digest",
            "/group_membership_state_digest",
        ],
        "target_paths": [
            "/tenant_reference_commitment",
            "/user_reference_commitment",
        ],
        "material_paths": [
            "/current_user_status",
            "/target_user_status",
            "/user_state_digest",
            "/target_is_privileged_admin",
            "/admin_role_assignments_digest",
            "/destructive_deprovisioning_acknowledged",
            "/app_assignment_state_digest",
            "/group_membership_state_digest",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "provider_user_preflight",
            "provider_admin_role_preflight",
            "provider_assignment_preflight",
            "explicit_destructive_action_acknowledgement",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.identity.disable.canonical.v1",
        "does_not_establish": [
            "okta_acceptance_or_terminal_deprovisioned_status_without_provider_readback",
            "preservation_or_removal_of_data_in_assigned_applications",
            "revocation_of_credentials_issued_outside_okta",
        ],
        "risk_tags": ["identity", "deprovisioning", "destructive", "access_removal"],
    },
    {
        "consequence_type": "identity.group_access.grant.v1",
        "semantic_id": "keel.action.identity_group_access_grant.v1",
        "action": "identity.group_access.grant",
        "connector_identity": "okta",
        "customer_title": "AI Permit-to-Grant-Group-Access",
        "type_definition": (
            "Exact authorization to add one provider-verified identity to one "
            "provider-verified Okta group"
        ),
        "provider_mapping": {"provider": "okta", "operation": "groups.users.add"},
        "specific_paths": [
            *IDENTITY_COMMON_PATHS,
            "/group_reference_commitment",
            "/group_type",
            "/group_privilege_class",
            "/group_state_digest",
            "/group_membership_state_digest",
            "/current_membership",
            "/target_membership",
            "/current_group_member_count",
            "/projected_group_member_count",
        ],
        "target_paths": [
            "/tenant_reference_commitment",
            "/user_reference_commitment",
            "/group_reference_commitment",
        ],
        "material_paths": [
            "/current_user_status",
            "/user_state_digest",
            "/target_is_privileged_admin",
            "/admin_role_assignments_digest",
            "/group_type",
            "/group_privilege_class",
            "/group_state_digest",
            "/group_membership_state_digest",
            "/current_membership",
            "/target_membership",
            "/current_group_member_count",
            "/projected_group_member_count",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "provider_user_preflight",
            "provider_group_preflight",
            "provider_membership_preflight",
            "keel_managed_group_privilege_classification",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.identity.group_access.grant.canonical.v1",
        "does_not_establish": [
            "okta_acceptance_or_completed_membership_change_without_provider_readback",
            "specific_downstream_application_entitlements_derived_from_the_group",
            "absence_of_other_access_paths",
        ],
        "risk_tags": ["identity", "access_grant", "privilege_change"],
    },
    {
        "consequence_type": "identity.group_access.remove.v1",
        "semantic_id": "keel.action.identity_group_access_remove.v1",
        "action": "identity.group_access.remove",
        "connector_identity": "okta",
        "customer_title": "AI Permit-to-Remove-Group-Access",
        "type_definition": (
            "Exact authorization to remove one provider-verified identity from one "
            "provider-verified Okta group"
        ),
        "provider_mapping": {"provider": "okta", "operation": "groups.users.remove"},
        "specific_paths": [
            *IDENTITY_COMMON_PATHS,
            "/group_reference_commitment",
            "/group_type",
            "/group_privilege_class",
            "/group_state_digest",
            "/group_membership_state_digest",
            "/current_membership",
            "/target_membership",
            "/current_group_member_count",
            "/projected_group_member_count",
            "/target_is_last_privileged_member",
        ],
        "target_paths": [
            "/tenant_reference_commitment",
            "/user_reference_commitment",
            "/group_reference_commitment",
        ],
        "material_paths": [
            "/current_user_status",
            "/user_state_digest",
            "/target_is_privileged_admin",
            "/admin_role_assignments_digest",
            "/group_type",
            "/group_privilege_class",
            "/group_state_digest",
            "/group_membership_state_digest",
            "/current_membership",
            "/target_membership",
            "/current_group_member_count",
            "/projected_group_member_count",
            "/target_is_last_privileged_member",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "provider_user_preflight",
            "provider_group_preflight",
            "provider_membership_preflight",
            "keel_managed_group_privilege_classification",
            "provider_last_privileged_member_preflight",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.identity.group_access.remove.canonical.v1",
        "does_not_establish": [
            "okta_acceptance_or_completed_membership_change_without_provider_readback",
            "revocation_of_sessions_or_entitlements_cached_by_downstream_applications",
            "absence_of_other_group_or_direct_access",
        ],
        "risk_tags": ["identity", "access_removal", "privilege_change"],
    },
    {
        "consequence_type": "security.indicator.block.v1",
        "semantic_id": "keel.action.security_indicator_block.v1",
        "action": "security.indicator.block",
        "connector_identity": "cloudflare",
        "customer_title": "AI Permit-to-Block-Indicator",
        "type_definition": (
            "Exact authorization to add one enabled block rule for one indicator "
            "to one provider-verified Cloudflare zone ruleset"
        ),
        "provider_mapping": {"provider": "cloudflare", "operation": "rulesets.rules.create"},
        "specific_paths": [
            "/zone_reference_commitment",
            "/zone_status",
            "/ruleset_reference_commitment",
            "/ruleset_phase",
            "/ruleset_version",
            "/ruleset_state_digest",
            "/indicator_reference_commitment",
            "/indicator_type",
            "/indicator_scope",
            "/source_alert_reference_commitment",
            "/rule_expression_digest",
            "/rule_reference_commitment",
            "/current_matching_rule_count",
            "/current_rules_count",
            "/projected_rules_count",
            "/target_action",
            "/rule_enabled",
        ],
        "target_paths": [
            "/zone_reference_commitment",
            "/ruleset_reference_commitment",
            "/indicator_reference_commitment",
        ],
        "material_paths": [
            "/zone_status",
            "/ruleset_phase",
            "/ruleset_version",
            "/ruleset_state_digest",
            "/indicator_type",
            "/indicator_scope",
            "/source_alert_reference_commitment",
            "/rule_expression_digest",
            "/rule_reference_commitment",
            "/current_matching_rule_count",
            "/current_rules_count",
            "/projected_rules_count",
            "/target_action",
            "/rule_enabled",
        ],
        "trusted_facts": [
            "connector_identity",
            "tool_contract",
            "provider_zone_preflight",
            "provider_ruleset_preflight",
            "provider_existing_rule_preflight",
            "deterministic_indicator_expression_derivation",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.security.indicator.block.canonical.v1",
        "does_not_establish": [
            "cloudflare_acceptance_or_active_rule_without_provider_readback",
            "maliciousness_of_the_indicator",
            "blocking_outside_the_named_zone_and_ruleset",
        ],
        "risk_tags": ["security_response", "network_block", "traffic_control"],
    },
]


INTEGER_FIELDS = {
    "enrolled_factor_count",
    "current_group_member_count",
    "projected_group_member_count",
    "current_matching_rule_count",
    "current_rules_count",
    "projected_rules_count",
    "max_uses",
}
BOOLEAN_FIELDS = {
    "target_is_privileged_admin",
    "revoke_oauth_tokens",
    "active_sessions_enumerable",
    "destructive_deprovisioning_acknowledged",
    "current_membership",
    "target_membership",
    "target_is_last_privileged_member",
    "rule_enabled",
}
TIMESTAMP_FIELDS = {"preflight_observed_at", "preflight_expires_at"}


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
        "presentation_profile_id": action_def["consequence_type"].rsplit(".v", 1)[0].replace(".", "_") + ".r1",
        "customer_title": action_def["customer_title"],
        "type_definition": action_def["type_definition"],
        "leading_fields": [
            {"field": "resource", "label": "Identity or security target"},
            {"field": "request_digest", "label": "Exact requested change"},
            {"field": "provider", "label": "Identity or security provider"},
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
        "does_not_establish": action_def["does_not_establish"],
        "fallback_profile": "generic_ai_permit",
        "release_state": "eligible",
    }


def fact_profile_id(action_def: dict[str, Any]) -> str:
    return "keel.facts." + action_def["action"].replace(".", "_") + "_exact.v1"


def fact_field(path: str) -> dict[str, Any]:
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
            "authorized": "commitment_with_optional_opening" if is_commitment else "cleartext",
            "private": "commitment_with_optional_opening" if is_commitment else "cleartext",
        },
        "retention": {
            "class": "deletable_identity" if is_commitment else "permit_evidence",
            "max_days": None,
            "erasable": is_commitment,
            "erasure_action": "erase_opening" if is_commitment else "retain_signed_value",
        },
        "commitment_method": "keel.salted_sha256_jcs.v1" if is_commitment else "signed_cleartext",
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
        "leading_fields": [
            {"field": "resource", "label": "Identity or security target"},
            {"field": "request_digest", "label": "Exact requested change"},
            {"field": "provider", "label": "Identity or security provider"},
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
        "does_not_establish": action_def["does_not_establish"],
        "risk_tags": action_def["risk_tags"],
    }


def common_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    raw_digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$",
    }
    return {
        "version": {"const": "keel.identity_security_exact_facts.v1"},
        "fact_profile_id": {"type": "string"},
        "action": {"type": "string"},
        "operation": {"const": "call.tools"},
        "connector_identity": {"enum": ["okta", "cloudflare"]},
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


def identity_schema(action_def: dict[str, Any]) -> dict[str, Any]:
    digest = {"$ref": "#/$defs/digest"}
    commitment_schema = {"$ref": "#/$defs/saltedCommitment"}
    properties: dict[str, Any] = {
        "fact_profile_id": {"const": fact_profile_id(action_def)},
        "action": {"const": action_def["action"]},
        "connector_identity": {"const": "okta"},
        "tenant_reference_commitment": commitment_schema,
        "user_reference_commitment": commitment_schema,
        "provider_identity_type": {"const": "user"},
        "current_user_status": {
            "enum": ["ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY", "SUSPENDED"]
        },
        "user_state_digest": digest,
        "target_is_privileged_admin": {"type": "boolean"},
        "admin_role_assignments_digest": digest,
    }
    action = action_def["action"]
    if action == "identity.mfa.reset":
        properties.update(
            {
                "enrolled_factor_count": {"type": "integer", "minimum": 1},
                "factor_enrollment_state_digest": digest,
                "reset_scope": {"const": "all_enrolled_factors"},
                "target_user_status": {"const": "ACTIVE"},
            }
        )
    elif action == "identity.sessions.revoke":
        properties.update(
            {
                "session_revocation_scope": {"const": "all_okta_sessions_and_oauth_tokens"},
                "revoke_oauth_tokens": {"const": True},
                "active_sessions_enumerable": {"const": False},
            }
        )
    elif action == "identity.disable":
        properties.update(
            {
                "current_user_status": {"const": "ACTIVE"},
                "target_user_status": {"const": "DEPROVISIONED"},
                "destructive_deprovisioning_acknowledged": {"const": True},
                "app_assignment_state_digest": digest,
                "group_membership_state_digest": digest,
            }
        )
    else:
        grant = action == "identity.group_access.grant"
        properties.update(
            {
                "current_user_status": {"const": "ACTIVE"},
                "group_reference_commitment": commitment_schema,
                "group_type": {"const": "OKTA_GROUP"},
                "group_privilege_class": {"enum": ["standard", "privileged", "administrative"]},
                "group_state_digest": digest,
                "group_membership_state_digest": digest,
                "current_membership": {"const": not grant},
                "target_membership": {"const": grant},
                "current_group_member_count": {"type": "integer", "minimum": 0},
                "projected_group_member_count": {"type": "integer", "minimum": 0},
            }
        )
        if not grant:
            properties["target_is_last_privileged_member"] = {"const": False}
    return properties


def cloudflare_schema(action_def: dict[str, Any]) -> dict[str, Any]:
    digest = {"$ref": "#/$defs/digest"}
    commitment_schema = {"$ref": "#/$defs/saltedCommitment"}
    return {
        "fact_profile_id": {"const": fact_profile_id(action_def)},
        "action": {"const": action_def["action"]},
        "connector_identity": {"const": "cloudflare"},
        "zone_reference_commitment": commitment_schema,
        "zone_status": {"const": "active"},
        "ruleset_reference_commitment": commitment_schema,
        "ruleset_phase": {"const": "http_request_firewall_custom"},
        "ruleset_version": {"type": "string", "minLength": 1, "maxLength": 64},
        "ruleset_state_digest": digest,
        "indicator_reference_commitment": commitment_schema,
        "indicator_type": {"enum": ["ipv4", "ipv6", "cidr"]},
        "indicator_scope": {"const": "public_internet"},
        "source_alert_reference_commitment": commitment_schema,
        "rule_expression_digest": digest,
        "rule_reference_commitment": commitment_schema,
        "current_matching_rule_count": {"const": 0},
        "current_rules_count": {"type": "integer", "minimum": 0},
        "projected_rules_count": {"type": "integer", "minimum": 1},
        "target_action": {"const": "block"},
        "rule_enabled": {"const": True},
    }


def build_schema() -> dict[str, Any]:
    common = common_schema()
    definitions: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    for action_def in ACTION_DEFS:
        name = action_def["action"].replace(".", "_")
        specific = (
            cloudflare_schema(action_def)
            if action_def["connector_identity"] == "cloudflare"
            else identity_schema(action_def)
        )
        properties = copy.deepcopy(common)
        properties.update(copy.deepcopy(specific))
        definitions[name] = {
            "type": "object",
            "additionalProperties": False,
            "required": list(properties),
            "properties": properties,
        }
        refs.append({"$ref": f"#/$defs/{name}"})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/keelapi/keel-permit/schemas/identity-security-exact-facts-v1.schema.json",
        "title": "Keel exact identity and security authorization facts v1",
        "oneOf": refs,
        "$defs": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "rawDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$",
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
        "version": "keel.identity_security_exact_facts.v1",
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
        "provider_api_version": "v1" if action_def["connector_identity"] == "okta" else "v4",
        "preflight_observed_at": "2026-08-10T12:00:00Z",
        "preflight_expires_at": "2026-08-10T12:05:00Z",
        "preflight_snapshot_digest": "sha256:" + "5" * 64,
        "idempotency_digest": "sha256:" + "6" * 64,
        "max_uses": 1,
    }
    identity_common = {
        "tenant_reference_commitment": commitment("7"),
        "user_reference_commitment": commitment("8"),
        "provider_identity_type": "user",
        "current_user_status": "ACTIVE",
        "user_state_digest": "sha256:" + "9" * 64,
        "target_is_privileged_admin": False,
        "admin_role_assignments_digest": "sha256:" + "a" * 64,
    }
    specifics: dict[str, dict[str, Any]] = {
        "identity.mfa.reset": {
            **identity_common,
            "enrolled_factor_count": 2,
            "factor_enrollment_state_digest": "sha256:" + "b" * 64,
            "reset_scope": "all_enrolled_factors",
            "target_user_status": "ACTIVE",
        },
        "identity.sessions.revoke": {
            **identity_common,
            "session_revocation_scope": "all_okta_sessions_and_oauth_tokens",
            "revoke_oauth_tokens": True,
            "active_sessions_enumerable": False,
        },
        "identity.disable": {
            **identity_common,
            "target_user_status": "DEPROVISIONED",
            "destructive_deprovisioning_acknowledged": True,
            "app_assignment_state_digest": "sha256:" + "b" * 64,
            "group_membership_state_digest": "sha256:" + "c" * 64,
        },
        "identity.group_access.grant": {
            **identity_common,
            "group_reference_commitment": commitment("b"),
            "group_type": "OKTA_GROUP",
            "group_privilege_class": "standard",
            "group_state_digest": "sha256:" + "c" * 64,
            "group_membership_state_digest": "sha256:" + "d" * 64,
            "current_membership": False,
            "target_membership": True,
            "current_group_member_count": 4,
            "projected_group_member_count": 5,
        },
        "identity.group_access.remove": {
            **identity_common,
            "group_reference_commitment": commitment("b"),
            "group_type": "OKTA_GROUP",
            "group_privilege_class": "privileged",
            "group_state_digest": "sha256:" + "c" * 64,
            "group_membership_state_digest": "sha256:" + "d" * 64,
            "current_membership": True,
            "target_membership": False,
            "current_group_member_count": 4,
            "projected_group_member_count": 3,
            "target_is_last_privileged_member": False,
        },
        "security.indicator.block": {
            "zone_reference_commitment": commitment("7"),
            "zone_status": "active",
            "ruleset_reference_commitment": commitment("8"),
            "ruleset_phase": "http_request_firewall_custom",
            "ruleset_version": "17",
            "ruleset_state_digest": "sha256:" + "9" * 64,
            "indicator_reference_commitment": commitment("a"),
            "indicator_type": "ipv4",
            "indicator_scope": "public_internet",
            "source_alert_reference_commitment": commitment("b"),
            "rule_expression_digest": "sha256:" + "c" * 64,
            "rule_reference_commitment": commitment("d"),
            "current_matching_rule_count": 0,
            "current_rules_count": 6,
            "projected_rules_count": 7,
            "target_action": "block",
            "rule_enabled": True,
        },
    }
    return {**common, **specifics[action]}


def main() -> None:
    write(FACT_SCHEMA, build_schema())

    consequences = [consequence(item) for item in ACTION_DEFS]
    consequence_v4 = load("consequence_registry/v4.json")
    consequence_v5 = copy.deepcopy(consequence_v4)
    consequence_v5["$schema"] = "./v5.schema.json"
    consequence_v5["version"] = "keel.consequence_registry.v5"
    consequence_v5["consequences"].extend(copy.deepcopy(consequences))
    write("consequence_registry/v5.json", consequence_v5)

    consequence_schema = copy.deepcopy(load("consequence_registry/v4.schema.json"))
    consequence_schema["$id"] = "https://github.com/keelapi/keel-permit/consequence_registry/v5.schema.json"
    consequence_schema["title"] = "Keel consequence registry v5"
    consequence_schema["properties"]["version"]["const"] = "keel.consequence_registry.v5"
    write("consequence_registry/v5.schema.json", consequence_schema)

    facts_digest = sha256(FACT_SCHEMA)
    facts_v7 = load("fact_profiles/v7.json")
    facts_v8 = copy.deepcopy(facts_v7)
    facts_v8["$schema"] = "./v8.schema.json"
    facts_v8["version"] = "keel.fact_profile_registry.v8"
    facts_v8["profiles"].extend(fact_profile(item, facts_digest) for item in ACTION_DEFS)
    write("fact_profiles/v8.json", facts_v8)

    facts_schema = copy.deepcopy(load("fact_profiles/v7.schema.json"))
    facts_schema["$id"] = "https://github.com/keelapi/keel-permit/fact_profiles/v8.schema.json"
    facts_schema["title"] = "Keel Permit fact profile registry v8"
    facts_schema["properties"]["version"]["const"] = "keel.fact_profile_registry.v8"
    write("fact_profiles/v8.schema.json", facts_schema)

    semantics_v9 = load("semantic_registry/v9.json")
    semantics_v10 = copy.deepcopy(semantics_v9)
    semantics_v10["$schema"] = "./v10.schema.json"
    semantics_v10["version"] = "keel.semantic_selector_registry.v10"
    semantics_v10["entries"].extend(semantic_entry(item) for item in ACTION_DEFS)
    write("semantic_registry/v10.json", semantics_v10)

    semantic_schema = copy.deepcopy(load("semantic_registry/v9.schema.json"))
    semantic_schema["$id"] = "https://github.com/keelapi/keel-permit/semantic_registry/v10.schema.json"
    semantic_schema["title"] = "Keel Permit semantic selector registry v10"
    semantic_schema["properties"]["version"]["const"] = "keel.semantic_selector_registry.v10"
    write("semantic_registry/v10.schema.json", semantic_schema)

    presentation_v8 = load("presentation_registry/v8.json")
    presentation_v9 = copy.deepcopy(presentation_v8)
    presentation_v9["$schema"] = "./v9.schema.json"
    presentation_v9["version"] = "keel.presentation_registry.v9"
    presentation_v9["semantic_registry_version"] = "keel.semantic_selector_registry.v10"
    presentation_v9["profiles"].extend(presentation_profile(item) for item in ACTION_DEFS)
    write("presentation_registry/v9.json", presentation_v9)

    presentation_schema = copy.deepcopy(load("presentation_registry/v8.schema.json"))
    presentation_schema["$id"] = "https://github.com/keelapi/keel-permit/presentation_registry/v9.schema.json"
    presentation_schema["title"] = "Keel Permit presentation registry v9"
    presentation_schema["properties"]["version"]["const"] = "keel.presentation_registry.v9"
    presentation_schema["properties"]["semantic_registry_version"]["const"] = "keel.semantic_selector_registry.v10"
    write("presentation_registry/v9.schema.json", presentation_schema)

    vectors_v5 = load("consequence_registry/test-vectors/v5.json")
    vectors_v6 = copy.deepcopy(vectors_v5)
    vectors_v6["version"] = "keel.consequence_registry.test_vectors.v6"
    vectors_v6["consequence_registry_version"] = consequence_v5["version"]
    vectors_v6["semantic_registry_version"] = semantics_v10["version"]
    vectors_v6["presentation_registry_version"] = presentation_v9["version"]
    for action_def in ACTION_DEFS:
        vectors_v6["vectors"].append(
            {
                "id": action_def["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": action_def["action"],
                    "operation": "call.tools",
                    "chain_role": "action_child",
                    "governed_surface": "mcp_tool",
                    "evidence_capabilities": ["authorization", "dispatch", "provider_outcome"],
                },
                "expected_semantic_id": action_def["semantic_id"],
                "expected_title": action_def["customer_title"],
                "expected_fact_profile_id": fact_profile_id(action_def),
                "valid_authorization_facts": fact_vector(action_def),
            }
        )
    write("consequence_registry/test-vectors/v6.json", vectors_v6)

    manifest_path = "artifact-manifests/permit-to-x-v1.json"
    manifest = load(manifest_path)
    additions = [
        ("keel.permit.consequence_registry.v5", "consequence_registry/v5.json"),
        ("keel.permit.consequence_registry.v5.schema", "consequence_registry/v5.schema.json"),
        ("keel.permit.identity_security_exact_facts.v1.schema", FACT_SCHEMA),
        ("keel.permit.fact_profile_registry.v8", "fact_profiles/v8.json"),
        ("keel.permit.fact_profile_registry.v8.schema", "fact_profiles/v8.schema.json"),
        ("keel.permit.semantic_selector_registry.v10", "semantic_registry/v10.json"),
        ("keel.permit.semantic_selector_registry.v10.schema", "semantic_registry/v10.schema.json"),
        ("keel.permit.presentation_registry.v9", "presentation_registry/v9.json"),
        ("keel.permit.presentation_registry.v9.schema", "presentation_registry/v9.schema.json"),
        ("permit-to-x.test-vectors.consequence-registry.v6", "consequence_registry/test-vectors/v6.json"),
        ("keel.permit.identity_security_exact_action_contract.v1.spec", "spec/identity-security-exact-action-contract-v1.md"),
    ]
    existing_by_path = {item["path"]: item for item in manifest["artifacts"]}
    for artifact_id, path in additions:
        if path in existing_by_path:
            existing_by_path[path]["id"] = artifact_id
            existing_by_path[path]["sha256"] = sha256(path)
            continue
        manifest["artifacts"].append({"id": artifact_id, "path": path, "sha256": sha256(path)})
    write(manifest_path, manifest)


if __name__ == "__main__":
    main()
