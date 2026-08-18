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


_DATABASE_FACT_PROFILES = {
    "database.rows.insert.v1": {
        "fact_profile_id": "keel.facts.database_rows_insert_exact.v1",
        "target_fact_paths": ["/table", "/schema_version"],
        "material_request_fact_paths": ["/rows_digest", "/request_digest"],
    },
    "database.rows.update.v1": {
        "fact_profile_id": "keel.facts.database_rows_update_exact.v1",
        "target_fact_paths": ["/table", "/predicate_digest"],
        "material_request_fact_paths": ["/changes_digest", "/request_digest"],
    },
    "database.rows.delete.v1": {
        "fact_profile_id": "keel.facts.database_rows_delete_exact.v1",
        "target_fact_paths": ["/table", "/predicate_digest"],
        "material_request_fact_paths": ["/request_digest"],
    },
    "database.migration.apply.v1": {
        "fact_profile_id": "keel.facts.database_migration_apply_exact.v1",
        "target_fact_paths": ["/migration_id", "/from_schema_version"],
        "material_request_fact_paths": ["/migration_digest", "/request_digest"],
    },
    "database.dataset.export.v1": {
        "fact_profile_id": "keel.facts.database_dataset_export_exact.v1",
        "target_fact_paths": ["/table", "/predicate_digest", "/fields_digest"],
        "material_request_fact_paths": ["/request_digest"],
    },
}


_PAYMENT_LEDGER_CONSEQUENCES = [
    {
        "consequence_type": "payment.invoice.pay.v1",
        "semantic_id": "keel.action.invoice_payment_execute.v1",
        "tool_names": ["payment.invoice.pay"],
        "customer_title": "AI Permit-to-Pay-Invoice",
        "type_definition": (
            "Exact authorization to pay one provider-verified open invoice"
        ),
        "required_material_fields": [
            "invoice_reference_commitment",
            "amount_minor",
            "currency",
            "invoice_state_digest",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_invoice_preflight",
            "invoice_status_before",
            "amount_minor",
            "currency",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.payment.invoice.pay.canonical.v1",
        "provider_mappings": [
            {"provider": "stripe", "operation": "invoice.pay"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Invoice"},
            {"field": "amount", "label": "Amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "recipient", "label": "Merchant"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "value_conservation",
            "settlement",
            "evidence_scope",
        ],
        "does_not_establish": [
            "provider_acceptance_without_provider_receipt",
            "financial_settlement",
            "delivery_of_invoiced_goods_or_services",
        ],
        "risk_tags": ["value_movement", "invoice_payment"],
    },
    {
        "consequence_type": "ledger.entry.record.v1",
        "semantic_id": "keel.action.ledger_entry_record.v1",
        "tool_names": ["ledger.entry.record"],
        "customer_title": "AI Permit-to-Record-Ledger-Entry",
        "type_definition": (
            "Exact authorization to post one version-checked double-entry record"
        ),
        "required_material_fields": [
            "ledger_reference_commitment",
            "entry_reference_commitment",
            "debit_account_commitment",
            "credit_account_commitment",
            "amount_minor",
            "currency",
            "entry_effective_at",
            "expected_ledger_version",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "ledger_schema_version",
            "expected_ledger_version",
            "value_conserved",
            "accounts_distinct",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.ledger.entry.record.canonical.v1",
        "provider_mappings": [
            {"provider": "postgres", "operation": "ledger_entry.insert"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Ledger and accounts"},
            {"field": "amount", "label": "Balanced amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "request_digest", "label": "Entry"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "value_conservation",
            "evidence_scope",
        ],
        "does_not_establish": [
            "database_commit_without_provider_receipt",
            "correct_accounting_classification",
            "financial_settlement",
        ],
        "risk_tags": ["financial_record", "data_mutation", "value_conservation"],
    },
    {
        "consequence_type": "payment.reconciliation.record.v1",
        "semantic_id": "keel.action.payment_reconciliation_record.v1",
        "tool_names": ["payment.reconciliation.record"],
        "customer_title": "AI Permit-to-Reconcile-Payment",
        "type_definition": (
            "Exact authorization to mark one payment and ledger entry reconciled"
        ),
        "required_material_fields": [
            "payment_reference_commitment",
            "ledger_entry_reference_commitment",
            "provider_observation_digest",
            "ledger_observation_digest",
            "amount_minor",
            "currency",
            "expected_current_status",
            "requested_status",
            "idempotency_digest",
            "preflight_snapshot_digest",
            "preflight_expires_at",
        ],
        "trusted_fact_requirements": [
            "connector_identity",
            "tool_contract",
            "provider_outcome_state",
            "ledger_entry_state",
            "amounts_match",
            "currencies_match",
            "reconciliation_basis_version",
            "gateway_preflight_hmac",
        ],
        "canonicalizer": "keel.payment.reconciliation.record.canonical.v1",
        "provider_mappings": [
            {"provider": "postgres", "operation": "reconciliation.update"}
        ],
        "leading_fields": [
            {"field": "resource", "label": "Payment and ledger entry"},
            {"field": "amount", "label": "Matched amount"},
            {"field": "currency", "label": "Currency"},
            {"field": "linked_to", "label": "Workflow"},
        ],
        "evidence_sections": [
            "record_identity",
            "authorization",
            "approval",
            "relationship",
            "limits",
            "dispatch",
            "provider_outcome",
            "value_conservation",
            "settlement",
            "evidence_scope",
        ],
        "does_not_establish": [
            "financial_settlement_beyond_the_bound_provider_observation",
            "correctness_of_unbound_ledger_entries",
            "absence_of_later_chargeback_or_reversal",
        ],
        "risk_tags": ["financial_record", "reconciliation", "data_mutation"],
    },
]


_PAYMENT_LEDGER_FACT_PROFILES = {
    "payment.invoice.pay.v1": {
        "fact_profile_id": "keel.facts.invoice_payment_exact.v1",
        "target_fact_paths": [
            "/invoice_reference_commitment",
            "/merchant_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/invoice_state_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
        ],
        "field_paths": [
            "/invoice_reference_commitment",
            "/payer_reference_commitment",
            "/merchant_reference_commitment",
            "/amount_minor",
            "/currency",
            "/payment_rail",
            "/invoice_status_before",
            "/invoice_state_digest",
            "/idempotency_digest",
            "/max_uses",
        ],
    },
    "ledger.entry.record.v1": {
        "fact_profile_id": "keel.facts.ledger_entry_record_exact.v1",
        "target_fact_paths": [
            "/ledger_reference_commitment",
            "/entry_reference_commitment",
            "/debit_account_commitment",
            "/credit_account_commitment",
        ],
        "material_request_fact_paths": [
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
            "/idempotency_digest",
        ],
        "field_paths": [
            "/ledger_reference_commitment",
            "/entry_reference_commitment",
            "/debit_account_commitment",
            "/credit_account_commitment",
            "/amount_minor",
            "/currency",
            "/entry_effective_at",
            "/ledger_schema_version",
            "/expected_ledger_version",
            "/value_conserved",
            "/accounts_distinct",
            "/idempotency_digest",
        ],
    },
    "payment.reconciliation.record.v1": {
        "fact_profile_id": "keel.facts.payment_reconciliation_exact.v1",
        "target_fact_paths": [
            "/payment_reference_commitment",
            "/ledger_entry_reference_commitment",
        ],
        "material_request_fact_paths": [
            "/provider_observation_digest",
            "/ledger_observation_digest",
            "/preflight_snapshot_digest",
            "/preflight_expires_at",
            "/request_digest",
        ],
        "field_paths": [
            "/payment_reference_commitment",
            "/ledger_entry_reference_commitment",
            "/provider_observation_digest",
            "/ledger_observation_digest",
            "/amount_minor",
            "/currency",
            "/provider_outcome_state",
            "/ledger_entry_state",
            "/amounts_match",
            "/currencies_match",
            "/expected_current_status",
            "/requested_status",
            "/reconciliation_basis_version",
            "/idempotency_digest",
        ],
    },
}


_FACT_FIELD_TYPES = {
    "connector_contract_hash": "digest",
    "tool_schema_hash": "digest",
    "decision_trace_hash": "digest",
    "tool_arguments_hash": "digest",
    "request_digest": "digest",
    "table": "string",
    "rows_digest": "digest",
    "row_count": "integer",
    "schema_version": "string",
    "predicate_digest": "digest",
    "changes_digest": "digest",
    "row_limit": "integer",
    "expected_current_version": "string",
    "migration_id": "string",
    "migration_digest": "digest",
    "from_schema_version": "string",
    "to_schema_version": "string",
    "fields_digest": "digest",
    "restricted_field_classification": "string",
    "amount_minor": "integer",
    "currency": "string",
    "entry_effective_at": "string",
    "value_conserved": "boolean",
    "accounts_distinct": "boolean",
    "amounts_match": "boolean",
    "currencies_match": "boolean",
    "max_uses": "integer",
}


def _fact_field(path: str) -> dict:
    name = path.removeprefix("/")
    value_type = _FACT_FIELD_TYPES.get(name, "string")
    sensitive = name in {"table", "restricted_field_classification"}
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": "sensitive_data" if sensitive else "operational",
        "low_entropy_possible": value_type not in {"digest"},
        "disclosure": {
            "verifier_safe": "omit" if sensitive else "cleartext",
            "authorized": "cleartext",
            "private": "cleartext",
        },
        "retention": {
            "class": "permit_evidence",
            "max_days": None,
            "erasable": False,
            "erasure_action": "retain_signed_value",
        },
        "commitment_method": "signed_cleartext",
    }


def database_fact_profile(consequence: dict, *, schema_digest: str) -> dict:
    contract = _DATABASE_FACT_PROFILES[consequence["consequence_type"]]
    field_paths = [
        "/connector_identity",
        "/connector_contract_hash",
        "/tool_schema_hash",
        "/decision_trace_hash",
        "/tool_arguments_hash",
        "/request_digest",
        *(f"/{name}" for name in consequence["required_material_fields"]),
    ]
    unique_paths = list(dict.fromkeys(field_paths))
    return {
        "fact_profile_id": contract["fact_profile_id"],
        "semantic_ids": [consequence["semantic_id"]],
        "authorized_action": consequence["tool_names"][0],
        "facts_schema": "schemas/database-exact-facts-v1.schema.json",
        "facts_schema_digest": f"sha256:{schema_digest}",
        "target_fact_paths": contract["target_fact_paths"],
        "material_request_fact_paths": contract["material_request_fact_paths"],
        "fields": [_fact_field(path) for path in unique_paths],
        "release_state": "eligible",
    }


def database_fact_vector(consequence: dict) -> dict:
    action = consequence["tool_names"][0]
    common = {
        "version": "keel.database_exact_facts.v1",
        "fact_profile_id": _DATABASE_FACT_PROFILES[
            consequence["consequence_type"]
        ]["fact_profile_id"],
        "action": action,
        "operation": "call.tools",
        "connector_identity": "database.readwrite",
        "connector_contract_hash": "0" * 64,
        "tool_schema_hash": "1" * 64,
        "decision_trace_hash": "2" * 64,
        "tool_arguments_hash": "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "enforcement_mode": "enforced_in_path",
    }
    action_specific = {
        "database.rows.insert": {
            "table": "customer_accounts",
            "rows_digest": "sha256:" + "5" * 64,
            "row_count": 1,
            "schema_version": "2026-08-10.1",
            "table_allowlist_digest": "sha256:" + "6" * 64,
        },
        "database.rows.update": {
            "table": "customer_accounts",
            "predicate_digest": "sha256:" + "5" * 64,
            "predicate_present": True,
            "changes_digest": "sha256:" + "6" * 64,
            "row_limit": 1,
            "expected_current_version": "7",
            "table_allowlist_digest": "sha256:" + "7" * 64,
        },
        "database.rows.delete": {
            "table": "customer_accounts",
            "predicate_digest": "sha256:" + "5" * 64,
            "predicate_present": True,
            "row_limit": 1,
            "expected_current_version": "7",
            "table_allowlist_digest": "sha256:" + "6" * 64,
        },
        "database.migration.apply": {
            "migration_id": "add_customer_risk_tier",
            "migration_digest": "sha256:" + "5" * 64,
            "from_schema_version": "2026-08-10.1",
            "to_schema_version": "2026-08-10.2",
            "migration_allowlist_digest": "sha256:" + "6" * 64,
            "current_schema_version": "2026-08-10.1",
        },
        "database.dataset.export": {
            "table": "customer_accounts",
            "predicate_digest": "sha256:" + "5" * 64,
            "predicate_present": True,
            "fields_digest": "sha256:" + "6" * 64,
            "row_limit": 100,
            "table_allowlist_digest": "sha256:" + "7" * 64,
            "restricted_field_classification": "none",
            "field_classifier_version": "keel.database.fields.v1",
        },
    }
    return {**common, **action_specific[action]}


def _payment_ledger_fact_field(path: str) -> dict:
    name = path.removeprefix("/")
    commitment = name.endswith("_commitment")
    value_type = (
        "commitment"
        if commitment
        else "digest"
        if name.endswith("_digest")
        else _FACT_FIELD_TYPES.get(name, "string")
    )
    classification = (
        "financial"
        if name in {"amount_minor", "currency"}
        else "personal_data"
        if commitment
        else "operational"
    )
    verifier_disclosure = "commitment" if commitment else "cleartext"
    authorized_disclosure = (
        "commitment_with_optional_opening" if commitment else "cleartext"
    )
    return {
        "path": path,
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": classification,
        "low_entropy_possible": value_type not in {"digest"},
        "disclosure": {
            "verifier_safe": verifier_disclosure,
            "authorized": authorized_disclosure,
            "private": authorized_disclosure,
        },
        "retention": {
            "class": "deletable_identity" if commitment else "permit_evidence",
            "max_days": None,
            "erasable": commitment,
            "erasure_action": "erase_opening" if commitment else "retain_signed_value",
        },
        "commitment_method": (
            "keel.salted_sha256_jcs.v1" if commitment else "signed_cleartext"
        ),
    }


def payment_ledger_fact_profile(consequence: dict, *, schema_digest: str) -> dict:
    contract = _PAYMENT_LEDGER_FACT_PROFILES[consequence["consequence_type"]]
    field_paths = [
        "/connector_identity",
        "/connector_contract_hash",
        "/tool_schema_hash",
        "/decision_trace_hash",
        "/tool_arguments_hash",
        "/request_digest",
        "/preflight_observed_at",
        "/preflight_expires_at",
        "/preflight_snapshot_digest",
        *contract["field_paths"],
    ]
    return {
        "fact_profile_id": contract["fact_profile_id"],
        "semantic_ids": [consequence["semantic_id"]],
        "authorized_action": consequence["tool_names"][0],
        "facts_schema": "schemas/payment-ledger-exact-facts-v1.schema.json",
        "facts_schema_digest": f"sha256:{schema_digest}",
        "target_fact_paths": contract["target_fact_paths"],
        "material_request_fact_paths": contract["material_request_fact_paths"],
        "fields": [
            _payment_ledger_fact_field(path)
            for path in dict.fromkeys(field_paths)
        ],
        "release_state": "eligible",
    }


def _commitment(character: str) -> dict[str, str]:
    return {
        "method": "keel.salted_sha256_jcs.v1",
        "digest": "sha256:" + character * 64,
    }


def payment_ledger_fact_vector(consequence: dict) -> dict:
    action = consequence["tool_names"][0]
    common = {
        "version": "keel.payment_ledger_exact_facts.v1",
        "fact_profile_id": _PAYMENT_LEDGER_FACT_PROFILES[
            consequence["consequence_type"]
        ]["fact_profile_id"],
        "action": action,
        "operation": "call.tools",
        "connector_identity": (
            "payments" if action == "payment.invoice.pay" else "database.readwrite"
        ),
        "connector_contract_hash": "0" * 64,
        "tool_schema_hash": "1" * 64,
        "decision_trace_hash": "2" * 64,
        "tool_arguments_hash": "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "enforcement_mode": "enforced_in_path",
        "preflight_observed_at": "2026-07-30T11:59:00Z",
        "preflight_expires_at": "2026-07-30T12:04:00Z",
        "preflight_snapshot_digest": "sha256:" + "a" * 64,
    }
    action_specific = {
        "payment.invoice.pay": {
            "invoice_reference_commitment": _commitment("5"),
            "payer_reference_commitment": _commitment("6"),
            "merchant_reference_commitment": _commitment("7"),
            "amount_minor": 12500,
            "currency": "USD",
            "payment_rail": "stripe.invoice",
            "invoice_status_before": "open",
            "invoice_state_digest": "sha256:" + "8" * 64,
            "idempotency_digest": "sha256:" + "9" * 64,
            "max_uses": 1,
        },
        "ledger.entry.record": {
            "ledger_reference_commitment": _commitment("5"),
            "entry_reference_commitment": _commitment("6"),
            "debit_account_commitment": _commitment("7"),
            "credit_account_commitment": _commitment("8"),
            "amount_minor": 12500,
            "currency": "USD",
            "entry_effective_at": "2026-08-10T08:00:00Z",
            "ledger_schema_version": "keel.demo.ledger.v1",
            "expected_ledger_version": "7",
            "value_conserved": True,
            "accounts_distinct": True,
            "idempotency_digest": "sha256:" + "9" * 64,
        },
        "payment.reconciliation.record": {
            "payment_reference_commitment": _commitment("5"),
            "ledger_entry_reference_commitment": _commitment("6"),
            "provider_observation_digest": "sha256:" + "7" * 64,
            "ledger_observation_digest": "sha256:" + "8" * 64,
            "amount_minor": 12500,
            "currency": "USD",
            "provider_outcome_state": "completed",
            "ledger_entry_state": "posted",
            "amounts_match": True,
            "currencies_match": True,
            "expected_current_status": "unreconciled",
            "requested_status": "reconciled",
            "reconciliation_basis_version": "keel.payment_reconciliation.v1",
            "idempotency_digest": "sha256:" + "9" * 64,
        },
    }
    return {**common, **action_specific[action]}


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

    facts_schema_digest = sha256("schemas/database-exact-facts-v1.schema.json")
    fact_registry = copy.deepcopy(load("fact_profiles/v3.json"))
    fact_registry["$schema"] = "./v4.schema.json"
    fact_registry["version"] = "keel.fact_profile_registry.v4"
    fact_registry["profiles"].extend(
        database_fact_profile(item, schema_digest=facts_schema_digest)
        for item in consequence_registry["consequences"]
    )
    write("fact_profiles/v4.json", fact_registry)

    fact_schema = copy.deepcopy(load("fact_profiles/v3.schema.json"))
    fact_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v4.schema.json"
    )
    fact_schema["title"] = "Keel Permit fact profile registry v4"
    fact_schema["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v4"
    )
    write("fact_profiles/v4.schema.json", fact_schema)

    semantic_v6 = copy.deepcopy(semantic)
    semantic_v6["$schema"] = "./v6.schema.json"
    semantic_v6["version"] = "keel.semantic_selector_registry.v6"
    fact_profile_by_semantic = {
        item["semantic_ids"][0]: item["fact_profile_id"]
        for item in fact_registry["profiles"]
        if item.get("semantic_ids")
    }
    for entry in semantic_v6["entries"]:
        fact_profile_id = fact_profile_by_semantic.get(entry.get("semantic_id"))
        if fact_profile_id is not None:
            entry["fact_profile_id"] = fact_profile_id
    write("semantic_registry/v6.json", semantic_v6)

    semantic_v6_schema = copy.deepcopy(semantic_schema)
    semantic_v6_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v6.schema.json"
    )
    semantic_v6_schema["title"] = "Keel Permit semantic selector registry v6"
    semantic_v6_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v6"
    )
    write("semantic_registry/v6.schema.json", semantic_v6_schema)

    presentation_v5 = copy.deepcopy(presentation)
    presentation_v5["$schema"] = "./v5.schema.json"
    presentation_v5["version"] = "keel.presentation_registry.v5"
    presentation_v5["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v6"
    )
    write("presentation_registry/v5.json", presentation_v5)

    presentation_v5_schema = copy.deepcopy(presentation_schema)
    presentation_v5_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/presentation_registry/v5.schema.json"
    )
    presentation_v5_schema["title"] = "Keel Permit presentation registry v5"
    presentation_v5_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v5"
    )
    presentation_v5_schema["properties"]["semantic_registry_version"]["const"] = (
        "keel.semantic_selector_registry.v6"
    )
    write("presentation_registry/v5.schema.json", presentation_v5_schema)

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

    exact_vectors = copy.deepcopy(consequence_vectors)
    exact_vectors["version"] = "keel.consequence_registry.test_vectors.v2"
    exact_vectors["semantic_registry_version"] = semantic_v6["version"]
    exact_vectors["presentation_registry_version"] = presentation_v5["version"]
    for vector in exact_vectors["vectors"]:
        vector["expected_fact_profile_id"] = fact_profile_by_semantic[
            vector["expected_semantic_id"]
        ]
        consequence = next(
            item
            for item in consequence_registry["consequences"]
            if item["consequence_type"] == vector["id"]
        )
        vector["valid_authorization_facts"] = database_fact_vector(consequence)
    write("consequence_registry/test-vectors/v2.json", exact_vectors)

    consequence_v2 = copy.deepcopy(consequence_registry)
    consequence_v2["$schema"] = "./v2.schema.json"
    consequence_v2["version"] = "keel.consequence_registry.v2"
    consequence_v2["consequences"].extend(copy.deepcopy(_PAYMENT_LEDGER_CONSEQUENCES))
    write("consequence_registry/v2.json", consequence_v2)

    consequence_v2_schema = copy.deepcopy(load("consequence_registry/v1.schema.json"))
    consequence_v2_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "consequence_registry/v2.schema.json"
    )
    consequence_v2_schema["title"] = "Keel consequence registry v2"
    consequence_v2_schema["properties"]["version"]["const"] = (
        "keel.consequence_registry.v2"
    )
    write("consequence_registry/v2.schema.json", consequence_v2_schema)

    payment_ledger_schema_digest = sha256(
        "schemas/payment-ledger-exact-facts-v1.schema.json"
    )
    fact_registry_v5 = copy.deepcopy(fact_registry)
    fact_registry_v5["$schema"] = "./v5.schema.json"
    fact_registry_v5["version"] = "keel.fact_profile_registry.v5"
    fact_registry_v5["profiles"].extend(
        payment_ledger_fact_profile(
            item,
            schema_digest=payment_ledger_schema_digest,
        )
        for item in _PAYMENT_LEDGER_CONSEQUENCES
    )
    write("fact_profiles/v5.json", fact_registry_v5)

    fact_schema_v5 = copy.deepcopy(fact_schema)
    fact_schema_v5["$id"] = (
        "https://github.com/keelapi/keel-permit/fact_profiles/v5.schema.json"
    )
    fact_schema_v5["title"] = "Keel Permit fact profile registry v5"
    fact_schema_v5["properties"]["version"]["const"] = (
        "keel.fact_profile_registry.v5"
    )
    write("fact_profiles/v5.schema.json", fact_schema_v5)

    semantic_v7 = copy.deepcopy(semantic_v6)
    semantic_v7["$schema"] = "./v7.schema.json"
    semantic_v7["version"] = "keel.semantic_selector_registry.v7"
    for consequence in _PAYMENT_LEDGER_CONSEQUENCES:
        entry = semantic_entry(consequence)
        entry["fact_profile_id"] = _PAYMENT_LEDGER_FACT_PROFILES[
            consequence["consequence_type"]
        ]["fact_profile_id"]
        semantic_v7["entries"].append(entry)
    write("semantic_registry/v7.json", semantic_v7)

    semantic_v7_schema = copy.deepcopy(semantic_v6_schema)
    semantic_v7_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/semantic_registry/v7.schema.json"
    )
    semantic_v7_schema["title"] = "Keel Permit semantic selector registry v7"
    semantic_v7_schema["properties"]["version"]["const"] = (
        "keel.semantic_selector_registry.v7"
    )
    write("semantic_registry/v7.schema.json", semantic_v7_schema)

    presentation_v6 = copy.deepcopy(presentation_v5)
    presentation_v6["$schema"] = "./v6.schema.json"
    presentation_v6["version"] = "keel.presentation_registry.v6"
    presentation_v6["semantic_registry_version"] = (
        "keel.semantic_selector_registry.v7"
    )
    presentation_v6["profiles"].extend(
        presentation_profile(item) for item in _PAYMENT_LEDGER_CONSEQUENCES
    )
    write("presentation_registry/v6.json", presentation_v6)

    presentation_v6_schema = copy.deepcopy(presentation_v5_schema)
    presentation_v6_schema["$id"] = (
        "https://github.com/keelapi/keel-permit/"
        "presentation_registry/v6.schema.json"
    )
    presentation_v6_schema["title"] = "Keel Permit presentation registry v6"
    presentation_v6_schema["properties"]["version"]["const"] = (
        "keel.presentation_registry.v6"
    )
    presentation_v6_schema["properties"]["semantic_registry_version"][
        "const"
    ] = "keel.semantic_selector_registry.v7"
    write("presentation_registry/v6.schema.json", presentation_v6_schema)

    profile_by_semantic_v5 = {
        item["semantic_ids"][0]: item["fact_profile_id"]
        for item in fact_registry_v5["profiles"]
        if item.get("semantic_ids")
    }
    exact_vectors_v3 = {
        "version": "keel.consequence_registry.test_vectors.v3",
        "consequence_registry_version": consequence_v2["version"],
        "semantic_registry_version": semantic_v7["version"],
        "presentation_registry_version": presentation_v6["version"],
        "vectors": [],
    }
    for consequence in consequence_v2["consequences"]:
        action = consequence["tool_names"][0]
        facts = (
            database_fact_vector(consequence)
            if consequence["consequence_type"] in _DATABASE_FACT_PROFILES
            else payment_ledger_fact_vector(consequence)
        )
        exact_vectors_v3["vectors"].append(
            {
                "id": consequence["consequence_type"],
                "candidate": {
                    "trusted_source_kind": "action_verb_execute",
                    "permit_product": "permit",
                    "action_name": action,
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
                "expected_fact_profile_id": profile_by_semantic_v5[
                    consequence["semantic_id"]
                ],
                "valid_authorization_facts": facts,
            }
        )
    write("consequence_registry/test-vectors/v3.json", exact_vectors_v3)

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
        (
            "keel.permit.database_exact_facts.v1.schema",
            "schemas/database-exact-facts-v1.schema.json",
        ),
        ("keel.permit.fact_profile_registry.v4", "fact_profiles/v4.json"),
        (
            "keel.permit.fact_profile_registry.v4.schema",
            "fact_profiles/v4.schema.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v6",
            "semantic_registry/v6.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v6.schema",
            "semantic_registry/v6.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v5",
            "presentation_registry/v5.json",
        ),
        (
            "keel.permit.presentation_registry.v5.schema",
            "presentation_registry/v5.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v2",
            "consequence_registry/test-vectors/v2.json",
        ),
        (
            "keel.permit.consequence_registry.v2",
            "consequence_registry/v2.json",
        ),
        (
            "keel.permit.consequence_registry.v2.schema",
            "consequence_registry/v2.schema.json",
        ),
        (
            "keel.permit.payment_ledger_exact_facts.v1.schema",
            "schemas/payment-ledger-exact-facts-v1.schema.json",
        ),
        ("keel.permit.fact_profile_registry.v5", "fact_profiles/v5.json"),
        (
            "keel.permit.fact_profile_registry.v5.schema",
            "fact_profiles/v5.schema.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v7",
            "semantic_registry/v7.json",
        ),
        (
            "keel.permit.semantic_selector_registry.v7.schema",
            "semantic_registry/v7.schema.json",
        ),
        (
            "keel.permit.presentation_registry.v6",
            "presentation_registry/v6.json",
        ),
        (
            "keel.permit.presentation_registry.v6.schema",
            "presentation_registry/v6.schema.json",
        ),
        (
            "permit-to-x.test-vectors.consequence-registry.v3",
            "consequence_registry/test-vectors/v3.json",
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
