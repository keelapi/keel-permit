#!/usr/bin/env python3
"""Build the additive Stripe payout-account-change exact-action artifacts.

One new exact action, ``stripe.external_account.create``: a Stripe test-mode
Connect request that attaches a new bank account to a connected account and
makes it the default payout destination for its currency
(``POST /v1/accounts/{account}/external_accounts`` with
``default_for_currency=true``). It moves no money in the call; it changes where
future payouts go, which is the classic account-takeover target.

The builder is additive and deterministic:

- ``schemas/stripe-payout-account-change-exact-facts-v1.schema.json`` (new)
- ``semantic_registry/v24.json`` = every v23 entry byte-for-byte + one entry
- ``fact_profiles/v21.json`` = every v20 profile byte-for-byte + one profile
- ``fact_profiles/test-vectors/stripe-payout-account-change-v1.json``
- the matching ``artifact-manifests/permit-to-x-v1.json`` entries

Historical registry bytes are never rewritten. Run with ``--check`` to prove the
committed artifacts equal a fresh build.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

ACTION = "stripe.external_account.create"
SEMANTIC_ID = "keel.action.stripe_connect_payout_account_change.v1"
FACT_PROFILE_ID = "keel.facts.stripe_payout_account_change_exact.v1"
FACTS_VERSION = "keel.stripe_payout_account_change_exact_facts.v1"
SCHEMA_PATH = "schemas/stripe-payout-account-change-exact-facts-v1.schema.json"
VECTORS_PATH = "fact_profiles/test-vectors/stripe-payout-account-change-v1.json"
SEMANTIC_PREVIOUS, SEMANTIC_NEXT = 23, 24
FACTS_PREVIOUS, FACTS_NEXT = 20, 21

#: Where the change request reached the agent. Attested by the gateway
#: deployment that mints the preflight, never by the agent's arguments.
CHANGE_CHANNELS = ("api", "chat", "email", "staff_console", "voice_call")

_DIGEST = {"$ref": "#/$defs/digest"}
_RAW_DIGEST = {"$ref": "#/$defs/rawDigest"}
_TIMESTAMP = {"$ref": "#/$defs/timestamp"}
_COMMITMENT = {"$ref": "#/$defs/saltedCommitment"}

# (path, schema, value_type, classification, commitment?, in target, in material)
_FIELDS: tuple[tuple[str, dict[str, Any], str, str, bool, bool, bool], ...] = (
    ("version", {"const": FACTS_VERSION}, "string", "operational", False, False, False),
    ("fact_profile_id", {"const": FACT_PROFILE_ID}, "string", "operational", False, False, False),
    ("action", {"const": ACTION}, "string", "operational", False, False, False),
    ("operation", {"const": "call.tools"}, "string", "operational", False, False, False),
    ("connector_identity", {"const": "stripe"}, "string", "operational", False, False, False),
    ("connector_contract_hash", _RAW_DIGEST, "digest", "operational", False, False, False),
    ("tool_schema_hash", _RAW_DIGEST, "digest", "operational", False, False, False),
    ("decision_trace_hash", _RAW_DIGEST, "digest", "operational", False, False, False),
    ("tool_arguments_hash", _RAW_DIGEST, "digest", "operational", False, False, False),
    ("request_digest", _DIGEST, "digest", "operational", False, False, True),
    ("enforcement_mode", {"const": "enforced_in_path"}, "string", "operational", False, False, False),
    ("provider_environment", {"const": "provider_sandbox"}, "string", "operational", False, False, True),
    (
        "provider_api_version",
        {"type": "string", "minLength": 1, "maxLength": 128},
        "string",
        "operational",
        False,
        False,
        False,
    ),
    ("preflight_observed_at", _TIMESTAMP, "timestamp", "operational", False, False, False),
    ("preflight_expires_at", _TIMESTAMP, "timestamp", "operational", False, False, True),
    ("preflight_snapshot_digest", _DIGEST, "digest", "operational", False, False, True),
    ("idempotency_digest", _DIGEST, "digest", "operational", False, False, True),
    ("max_uses", {"const": 1}, "integer", "operational", False, False, True),
    ("provider_instance_reference_commitment", _COMMITMENT, "commitment", "personal_data", True, True, False),
    ("target_is_dedicated_demo", {"const": True}, "boolean", "operational", False, False, True),
    ("platform_account_digest", _DIGEST, "digest", "operational", False, False, True),
    # The customer whose payout destination changes: the Stripe connected account.
    ("connected_account_reference_commitment", _COMMITMENT, "commitment", "personal_data", True, True, False),
    ("connected_account_state_digest", _DIGEST, "digest", "operational", False, False, True),
    # The tokenized bank account the request attaches (a Stripe btok_ token).
    ("external_account_token_reference_commitment", _COMMITMENT, "commitment", "personal_data", True, True, False),
    # Provider-read facts about the new bank account, from Stripe's token object.
    ("new_account_fingerprint_commitment", _COMMITMENT, "commitment", "personal_data", True, False, True),
    ("new_account_is_new_to_customer", {"type": "boolean"}, "boolean", "financial", False, False, True),
    (
        "new_account_last4",
        {"type": "string", "pattern": "^[0-9]{4}$"},
        "string",
        "financial",
        False,
        False,
        True,
    ),
    (
        "new_account_country",
        {"type": "string", "pattern": "^[A-Z]{2}$"},
        "string",
        "financial",
        False,
        False,
        True,
    ),
    (
        "new_account_currency",
        {"type": "string", "pattern": "^[A-Z]{3}$"},
        "string",
        "financial",
        False,
        False,
        True,
    ),
    # The account it replaces as the default for that currency, as Stripe lists it.
    (
        "previous_default_account_last4",
        {"type": "string", "pattern": "^(?:[0-9]{4}|none)$"},
        "string",
        "financial",
        False,
        False,
        True,
    ),
    (
        "existing_external_account_count",
        {"type": "integer", "minimum": 0, "maximum": 100},
        "integer",
        "operational",
        False,
        False,
        True,
    ),
    ("default_for_currency", {"const": True}, "boolean", "operational", False, False, True),
    ("change_channel", {"enum": list(CHANGE_CHANNELS)}, "string", "operational", False, False, True),
)


def _load(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_schema() -> dict[str, Any]:
    goal3a = _load("schemas/goal3a-portfolio-exact-facts-v1.schema.json")
    defs = {
        key: copy.deepcopy(goal3a["$defs"][key])
        for key in ("digest", "rawDigest", "timestamp", "saltedCommitment")
    }
    defs["stripe_external_account_create"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [path for path, *_ in _FIELDS],
        "properties": {path: copy.deepcopy(schema) for path, schema, *_ in _FIELDS},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://github.com/keelapi/keel-permit/"
            "schemas/stripe-payout-account-change-exact-facts-v1.schema.json"
        ),
        "title": "Keel exact Stripe payout-account-change facts v1",
        "oneOf": [{"$ref": "#/$defs/stripe_external_account_create"}],
        "$defs": defs,
    }


def _field(path: str, value_type: str, classification: str, commitment: bool) -> dict[str, Any]:
    if commitment:
        return {
            "path": f"/{path}",
            "value_type": value_type,
            "required_for_authorization": True,
            "classification": classification,
            "low_entropy_possible": True,
            "disclosure": {
                "verifier_safe": "commitment",
                "authorized": "commitment_with_optional_opening",
                "private": "commitment_with_optional_opening",
            },
            "retention": {
                "class": "deletable_identity",
                "max_days": None,
                "erasable": True,
                "erasure_action": "erase_opening",
            },
            "commitment_method": "keel.salted_sha256_jcs.v1",
        }
    return {
        "path": f"/{path}",
        "value_type": value_type,
        "required_for_authorization": True,
        "classification": classification,
        "low_entropy_possible": value_type not in {"digest"},
        "disclosure": {
            "verifier_safe": "cleartext",
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


# Fields the profile does not list: constants every exact profile omits.
_PROFILE_OMITTED = frozenset({"version", "fact_profile_id", "action", "operation", "enforcement_mode"})


def build_profile(schema_text: str) -> dict[str, Any]:
    return {
        "fact_profile_id": FACT_PROFILE_ID,
        "semantic_ids": [SEMANTIC_ID],
        "authorized_action": ACTION,
        "facts_schema": SCHEMA_PATH,
        "facts_schema_digest": "sha256:" + _sha256(schema_text),
        "target_fact_paths": [f"/{path}" for path, *rest in _FIELDS if rest[4]],
        "material_request_fact_paths": [f"/{path}" for path, *rest in _FIELDS if rest[5]],
        "fields": [
            _field(path, value_type, classification, commitment)
            for path, _, value_type, classification, commitment, _, _ in _FIELDS
            if path not in _PROFILE_OMITTED
        ],
        "release_state": "eligible",
    }


def build_semantic_entry() -> dict[str, Any]:
    return {
        "semantic_id": SEMANTIC_ID,
        "semantic_kind": "exact_action",
        "trusted_source_kinds": ["action_verb_execute"],
        "match": {
            "action_names": [ACTION],
            "operations": ["call.tools"],
            "allowed_chain_roles": ["session_root", "action_child"],
            "required_evidence_capabilities": ["authorization", "dispatch", "provider_outcome"],
        },
        "excluded_permit_products": ["cost_permit"],
        "release_state": "eligible",
        "fact_profile_id": FACT_PROFILE_ID,
    }


def _successor_schema(directory: str, previous: int, nxt: int, label: str, version_prefix: str) -> str:
    text = (ROOT / f"{directory}/v{previous}.schema.json").read_text(encoding="utf-8")
    replacements = (
        (f"{directory}/v{previous}.schema.json", f"{directory}/v{nxt}.schema.json"),
        (f"{label} v{previous}", f"{label} v{nxt}"),
        (f'"{version_prefix}.v{previous}"', f'"{version_prefix}.v{nxt}"'),
    )
    for old, new in replacements:
        if text.count(old) != 1:
            raise SystemExit(f"{directory} v{previous} schema: expected exactly one {old!r}")
        text = text.replace(old, new)
    return text


def _successor_registry(
    directory: str, previous: int, nxt: int, field: str, version_prefix: str, addition: dict[str, Any]
) -> str:
    registry = _load(f"{directory}/v{previous}.json")
    registry["$schema"] = f"./v{nxt}.schema.json"
    registry["version"] = f"{version_prefix}.v{nxt}"
    registry[field] = [*registry[field], addition]
    return _dump(registry)


def _vector_commitment(label: str) -> dict[str, str]:
    return {"method": "keel.salted_sha256_jcs.v1", "digest": "sha256:" + _sha256(f"synthetic:{label}")}


def build_vectors() -> str:
    facts = {
        "version": FACTS_VERSION,
        "fact_profile_id": FACT_PROFILE_ID,
        "action": ACTION,
        "operation": "call.tools",
        "connector_identity": "stripe",
        "connector_contract_hash": "c" * 64,
        "tool_schema_hash": "a" * 64,
        "decision_trace_hash": "d" * 64,
        "tool_arguments_hash": "b" * 64,
        "request_digest": "sha256:" + "e" * 64,
        "enforcement_mode": "enforced_in_path",
        "provider_environment": "provider_sandbox",
        "provider_api_version": "stripe-2025-12-15.clover",
        "preflight_observed_at": "2026-11-27T18:00:00Z",
        "preflight_expires_at": "2026-11-27T18:04:00Z",
        "preflight_snapshot_digest": "sha256:" + "f" * 64,
        "idempotency_digest": "sha256:" + _sha256("synthetic:idempotency"),
        "max_uses": 1,
        "provider_instance_reference_commitment": _vector_commitment("provider_instance"),
        "target_is_dedicated_demo": True,
        "platform_account_digest": "sha256:" + _sha256("synthetic:platform"),
        "connected_account_reference_commitment": _vector_commitment("connected_account"),
        "connected_account_state_digest": "sha256:" + _sha256("synthetic:connected_state"),
        "external_account_token_reference_commitment": _vector_commitment("bank_token"),
        "new_account_fingerprint_commitment": _vector_commitment("fingerprint"),
        "new_account_is_new_to_customer": True,
        "new_account_last4": "6789",
        "new_account_country": "US",
        "new_account_currency": "USD",
        "previous_default_account_last4": "1116",
        "existing_external_account_count": 1,
        "default_for_currency": True,
        "change_channel": "voice_call",
    }
    return _dump(
        {
            "scope": (
                "synthetic schema-validation examples; not issued Permits, provider "
                "evidence or a live authorization result"
            ),
            "cases": [{"action": ACTION, "facts": facts}],
        }
    )


def build() -> dict[str, str]:
    schema_text = _dump(build_schema())
    outputs = {
        SCHEMA_PATH: schema_text,
        f"semantic_registry/v{SEMANTIC_NEXT}.schema.json": _successor_schema(
            "semantic_registry",
            SEMANTIC_PREVIOUS,
            SEMANTIC_NEXT,
            "Keel Permit semantic selector registry",
            "keel.semantic_selector_registry",
        ),
        f"semantic_registry/v{SEMANTIC_NEXT}.json": _successor_registry(
            "semantic_registry",
            SEMANTIC_PREVIOUS,
            SEMANTIC_NEXT,
            "entries",
            "keel.semantic_selector_registry",
            build_semantic_entry(),
        ),
        f"fact_profiles/v{FACTS_NEXT}.schema.json": _successor_schema(
            "fact_profiles",
            FACTS_PREVIOUS,
            FACTS_NEXT,
            "Keel Permit fact profile registry",
            "keel.fact_profile_registry",
        ),
        f"fact_profiles/v{FACTS_NEXT}.json": _successor_registry(
            "fact_profiles",
            FACTS_PREVIOUS,
            FACTS_NEXT,
            "profiles",
            "keel.fact_profile_registry",
            build_profile(schema_text),
        ),
        VECTORS_PATH: build_vectors(),
    }
    manifest_ids = {
        f"semantic_registry/v{SEMANTIC_NEXT}.json": f"keel.permit.semantic_selector_registry.v{SEMANTIC_NEXT}",
        f"semantic_registry/v{SEMANTIC_NEXT}.schema.json": (
            f"keel.permit.semantic_selector_registry.v{SEMANTIC_NEXT}.schema"
        ),
        f"fact_profiles/v{FACTS_NEXT}.json": f"keel.permit.fact_profile_registry.v{FACTS_NEXT}",
        f"fact_profiles/v{FACTS_NEXT}.schema.json": f"keel.permit.fact_profile_registry.v{FACTS_NEXT}.schema",
        SCHEMA_PATH: "keel.permit.stripe_payout_account_change_exact_facts.v1.schema",
        VECTORS_PATH: "keel.permit.stripe_payout_account_change_exact_facts.v1.test_vectors",
    }
    manifest = _load("artifact-manifests/permit-to-x-v1.json")
    by_path = {entry["path"]: entry for entry in manifest["artifacts"]}
    for path, artifact_id in manifest_ids.items():
        entry = {"id": artifact_id, "path": path, "sha256": _sha256(outputs[path])}
        if path in by_path:
            by_path[path].clear()
            by_path[path].update(entry)
        else:
            manifest["artifacts"].append(entry)
    outputs["artifact-manifests/permit-to-x-v1.json"] = _dump(manifest)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if committed bytes differ")
    args = parser.parse_args()
    outputs = build()
    stale = []
    for path, text in outputs.items():
        target = ROOT / path
        current = target.read_text(encoding="utf-8") if target.exists() else None
        if current == text:
            continue
        if args.check:
            stale.append(path)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            print(f"wrote {path}")
    if stale:
        print("stale payout-account-change artifacts: " + ", ".join(stale))
        return 1
    if args.check:
        print("Payout-account-change artifacts match a fresh build.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
