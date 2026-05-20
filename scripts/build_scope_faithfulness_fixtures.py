#!/usr/bin/env python3
"""Build the Step 2 scope-faithfulness baseline fixtures.

The script is deterministic by construction: keys are derived from fixed
test-only Ed25519 seeds, timestamps and UUIDs are constants, JSON output uses
sorted keys plus fixed indentation, and all hashes/signatures are recomputed
from those stable bytes. Re-running the script from a clean checkout rewrites
the same fixture bytes.

Future negative and edge fixtures should extend the declarative FIXTURES table
instead of hand-editing committed artifacts.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = ROOT / "test-vectors" / "verifier_claims" / "v0"
FIXTURE_ROOT = CORPUS_ROOT / "fixtures"
TRUST_ROOT = CORPUS_ROOT / "trust_roots" / "step2-scope-faithfulness-trust-root.json"

PROJECT_ID = "00000000-0000-0000-0000-000000000001"
CHAIN_SCOPE = f"project:{PROJECT_ID}"
CHECKPOINT_ID = "22222222-3333-4444-5555-666666666666"
SIGNED_AT = "2026-05-19T12:00:00Z"
GENESIS_PREV_HASH = "0" * 64
EMPTY_TREE_HASH = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

EXPORT_SEED = bytes.fromhex("11" * 32)
SCOPE_CHECKPOINT_SEED = bytes.fromhex("22" * 32)

SUPPORTED_PREDICATE_KINDS = [
    "project_id",
    "permit_id",
    "request_id",
    "event_type",
    "category",
    "severity",
    "decision_type",
    "policy_id",
    "provider",
    "sequence_number",
    "created_at",
    "occurred_at",
    "section",
    "export_type",
]

LOOKUP_CHAIN_TEXT_BY_KIND = {
    "project_id": "1. `entry.project_id`; 2. `entry.payload_json.project_id`; 3. `entry.payload_json.project.id`; 4. `entry.payload_json.export.project_id`",
    "permit_id": "1. `entry.permit_id`; 2. `entry.resource_id` when `entry.resource_type == \"permit\"`; 3. `entry.payload_json.permit_id`; 4. `entry.payload_json.permit_uuid`; 5. `entry.payload_json.permit.id`",
    "request_id": "1. `entry.request_id`; 2. `entry.payload_json.request_id`; 3. `entry.payload_json.execution.request_id`; 4. `entry.payload_json.permit.request_id`",
    "event_type": "1. `entry.event_type`; 2. `entry.payload_json.event_type`",
    "category": "1. `entry.category`; 2. `entry.payload_json.category`; 3. `entry.payload_json.classification.category`; 4. `entry.payload_json.policy.category`",
    "severity": "1. `entry.severity`; 2. `entry.payload_json.severity`; 3. `entry.payload_json.classification.severity`; 4. `entry.payload_json.incident.severity`",
    "decision_type": "1. `entry.decision_type`; 2. `entry.payload_json.decision_type`; 3. `entry.payload_json.decision.type`; 4. `entry.payload_json.permit.decision_type`",
    "policy_id": "1. `entry.policy_id`; 2. `entry.payload_json.policy_id`; 3. `entry.payload_json.policy.id`; 4. `entry.payload_json.permit.policy_id`",
    "provider": "1. `entry.provider`; 2. `entry.payload_json.provider`; 3. `entry.payload_json.model_provider`; 4. `entry.payload_json.metadata.provider`; 5. `entry.payload_json.execution.provider`",
    "sequence_number": "1. `entry.sequence_number`",
    "created_at": "1. `entry.created_at`",
    "occurred_at": "1. `entry.occurred_at`; 2. `entry.payload_json.occurred_at`; 3. `entry.payload_json.event_time`; 4. `entry.payload_json.timestamp`; 5. `entry.created_at`",
    "section": "1. `entry.section`; 2. `entry.payload_json.section`; 3. `entry.payload_json.export_section`; 4. `entry.payload_json.report.section`",
    "export_type": "1. `entry.export_type`; 2. `entry.payload_json.export_type`; 3. `entry.payload_json.export.type`",
}


@dataclass(frozen=True)
class FixtureSpec:
    fixture_id: str
    title: str
    purpose: str
    predicate: dict[str, Any]
    raw_filters: dict[str, Any]
    scope_kind: str
    population_label: str
    presentation_policy: dict[str, Any]


FIXTURES = [
    FixtureSpec(
        fixture_id="scope-faithfulness-valid-full-chain",
        title="Valid scope-faithful full project chain",
        purpose="Full project chain from genesis to checkpoint head; predicate project_id.",
        predicate={
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {"project_id": PROJECT_ID},
            "ranges": {},
        },
        raw_filters={"project_id": PROJECT_ID},
        scope_kind="declared_population",
        population_label="All project-chain records through checkpoint",
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "none",
            "policy_parameters": {},
        },
    ),
    FixtureSpec(
        fixture_id="scope-faithfulness-valid-permit-id-sample",
        title="Valid declared sample by permit_id",
        purpose="Selective declared sample by permit_id; sidecar matching count equals disclosed records.",
        predicate={
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {"permit_id": "permit-alpha"},
            "ranges": {},
        },
        raw_filters={"permit_id": "permit-alpha"},
        scope_kind="declared_sample",
        population_label="Records for permit-alpha",
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "none",
            "policy_parameters": {},
        },
    ),
    FixtureSpec(
        fixture_id="scope-faithfulness-valid-event-type",
        title="Valid declared sample by event_type",
        purpose="Selective disclosure by event_type.",
        predicate={
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {"event_type": "permit.created"},
            "ranges": {},
        },
        raw_filters={"event_type": "permit.created"},
        scope_kind="declared_sample",
        population_label="permit.created events",
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "none",
            "policy_parameters": {},
        },
    ),
    FixtureSpec(
        fixture_id="scope-faithfulness-valid-created-at-range",
        title="Valid declared sample by created_at range",
        purpose="Time-range predicate with created_at.gte/lt.",
        predicate={
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {},
            "ranges": {
                "created_at": {
                    "gte": "2026-05-19T10:00:03.000000Z",
                    "lt": "2026-05-19T10:00:07.000000Z",
                }
            },
        },
        raw_filters={
            "created_at": {
                "gte": "2026-05-19T10:00:03.000000Z",
                "lt": "2026-05-19T10:00:07.000000Z",
            }
        },
        scope_kind="declared_sample",
        population_label="Records created from 10:00:03Z up to 10:00:07Z",
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "none",
            "policy_parameters": {},
        },
    ),
    FixtureSpec(
        fixture_id="scope-faithfulness-valid-provider",
        title="Valid declared sample by provider",
        purpose="Selective disclosure by provider metadata.",
        predicate={
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {"provider": "anthropic"},
            "ranges": {},
        },
        raw_filters={"provider": "anthropic"},
        scope_kind="declared_sample",
        population_label="Anthropic provider records",
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "none",
            "policy_parameters": {},
        },
    ),
    FixtureSpec(
        fixture_id="scope-faithfulness-valid-presentation-policy-restricted",
        title="Valid declared sample with presentation policy redaction",
        purpose="Predicate plus presentation_policy redaction; verifier checks declared policy application, not entitlement correctness.",
        predicate={
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {"category": "security"},
            "ranges": {},
        },
        raw_filters={
            "category": "security",
            "presentation_policy": {
                "policy_kind": "field_redaction",
                "redacted_fields": ["payload_json.details"],
            },
        },
        scope_kind="declared_sample",
        population_label="Security category records with details redacted",
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "field_redaction",
            "policy_parameters": {"redacted_fields": ["payload_json.details"]},
        },
    ),
]


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pretty_json_bytes(value))


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    return f"sha256:{sha256_hex(data)}"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"ed25519:{b64(raw)}"


def key_id(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"sha256:{sha256_hex(raw)[:32]}"


def sign_b64(key: Ed25519PrivateKey, message: bytes) -> str:
    return f"ed25519:{b64(key.sign(message))}"


def registry_ref() -> dict[str, str]:
    data = (ROOT / "claim_registry" / "v0.json").read_bytes()
    return {
        "id": "keel.verifier_claim_registry.v0",
        "hash": sha256_prefixed(data),
        "content_b64": b64(data),
    }


def semantic_ref(path: str, semantic_id: str, *, canonical_hash: bool = False) -> dict[str, str]:
    full_path = ROOT / path
    if canonical_hash:
        obj = load_json(full_path)
        data = canonical_json_bytes(obj)
    else:
        data = full_path.read_bytes()
    return {
        "id": semantic_id,
        "hash": sha256_prefixed(data),
        "content_b64": b64(data),
    }


def export_semantics_pins() -> dict[str, Any]:
    artifacts = [
        semantic_ref("semantics/export_manifest/integrity_v1.json", "keel.export_manifest.integrity.v1"),
        semantic_ref("semantics/governance_chain/record_hash_v1.json", "keel.governance_chain.record_hash.v1"),
        semantic_ref("semantics/checkpoint/composite_hash_v1.json", "keel.checkpoint.composite_hash.v1"),
        semantic_ref("semantics/checkpoint/signature_v1.json", "keel.checkpoint.signature.v1"),
        semantic_ref("semantics/scope_state/merkle_v1.json", "keel.scope_state.merkle.v1", canonical_hash=True),
        semantic_ref("semantics/scope_state/sidecar_format_v1.json", "keel.scope_state.sidecar_format.v1", canonical_hash=True),
        semantic_ref("semantics/export/scope_faithfulness_v1.json", "keel.export.scope_faithfulness.v1", canonical_hash=True),
    ]
    return {"version": "keel-semantics-pins.v0", "mode": "pinned", "artifacts": artifacts}


def checkpoint_semantics_pins() -> dict[str, Any]:
    artifacts = [
        semantic_ref("semantics/checkpoint/composite_hash_v1.json", "keel.checkpoint.composite_hash.v1"),
        semantic_ref("semantics/checkpoint/signature_v1.json", "keel.checkpoint.signature.v1"),
    ]
    return {"version": "keel-semantics-pins.v0", "mode": "pinned", "artifacts": artifacts}


def parse_record_hash_time(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    return parsed.replace(tzinfo=None)


def record_hash_v1(entry: dict[str, Any]) -> str:
    timestamp = parse_record_hash_time(str(entry["created_at"])).strftime("%Y-%m-%dT%H:%M:%S.%f")
    parts = [
        str(entry["event_id"]),
        str(entry["event_type"]),
        str(entry.get("resource_type") or ""),
        str(entry.get("resource_id") or ""),
        str(entry.get("outcome") or ""),
        str(entry["severity"]),
        timestamp,
        str(entry["prev_hash"]),
        str(entry["sequence_number"]),
    ]
    return sha256_hex("|".join(parts).encode("utf-8"))


def make_source_chain() -> list[dict[str, Any]]:
    base = [
        {
            "event_id": "evt_step2_001",
            "event_type": "permit.created",
            "resource_type": "permit",
            "resource_id": "permit-alpha",
            "outcome": "success",
            "severity": "info",
            "created_at": "2026-05-19T10:00:01.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-alpha",
                "category": "security",
                "details": "Sensitive prompt context redacted in restricted fixture.",
                "execution": {"provider": "openai"},
            },
        },
        {
            "event_id": "evt_step2_002",
            "event_type": "policy.evaluated",
            "resource_type": "permit",
            "resource_id": "permit-alpha",
            "outcome": "allow",
            "severity": "info",
            "created_at": "2026-05-19T10:00:02.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-alpha",
                "category": "security",
                "decision": {"type": "allow"},
                "policy": {"id": "pol-prod"},
                "details": "Policy inputs redacted in restricted fixture.",
                "execution": {"provider": "openai"},
            },
        },
        {
            "event_id": "evt_step2_003",
            "event_type": "execution.requested",
            "resource_type": "permit",
            "resource_id": "permit-alpha",
            "outcome": "success",
            "severity": "info",
            "created_at": "2026-05-19T10:00:03.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-alpha",
                "request_id": "req-alpha",
                "category": "security",
                "details": "Execution request body redacted in restricted fixture.",
                "execution": {"provider": "openai"},
            },
        },
        {
            "event_id": "evt_step2_004",
            "event_type": "permit.created",
            "resource_type": "permit",
            "resource_id": "permit-beta",
            "outcome": "success",
            "severity": "info",
            "created_at": "2026-05-19T10:00:04.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-beta",
                "category": "finance",
                "details": "Finance permit details.",
                "execution": {"provider": "anthropic"},
            },
        },
        {
            "event_id": "evt_step2_005",
            "event_type": "provider.response.received",
            "resource_type": "permit",
            "resource_id": "permit-alpha",
            "outcome": "success",
            "severity": "info",
            "created_at": "2026-05-19T10:00:05.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-alpha",
                "request_id": "req-alpha",
                "category": "security",
                "provider_response_digest_v1": "a" * 64,
                "details": "Provider response details redacted in restricted fixture.",
                "execution": {"provider": "openai"},
            },
        },
        {
            "event_id": "evt_step2_006",
            "event_type": "execution.completed",
            "resource_type": "permit",
            "resource_id": "permit-beta",
            "outcome": "success",
            "severity": "info",
            "created_at": "2026-05-19T10:00:06.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-beta",
                "request_id": "req-beta",
                "category": "finance",
                "client_response_digest_v1": "b" * 64,
                "details": "Finance execution result.",
                "execution": {"provider": "anthropic"},
            },
        },
        {
            "event_id": "evt_step2_007",
            "event_type": "permit.closed",
            "resource_type": "permit",
            "resource_id": "permit-gamma",
            "outcome": "success",
            "severity": "warning",
            "created_at": "2026-05-19T10:00:07.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "permit_id": "permit-gamma",
                "request_id": "req-gamma",
                "category": "security",
                "details": "Closure notes redacted in restricted fixture.",
                "execution": {"provider": "anthropic"},
            },
        },
        {
            "event_id": "evt_step2_008",
            "event_type": "audit.integrity_digest",
            "resource_type": "project",
            "resource_id": PROJECT_ID,
            "outcome": "success",
            "severity": "info",
            "created_at": "2026-05-19T10:00:08.000000Z",
            "payload_json": {
                "project_id": PROJECT_ID,
                "category": "security",
                "digest": "c" * 64,
                "details": "Integrity digest details redacted in restricted fixture.",
            },
        },
    ]

    previous_hash = GENESIS_PREV_HASH
    entries = []
    for sequence_number, entry in enumerate(base, start=1):
        current = copy.deepcopy(entry)
        current["chain_scope"] = CHAIN_SCOPE
        current["sequence_number"] = sequence_number
        current["prev_hash"] = previous_hash
        current["chain_format_version"] = "v1"
        current["record_hash"] = record_hash_v1(current)
        entries.append(current)
        previous_hash = current["record_hash"]
    return entries


def entry_ref(entry: dict[str, Any], *, redact_details: bool) -> dict[str, Any]:
    payload = copy.deepcopy(entry["payload_json"])
    if redact_details:
        payload.pop("details", None)
    return {
        "event_id": entry["event_id"],
        "event_type": entry["event_type"],
        "chain_scope": entry["chain_scope"],
        "sequence_number": entry["sequence_number"],
        "record_hash": entry["record_hash"],
        "prev_hash": entry["prev_hash"],
        "created_at": entry["created_at"],
        "chain_format_version": entry["chain_format_version"],
        "payload_json": payload,
    }


def get_path(value: dict[str, Any], path: str) -> Any:
    if not path.startswith("entry."):
        return None
    current: Any = value
    for part in path.removeprefix("entry.").split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def lookup_paths(kind: str) -> list[tuple[str, str | None]]:
    paths: list[tuple[str, str | None]] = []
    for segment in LOOKUP_CHAIN_TEXT_BY_KIND[kind].split("; "):
        match = re.match(r'\d+\. `([^`]+)`(?: when `([^`]+)`)?$', segment)
        if not match:
            raise ValueError(f"cannot parse lookup segment {segment!r}")
        paths.append((match.group(1), match.group(2)))
    return paths


def condition_matches(entry: dict[str, Any], condition: str | None) -> bool:
    if condition is None:
        return True
    if condition == 'entry.resource_type == "permit"':
        return get_path(entry, "entry.resource_type") == "permit"
    raise ValueError(f"unsupported lookup condition {condition!r}")


def resolve_predicate_value(entry: dict[str, Any], kind: str) -> Any:
    for path, condition in lookup_paths(kind):
        if not condition_matches(entry, condition):
            continue
        value = get_path(entry, path)
        if isinstance(value, (str, int, float, bool)):
            return value
    return None


def parse_time(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    return datetime.fromisoformat(normalized)


def predicate_matches(entry: dict[str, Any], predicate: dict[str, Any]) -> bool:
    for kind, expected in predicate["equals"].items():
        actual = resolve_predicate_value(entry, kind)
        if actual != expected:
            return False

    for kind, range_value in predicate["ranges"].items():
        actual = resolve_predicate_value(entry, kind)
        if actual is None:
            return False
        if kind == "sequence_number":
            if int(actual) < int(range_value["gte"]) or int(actual) > int(range_value["lte"]):
                return False
            continue
        actual_time = parse_time(str(actual))
        if actual_time < parse_time(str(range_value["gte"])) or actual_time >= parse_time(str(range_value["lt"])):
            return False
    return True


def predicate_hash(predicate: dict[str, Any]) -> str:
    return sha256_prefixed(canonical_json_bytes(predicate))


def merkle_root(disclosure_records: list[dict[str, Any]], predicate_value_hash: str) -> str:
    if not disclosure_records:
        return EMPTY_TREE_HASH

    leaves = []
    for record in sorted(
        disclosure_records,
        key=lambda item: (item["sequence_number"], item["event_id"], item["record_hash"]),
    ):
        leaf_object = {
            "canonical_predicate_value_hash": predicate_value_hash,
            "event_id": record["event_id"],
            "record_hash": record["record_hash"],
            "sequence_number": record["sequence_number"],
        }
        leaves.append(sha256_bytes(b"\x00" + canonical_json_bytes(leaf_object)))

    def merkle_hash(nodes: list[bytes]) -> bytes:
        if len(nodes) == 1:
            return nodes[0]
        split = 1 << ((len(nodes) - 1).bit_length() - 1)
        left = merkle_hash(nodes[:split])
        right = merkle_hash(nodes[split:])
        return sha256_bytes(b"\x01" + left + right)

    return f"sha256:{merkle_hash(leaves).hex()}"


def chain_scope_hash() -> str:
    return sha256_hex(canonical_json_bytes({"chain_scope": CHAIN_SCOPE}))


def composite_hash(chain_heads: dict[str, dict[str, Any]]) -> str:
    lines = [
        f"{scope}:{head['sequence_number']}:{head['last_record_hash']}"
        for scope, head in sorted(chain_heads.items())
    ]
    return sha256_prefixed("\n".join(lines).encode("utf-8"))


def build_trust_root() -> None:
    export_key = private_key(EXPORT_SEED)
    scope_checkpoint_key = private_key(SCOPE_CHECKPOINT_SEED)
    keys = [
        {
            "algorithm": "ed25519",
            "key_id": key_id(export_key),
            "public_key": public_key_b64(export_key),
            "purpose": "export_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
        {
            "algorithm": "ed25519",
            "key_id": key_id(scope_checkpoint_key),
            "public_key": public_key_b64(scope_checkpoint_key),
            "purpose": "integrity_checkpoint",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
        {
            "algorithm": "ed25519",
            "key_id": key_id(scope_checkpoint_key),
            "public_key": public_key_b64(scope_checkpoint_key),
            "purpose": "scope_state",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
    ]
    write_json(TRUST_ROOT, {"schema_version": 1, "generated_at": SIGNED_AT, "keys": keys})


def build_checkpoint(entries: list[dict[str, Any]]) -> dict[str, Any]:
    scope_checkpoint_key = private_key(SCOPE_CHECKPOINT_SEED)
    last = entries[-1]
    chain_heads = {
        CHAIN_SCOPE: {
            "sequence_number": last["sequence_number"],
            "last_record_hash": last["record_hash"],
        }
    }
    checkpoint = {
        "checkpoint_id": CHECKPOINT_ID,
        "computed_at": SIGNED_AT,
        "keel_version": "step2-scope-faithfulness-fixtures",
        "chain_heads": chain_heads,
        "composite_hash": composite_hash(chain_heads),
        "key_id": key_id(scope_checkpoint_key),
        "public_key": public_key_b64(scope_checkpoint_key),
        "claim_set": {
            "version": "verifier-claims.v0",
            "registry": registry_ref(),
            "claims": [
                {"name": "checkpoint.composite_hash.v1", "required": True},
                {"name": "checkpoint.signature.v1", "required": True},
            ],
        },
        "semantics_pins": checkpoint_semantics_pins(),
    }
    checkpoint["signature"] = sign_b64(scope_checkpoint_key, checkpoint["composite_hash"].encode("utf-8"))
    return checkpoint


def build_sidecar(
    *,
    spec: FixtureSpec,
    entries: list[dict[str, Any]],
    disclosure_records: list[dict[str, Any]],
) -> dict[str, Any]:
    scope_checkpoint_key = private_key(SCOPE_CHECKPOINT_SEED)
    pred_hash = predicate_hash(spec.predicate)
    sequences = [record["sequence_number"] for record in disclosure_records]
    commitment = {
        "predicate_value": spec.predicate,
        "predicate_value_hash": pred_hash,
        "first_matching_sequence": min(sequences) if sequences else None,
        "last_matching_sequence": max(sequences) if sequences else None,
        "matching_count": len(disclosure_records),
        "membership_root_hash": merkle_root(disclosure_records, pred_hash),
    }
    sidecar = {
        "artifact_type": "checkpoint_scope_state",
        "version": "checkpoint_scope_state.v1",
        "scope_state_id": f"keel.scope_state.v1:{chain_scope_hash()}:{CHECKPOINT_ID}",
        "checkpoint_id": CHECKPOINT_ID,
        "chain_scope": CHAIN_SCOPE,
        "predicate_grammar_version": "keel.scope_predicate.v1",
        "predicate_basis": {
            "canonicalization_profile": "keel.canonical_json.payload.v1",
            "supported_predicate_kinds": SUPPORTED_PREDICATE_KINDS,
            "reserved_namespaces": ["keel.scope_predicate.reserved.v1"],
        },
        "commitment_profile": "keel.scope_state.merkle.v1",
        "scope_commitments": [commitment],
        "tree_size": entries[-1]["sequence_number"],
        "signed_at": SIGNED_AT,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id(scope_checkpoint_key),
            "signature": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        },
        "trust_root_reference": {
            "manifest_version": "keel.public_key_manifest.v1",
            "purpose": "scope_state",
            "key_id": key_id(scope_checkpoint_key),
        },
    }
    signed_payload = copy.deepcopy(sidecar)
    del signed_payload["signature"]["signature"]
    sidecar["signature"]["signature"] = sign_b64(scope_checkpoint_key, canonical_json_bytes(signed_payload))
    return sidecar


def fixture_readme(spec: FixtureSpec, disclosure_count: int, merkle_hash: str) -> str:
    return f"""# {spec.fixture_id}

{spec.title}.

## What It Tests

{spec.purpose}

## Expected Verdict

`export.scope_faithfulness.v1` is expected to return `supported`.

The sidecar is signed by the Step 2 scope-state trust-root key, references the
fixture checkpoint, and commits to the declared predicate under
`keel.scope_state.merkle.v1`. The export discloses {disclosure_count} scope
member record(s); the committed Merkle root is `{merkle_hash}`.
"""


def build_fixture(spec: FixtureSpec, entries: list[dict[str, Any]], checkpoint: dict[str, Any]) -> dict[str, Any]:
    redact = spec.presentation_policy["policy_kind"] == "field_redaction"
    refs = [entry_ref(entry, redact_details=redact) for entry in entries]
    disclosure_records = [record for record in refs if predicate_matches(record, spec.predicate)]
    disclosure_ids = {record["event_id"] for record in disclosure_records}
    proof_bridge_records = [record for record in refs if record["event_id"] not in disclosure_ids]

    sidecar = build_sidecar(spec=spec, entries=entries, disclosure_records=disclosure_records)
    sidecar_bytes = pretty_json_bytes(sidecar)
    sidecar_hash = sha256_prefixed(sidecar_bytes)
    storage_uri = f"scope-state/v1/{chain_scope_hash()}/{CHECKPOINT_ID}/checkpoint-scope-state-v1.json"
    filters_hash = sha256_prefixed(canonical_json_bytes(spec.raw_filters))

    export_payload = {
        "scope_faithfulness": {
            "version": "keel.export_scope_faithfulness.v1",
            "segments": [
                {
                    "segment_id": spec.fixture_id,
                    "declared_scope": {
                        "version": "keel.scope_declaration.v1",
                        "scope_kind": spec.scope_kind,
                        "chain_scope": CHAIN_SCOPE,
                        "population_label": spec.population_label,
                        "predicate": spec.predicate,
                        "presentation_policy": spec.presentation_policy,
                    },
                    "declared_start": {
                        "kind": "genesis",
                        "chain_scope": CHAIN_SCOPE,
                        "sequence_number": 1,
                        "genesis_prev_hash": GENESIS_PREV_HASH,
                    },
                    "declared_end": {
                        "checkpoint_id": CHECKPOINT_ID,
                        "chain_scope": CHAIN_SCOPE,
                        "sequence_number": entries[-1]["sequence_number"],
                        "last_record_hash": entries[-1]["record_hash"],
                        "boundary_policy": "explicit_checkpoint",
                    },
                    "scope_state_reference": {
                        "artifact_type": "checkpoint_scope_state",
                        "scope_state_id": sidecar["scope_state_id"],
                        "checkpoint_id": CHECKPOINT_ID,
                        "chain_scope": CHAIN_SCOPE,
                        "artifact_hash": sidecar_hash,
                        "storage_uri": storage_uri,
                    },
                    "canonical_filters": {
                        "canonicalization_profile": "keel.canonical_json.payload.v1",
                        "raw_filters": spec.raw_filters,
                        "filters_hash": filters_hash,
                    },
                    "chain_evidence": {
                        "disclosure_records": disclosure_records,
                        "proof_bridge_records": proof_bridge_records,
                    },
                }
            ],
        }
    }

    export_bytes = pretty_json_bytes(export_payload)
    export_content_hash = sha256_prefixed(export_bytes)
    export_key = private_key(EXPORT_SEED)
    manifest = {
        "export_id": spec.fixture_id,
        "project_id": PROJECT_ID,
        "export_type": "audit_export",
        "format": "json",
        "compressed": False,
        "record_count": len(disclosure_records),
        "content_hash": export_content_hash,
        "key_id": key_id(export_key),
        "public_key": public_key_b64(export_key),
        "signed_at": SIGNED_AT,
        "claim_set": {
            "version": "verifier-claims.v0",
            "registry": registry_ref(),
            "claims": [
                {"name": "export.integrity.v1", "required": True},
                {"name": "checkpoint.scope_state.v1", "required": True},
                {"name": "export.scope_faithfulness.v1", "required": True},
            ],
        },
        "semantics_pins": export_semantics_pins(),
        "signature": sign_b64(export_key, export_content_hash.encode("utf-8")),
    }

    fixture_dir = FIXTURE_ROOT / spec.fixture_id
    write_json(fixture_dir / "pack" / "export.json", export_payload)
    write_json(fixture_dir / "pack" / "manifest.json", manifest)
    write_json(fixture_dir / "pack" / "checkpoint.json", checkpoint)
    write_json(fixture_dir / "sidecars" / "checkpoint-scope-state-v1.json", sidecar)
    (fixture_dir / "README.md").write_text(
        fixture_readme(
            spec,
            disclosure_count=len(disclosure_records),
            merkle_hash=sidecar["scope_commitments"][0]["membership_root_hash"],
        ),
        encoding="utf-8",
    )

    return {
        "claims": [
            {"expected_verdict": "supported", "name": "export.integrity.v1"},
            {"expected_verdict": "supported", "name": "checkpoint.scope_state.v1"},
            {"expected_verdict": "supported", "name": "export.scope_faithfulness.v1"},
        ],
        "expected_current": {
            "outcome": "PASS",
            "reason_classes": [],
        },
        "id": spec.fixture_id,
        "kind": "export",
        "pack": {
            "export_file": f"fixtures/{spec.fixture_id}/pack/export.json",
            "features": ["scope_faithfulness"],
            "key_manifest": "trust_roots/step2-scope-faithfulness-trust-root.json",
            "manifest": f"fixtures/{spec.fixture_id}/pack/manifest.json",
            "checkpoint_file": f"fixtures/{spec.fixture_id}/pack/checkpoint.json",
            "sidecar_file": f"fixtures/{spec.fixture_id}/sidecars/checkpoint-scope-state-v1.json",
        },
        "title": spec.title,
    }


def update_corpus(records: list[dict[str, Any]]) -> None:
    corpus_path = CORPUS_ROOT / "corpus.json"
    corpus = load_json(corpus_path)
    existing = [record for record in corpus["records"] if record.get("id") not in {item["id"] for item in records}]
    corpus["records"] = existing + records
    write_json(corpus_path, corpus)


def main() -> int:
    build_trust_root()
    entries = make_source_chain()
    checkpoint = build_checkpoint(entries)
    records = [build_fixture(spec, entries, checkpoint) for spec in FIXTURES]
    update_corpus(records)
    print(f"Generated {len(records)} scope-faithfulness fixtures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
