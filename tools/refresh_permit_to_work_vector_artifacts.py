#!/usr/bin/env python3
"""Refresh the self-contained artifact bytes and dependent Work vector hashes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "test-vectors/permit_to_work/v1/corpus.json"


def digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def artifact(artifact_id: str, artifact_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "artifact_digest": digest(payload),
        "payload": payload,
    }


def reference(item: dict[str, Any]) -> dict[str, str]:
    return {
        "artifact_id": item["artifact_id"],
        "artifact_type": item["artifact_type"],
        "artifact_digest": item["artifact_digest"],
    }


def main() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    valid = corpus["valid"]
    pack = valid["pack"]
    root_id = pack["root_permit_id"]
    child_id = valid["child_permit"]["permit_id"]
    root_event = valid["lifecycle_events"][0]
    dispatch_event = valid["lifecycle_events"][1]

    root_artifact = artifact(
        f"urn:x-keel:artifact:permit:{root_id}",
        "permit",
        {
            "version": "keel.test_permit_artifact.v1",
            "permit_id": root_id,
            "project_id": pack["project_id"],
            "chain_role": "work_root",
            "binding_key_id": "keel-test-signing-key-v1",
            "binding_canonical_hash": "a" * 64,
            "binding_signature": "ed25519:" + "A" * 86 + "==",
        },
    )
    child_artifact = artifact(
        f"urn:x-keel:artifact:permit:{child_id}",
        "permit",
        {
            "version": "keel.test_permit_artifact.v1",
            "permit_id": child_id,
            "project_id": pack["project_id"],
            "chain_role": "action_child",
            "parent_permit_id": root_id,
            "work_binding": valid["child_permit"]["work_binding"],
            "binding_key_id": "keel-test-signing-key-v1",
            "binding_canonical_hash": "b" * 64,
            "binding_signature": "ed25519:" + "A" * 86 + "==",
        },
    )
    issue_artifact = artifact(
        f"urn:x-keel:artifact:governance_event:{root_event['event_id']}",
        "governance_event",
        {
            "version": "keel.work_lifecycle_event.v1",
            **root_event,
        },
    )
    dispatch_artifact = artifact(
        f"urn:x-keel:artifact:governance_event:{dispatch_event['event_id']}",
        "governance_event",
        {
            "version": "keel.work_dispatch_boundary.v1",
            **dispatch_event,
            "root_permit_id": root_id,
            "child_permit_id": child_id,
            "liveness": {
                "root_live": True,
                "authority_live": True,
                "child_live": True,
                "reservation_live": True,
                "current_policy_epoch_matched": True,
                "platform_safety_floor_passed": True,
            },
            "execution_policy": pack["policy_snapshots"][2],
            "asserts_provider_acceptance": False,
            "asserts_business_job_completed": False,
            "asserts_settlement": False,
        },
    )
    provider_artifact = artifact(
        "urn:x-keel:artifact:provider_receipt:receipt-84",
        "provider_receipt",
        {
            "version": "keel.test_provider_receipt.v1",
            "provider": "test-payments",
            "provider_reference": "receipt-84",
            "accepted_at": "2026-07-21T16:07:02Z",
            "asserts_settlement": False,
        },
    )
    settlement_artifact = artifact(
        "urn:x-keel:artifact:settlement:settlement-84",
        "x402_settlement_proof",
        {
            "version": "keel.test_x402_settlement_proof.v1",
            "provider_reference": "settlement-84",
            "amount_minor": 8400,
            "currency": "USD",
            "settled_at": "2026-07-21T16:08:00Z",
        },
    )

    pack["root"]["permit_artifact"] = reference(root_artifact)
    valid["child_permit"]["permit_artifact"] = reference(child_artifact)
    valid["child_permit"]["dispatch_boundary_evidence"] = reference(dispatch_artifact)
    root_event["event_digest"] = issue_artifact["artifact_digest"]
    dispatch_event["event_digest"] = dispatch_artifact["artifact_digest"]
    valid["value_events"][2]["evidence_reference"] = {
        "artifact_id": provider_artifact["artifact_id"],
        "artifact_digest": provider_artifact["artifact_digest"],
    }
    valid["value_events"][3]["evidence_reference"] = {
        "artifact_id": settlement_artifact["artifact_id"],
        "artifact_digest": settlement_artifact["artifact_digest"],
    }
    pack["evidence_artifacts"] = [
        reference(provider_artifact),
        reference(settlement_artifact),
    ]
    pack["artifacts"] = [
        root_artifact,
        child_artifact,
        issue_artifact,
        dispatch_artifact,
        provider_artifact,
        settlement_artifact,
    ]

    populations = {
        "work_authorities": [valid["authority"]],
        "child_permits": [valid["child_permit"]],
        "work_value_events": valid["value_events"],
        "lifecycle_events": valid["lifecycle_events"],
    }
    for commitment in pack["scope_commitment"]["populations"]:
        values = populations[commitment["population"]]
        commitment["included_count"] = len(values)
        commitment["included_set_hash"] = digest(values)

    CORPUS.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
