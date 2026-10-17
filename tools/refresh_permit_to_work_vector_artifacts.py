#!/usr/bin/env python3
"""Author deterministic synthetic Work vectors; never rewrite customer evidence.

Requires only the repository validation dependencies. Fixed disclosed test seeds
are NOT Keel keys. The independently selected export root authenticates the
binding-key manifest, Permit v6 bytes, and scope commitments. Negative packs
re-sign unaffected layers so their advertised failure is reachable.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "test-vectors/permit_to_work/v1/corpus.json"
EXPORT_SEED = bytes([49]) * 32
BINDING_SEED = bytes([50]) * 32
EXPORT_PRIVATE = Ed25519PrivateKey.from_private_bytes(EXPORT_SEED)
BINDING_PRIVATE = Ed25519PrivateKey.from_private_bytes(BINDING_SEED)


def raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def public(private: Ed25519PrivateKey) -> str:
    return "ed25519:" + base64.b64encode(raw_public(private)).decode("ascii")


EXPORT_KEY_ID = "sha256:" + hashlib.sha256(raw_public(EXPORT_PRIVATE)).hexdigest()[:32]
BINDING_KEY_ID = hashlib.sha256(raw_public(BINDING_PRIVATE)).hexdigest()[:16]


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def signature(private: Ed25519PrivateKey, message: str) -> str:
    return "ed25519:" + base64.b64encode(private.sign(message.encode("utf-8"))).decode("ascii")


def artifact(artifact_id: str, artifact_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "artifact_digest": digest(payload),
        "payload": payload,
    }


def reference(item: dict[str, Any]) -> dict[str, str]:
    return {key: item[key] for key in ("artifact_id", "artifact_type", "artifact_digest")}


def semantic(binding: dict[str, Any]) -> dict[str, Any]:
    binding = copy.deepcopy(binding)
    data = (ROOT / "semantic_registry/v1.json").read_bytes()
    registry = json.loads(data)
    entry = next(item for item in registry["entries"] if item["semantic_id"] == binding["semantic_id"])
    binding.update(
        selector_registry_version=registry["version"],
        selector_registry_digest="sha256:" + hashlib.sha256(data).hexdigest(),
        selector_entry_digest=digest(entry),
    )
    return binding


def permit(pack: dict[str, Any], *, child: bool) -> dict[str, Any]:
    package = pack["root"]["work_package"]
    item = pack["child_permits"][0]
    root_id = pack["root_permit_id"]
    permit_id = item["permit_id"] if child else root_id
    action = "payment.execute" if child else "work.authorize"
    attrs: dict[str, Any] = {
        "operation": action,
        "permit_semantic_binding_v1": item["semantic_binding"] if child else pack["root"]["semantic_binding"],
    }
    spend_hash = None
    if child:
        authority = pack["authorities"][0]
        amount = pack["value_events"][0]["amount_minor"]
        attrs.update(
            work_binding_v1=item["work_binding"],
            work_resource_scope_v1={"version": "keel.work_resource_scope.v1", **authority["resource_scope"]},
            work_resource_digest=authority["resource_scope"]["digest"],
            spend_scope={
                "amount_max": str(amount),
                "currency_class": "USD_FIAT",
                "cadence": "one_shot",
                "ttl_seconds": 3600,
                "purpose_binding": "purchase.once",
                "recipient_address_digest": "1" * 64,
                "description_digest": "2" * 64,
            },
        )
        spend = {**attrs["spend_scope"], "amount_max": amount, "merchant_id_digest": None}
        spend_hash = hashlib.sha256(rfc8785.dumps(spend)).hexdigest()
    else:
        attrs["work_package_v1"] = package
    fingerprint = item["request_digest"].removeprefix("sha256:") if child else "a" * 64
    # Explicit Permit v6 fixture payload: no runtime/private Keel imports.
    payload = {
        "binding_version": "v6",
        "permit_id": permit_id,
        "project_id": pack["project_id"],
        "parent_permit_id": root_id if child else None,
        "decision": "allow",
        "reason": "policy.allow",
        "provider": "stripe_mpp" if child else "keel",
        "model": "stripe.mpp.v1" if child else "work.v1",
        "operation": action,
        "action_name": action,
        "request_fingerprint": fingerprint,
        "constraints": {},
        "routing": None,
        "policy_id": package["policy_snapshot"]["policy_id"],
        "policy_version": package["policy_snapshot"]["policy_version"],
        "policy_snapshot_hash": package["policy_snapshot"]["policy_snapshot_hash"].removeprefix("sha256:"),
        "issued_at": "2026-07-21T16:05:00Z",
        "expires_at": package["expires_at"],
        "is_dry_run": False,
        "binding_key_id": BINDING_KEY_ID,
        "final_request_hash": None,
        "binding_session_id": None,
        "binding_session_event_hash": None,
        "binding_project_anchor_hash": None,
        "permit_chain_role": "action_child" if child else "work_root",
        "inherits_from": None,
        "authority_delta": None,
        "spend_scope_hash": spend_hash,
        "delegation_policy_hash": None,
        "resource_attributes_canonical_hash": digest(attrs).removeprefix("sha256:"),
    }
    binding_hash = digest(payload).removeprefix("sha256:")
    binding = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": payload,
        "resource_attributes_json": attrs,
        "binding_canonical_hash": binding_hash,
        "binding_signature": signature(BINDING_PRIVATE, binding_hash),
        "binding_key_id": BINDING_KEY_ID,
        "binding_issued_at": payload["issued_at"],
        "expected_decision": "allow",
    }
    receipt = {
        "receipt_type": "permit_receipt",
        "project_id": pack["project_id"],
        "permit_id": permit_id,
        "action": {"action_name": action, "resource_attributes_json": attrs},
        "decision": {"decision": "allow"},
    }
    return artifact(
        "urn:x-keel:artifact:permit:" + permit_id,
        "keel.work_permit_evidence.v1",
        {"version": "keel.work_permit_evidence.v1", "permit_receipt": receipt, "permit_decision_binding": binding},
    )


def authenticate(pack: dict[str, Any]) -> None:
    for child in (False, True):
        signed = permit(pack, child=child)
        pack["artifacts"] = [
            signed if item["artifact_id"] == signed["artifact_id"] else item for item in pack["artifacts"]
        ]
        if child:
            pack["child_permits"][0]["permit_artifact"] = reference(signed)
        else:
            pack["root"]["permit_artifact"] = reference(signed)
    fields = {
        "work_authorities": "authorities",
        "child_permits": "child_permits",
        "work_value_events": "value_events",
        "lifecycle_events": "lifecycle_events",
    }
    for item in pack["scope_commitment"]["populations"]:
        values = pack[fields[item["population"]]]
        item.update(included_count=len(values), included_set_hash=digest(values))
    payload = {
        "version": "keel.work_scope_commitment_signature_payload.v1",
        "project_id": pack["project_id"],
        "root_permit_id": pack["root_permit_id"],
        "export_source": pack["export_source"],
        "recorded_through": pack["declared_cutoff"]["recorded_through"],
        "checkpoint_id": pack["declared_cutoff"]["checkpoint_id"],
        "scope_commitment": pack["scope_commitment"],
        "binding_key_id": BINDING_KEY_ID,
    }
    scope_hash = digest(payload)
    pack["declared_cutoff"]["checkpoint_digest"] = scope_hash
    pack["scope_commitment_signature"] = {
        "version": "keel.work_scope_commitment_signature.v1",
        "signature_profile": "keel.canonical_json.payload.v1",
        "binding_key_id": BINDING_KEY_ID,
        "canonical_hash": scope_hash,
        "signature": signature(BINDING_PRIVATE, scope_hash.removeprefix("sha256:")),
        "signed_at": pack["declared_cutoff"]["recorded_through"],
    }


def mutate(pack: dict[str, Any], mutation: dict[str, Any]) -> None:
    roots = {
        "pack": pack,
        "work_package": pack["root"]["work_package"],
        "authority": pack["authorities"][0],
        "child_permit": pack["child_permits"][0],
        "value_events": pack["value_events"],
    }
    prefix, *parts = mutation["target"].split(".")
    node = roots[prefix]
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    key = int(parts[-1]) if isinstance(node, list) else parts[-1]
    if mutation.get("operation") == "delete":
        del node[key]
    else:
        node[key] = copy.deepcopy(mutation["value"])


def generate(corpus: dict[str, Any]) -> dict[str, Any]:
    corpus = copy.deepcopy(corpus)
    valid = corpus["valid"]
    pack = valid["pack"]
    for target, source in corpus["assembly"].items():

        def resolve(path: str) -> Any:
            value: Any = corpus
            for part in path.split("."):
                value = value[int(part)] if isinstance(value, list) else value[part]
            return copy.deepcopy(value)

        value = [resolve(path) for path in source] if isinstance(source, list) else resolve(source)
        node = pack
        parts = target.removeprefix("pack.").split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    pack["root"]["semantic_binding"] = semantic(pack["root"]["semantic_binding"])
    pack["child_permits"][0]["semantic_binding"] = semantic(pack["child_permits"][0]["semantic_binding"])
    pack["child_permits"][0]["work_binding"]["root_manifest_hash"] = digest(pack["root"]["work_package"])
    keys = [
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key": public(private),
            "purpose": purpose,
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        }
        for key_id, private, purpose in (
            (EXPORT_KEY_ID, EXPORT_PRIVATE, "export_signing"),
            (BINDING_KEY_ID, BINDING_PRIVATE, "permit_binding_signing"),
        )
    ]
    manifest = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "keys": keys,
    }
    content_hash = digest(manifest)
    manifest["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": EXPORT_KEY_ID,
        "public_key": public(EXPORT_PRIVATE),
        "content_hash": content_hash,
        "signature": signature(EXPORT_PRIVATE, content_hash),
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "signed_fields": ["manifest_version", "canonicalization_profile", "keys"],
    }
    key_artifact = artifact("urn:x-keel:artifact:key_manifest:permit-binding", "keel.public_key_manifest.v1", manifest)
    pack["artifacts"] = [item for item in pack["artifacts"] if item["artifact_type"] != "keel.public_key_manifest.v1"]
    pack["artifacts"].append(key_artifact)
    pack["evidence_artifacts"] = [
        item for item in pack["evidence_artifacts"] if item["artifact_type"] != "keel.public_key_manifest.v1"
    ]
    pack["evidence_artifacts"].append(reference(key_artifact))
    authenticate(pack)
    valid.update(
        work_package=copy.deepcopy(pack["root"]["work_package"]),
        authority=copy.deepcopy(pack["authorities"][0]),
        child_permit=copy.deepcopy(pack["child_permits"][0]),
        value_events=copy.deepcopy(pack["value_events"]),
        lifecycle_events=copy.deepcopy(pack["lifecycle_events"]),
    )
    corpus["test_trust"] = {
        "purpose": "synthetic fixture only; no Keel production trust or external effect",
        "export_seed_hex": EXPORT_SEED.hex(),
        "binding_seed_hex": BINDING_SEED.hex(),
        "trust_root": {"version": "keel.trust_root.v1", "keys": [keys[0]]},
    }
    for mutation in corpus["negative_mutations"]:
        negative = copy.deepcopy(pack)
        mutate(negative, mutation)
        if mutation["id"] in {
            "required-authority-missing",
            "authority-hash-mismatch",
            "child-binding-mismatch",
            "settlement-evidence-missing",
        }:
            if mutation["id"] == "required-authority-missing":
                negative["child_permits"][0]["work_binding"]["root_manifest_hash"] = digest(
                    negative["root"]["work_package"]
                )
            authenticate(negative)
        mutation["pack"] = negative
    return corpus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if committed deterministic bytes need regeneration")
    args = parser.parse_args()
    generated = json.dumps(generate(json.loads(CORPUS.read_text())), indent=2, ensure_ascii=False) + "\n"
    manifest_path = ROOT / "artifact-manifests/permit-to-x-v1.json"
    manifest = json.loads(manifest_path.read_text())
    entry = next(item for item in manifest["artifacts"] if item["path"] == "test-vectors/permit_to_work/v1/corpus.json")
    generated_hash = hashlib.sha256(generated.encode("utf-8")).hexdigest()
    if args.check:
        if CORPUS.read_text() != generated:
            raise SystemExit("Work corpus is not reproducible; run this authoring helper")
        if entry["sha256"] != generated_hash:
            raise SystemExit("Work corpus artifact-manifest hash differs")
        print("Work corpus deterministic bytes: PASS")
    else:
        CORPUS.write_text(generated)
        entry["sha256"] = generated_hash
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
