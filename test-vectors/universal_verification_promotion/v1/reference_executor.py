#!/usr/bin/env python3
"""Reference executor for the immutable v6-to-released-v7 recipe promotion."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CORPUS = json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))


def canonical_bytes(document: dict) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()


def apply_mutation(document: dict, mutation: dict) -> dict:
    out = copy.deepcopy(document)
    op = mutation["op"]
    if op == "remove_extends":
        out.pop("extends", None)
    elif op == "remove_extends_field":
        out.get("extends", {}).pop(mutation["field"], None)
    elif op == "set_extends_field":
        out.setdefault("extends", {})[mutation["field"]] = mutation["value"]
    elif op == "set_top_field":
        out[mutation["field"]] = mutation["value"]
    elif op == "set_body_field":
        out.setdefault("body", {})[mutation["field"]] = mutation["value"]
    else:
        raise SystemExit(f"unknown mutation op: {op}")
    return out


def resolve(base: dict, base_bytes: bytes, promotion: dict) -> tuple[str, str]:
    expected = CORPUS["expected"]
    pin = promotion.get("extends")
    if not isinstance(pin, dict):
        return "refused", "RECIPE_PROMOTION_BASE_UNPINNED"
    if pin.get("artifact_id") != expected["base_artifact_id"]:
        return "refused", "RECIPE_PROMOTION_BASE_ARTIFACT_MISMATCH"
    if pin.get("version") != expected["base_version"]:
        return "refused", "RECIPE_PROMOTION_BASE_VERSION_MISMATCH"
    if "sha256" not in pin:
        return "refused", "RECIPE_PROMOTION_BASE_DIGEST_ABSENT"
    if pin["sha256"] != hashlib.sha256(base_bytes).hexdigest():
        return "refused", "RECIPE_PROMOTION_BASE_DIGEST_MISMATCH"
    if promotion.get("id") != expected["promotion_artifact_id"]:
        return "refused", "RECIPE_PROMOTION_ID_MISMATCH"
    if promotion.get("version") != expected["promotion_version"]:
        return "refused", "RECIPE_PROMOTION_VERSION_MISMATCH"
    if promotion.get("status") != expected["promotion_status"]:
        return "refused", "RECIPE_PROMOTION_STATUS_MISMATCH"
    if promotion.get("kind") != base.get("kind"):
        return "refused", "RECIPE_PROMOTION_KIND_MISMATCH"
    if promotion.get("body") != base.get("body"):
        return "refused", "RECIPE_PROMOTION_BODY_MISMATCH"
    return "resolved", "RECIPE_PROMOTION_RESOLVED"


def execute(vector: dict) -> tuple[str, str]:
    base_path = ROOT / CORPUS["base"]
    promotion_path = ROOT / CORPUS["promotion"]
    base_bytes = base_path.read_bytes()
    base = json.loads(base_bytes)
    promotion = json.loads(promotion_path.read_bytes())
    mutation = vector.get("mutation")
    if mutation:
        if mutation["target"] == "base":
            base = apply_mutation(base, mutation)
            base_bytes = canonical_bytes(base)
        else:
            promotion = apply_mutation(promotion, mutation)
    return resolve(base, base_bytes, promotion)


def main() -> int:
    failures = 0
    for vector in CORPUS["vectors"]:
        actual = execute(vector)
        expected = vector["expected"]
        wanted = (expected["outcome"], expected["reason"])
        ok = actual == wanted
        failures += not ok
        print(f"{'OK ' if ok else 'XX '}{vector['id']:<42} got={actual[0]}/{actual[1]}")
        if not ok:
            print(f"      want={wanted[0]}/{wanted[1]}")
    print(f"\n{len(CORPUS['vectors'])} vectors, {failures} mismatch")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
