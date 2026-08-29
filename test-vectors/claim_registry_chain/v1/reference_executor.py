#!/usr/bin/env python3
"""Reference executor for the v7 claim-registry and v6 recipe extension chains.

Not the product verifier. Executes the normative extension-resolution rules by
hand, purely from the spec, so that two implementers resolving the same chain
reach the same outcome without an undocumented choice. Every place this script
had to decide something the spec did not state is a spec gap.

The rules executed here are stated in `spec/verifier-claims-v2.md` ("load the
exact base registry named by `extends`; verify its version and SHA-256 digest;
reject duplicate claim names across the base and extension") and narrowed for
v7 by `spec/verifier-claims-v7.md`.

Each vector names a chain, an optional single-delta mutation of a valid parent,
and the expected outcome. A mutation is applied to a parsed copy of the named
artifact; when the mutation targets `base`, the base bytes change and the
extension's pinned digest is expected to stop matching. Nothing here reads a
verifier's current output: the expectations come from the specification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CORPUS = json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))

VERDICTS = {"supported", "disproved", "insufficient_evidence", "unverifiable_scope"}

# Keys whose presence would pull a neighbouring contract into these artifacts.
# The v7 registry and the v6 recipe introduce no semantic-registry selector, no
# fact profile, no consequence or presentation registry entry, and no Permit
# schema or binding-version field; scanning for the keys keeps that true.
FORBIDDEN_KEYS = {
    "semantic_id",
    "semantic_registry_version",
    "selector_registry_version",
    "selector_entry_digest",
    "fact_profile_id",
    "fact_profile_registry_version",
    "fact_profile_entry_digest",
    "consequence_id",
    "consequence_registry_version",
    "presentation_profile_id",
    "non_authorizing_presentation_profile_id",
    "presentation_registry_version",
    "permit_schema_version",
    "permit_binding_version",
    "binding_version",
}

# A claim name is a claim name. A `keel.action.*` identifier is a semantic
# registry selector, and the released consequence claims carry payment-refund
# and generate-text meaning that this surface must not borrow.
SUBSTITUTED_CLAIM_PREFIXES = ("keel.action.",)
SUBSTITUTED_CLAIM_TOKENS = ("refund", "payment", "generate_text", "tool_call")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_bytes(document: dict) -> bytes:
    """Re-serialise a mutated artifact the way the repository stores JSON."""
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def walk_keys(node, found: set[str]) -> set[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            walk_keys(value, found)
    elif isinstance(node, list):
        for item in node:
            walk_keys(item, found)
    return found


def substituted(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(SUBSTITUTED_CLAIM_PREFIXES):
        return True
    return any(token in lowered for token in SUBSTITUTED_CLAIM_TOKENS)


def apply_mutation(document: dict, mutation: dict) -> dict:
    """Apply one declared single-delta mutation to a parsed artifact copy."""
    out = copy.deepcopy(document)
    op = mutation["op"]

    if op == "remove_extends":
        out.pop("extends", None)
    elif op == "remove_extends_field":
        out.get("extends", {}).pop(mutation["field"], None)
    elif op == "set_extends_field":
        out.setdefault("extends", {})[mutation["field"]] = mutation["value"]
    elif op == "set_verdict_enum":
        out["verdict_enum"] = mutation["value"]
    elif op == "inject_key":
        out[mutation["key"]] = mutation["value"]
    elif op == "rename_claim":
        for claim in out.get("claims", []):
            if claim.get("name") == mutation["from"]:
                claim["name"] = mutation["to"]
    elif op == "remove_claim":
        out["claims"] = [c for c in out.get("claims", []) if c.get("name") != mutation["name"]]
    elif op == "duplicate_claim":
        for claim in list(out.get("claims", [])):
            if claim.get("name") == mutation["name"]:
                out["claims"].append(copy.deepcopy(claim))
                break
    elif op == "add_claim":
        template = copy.deepcopy(out["claims"][0])
        template["name"] = mutation["name"]
        out["claims"].append(template)
    elif op == "remove_claim_field":
        for claim in out.get("claims", []):
            if claim.get("name") == mutation["name"]:
                claim.pop(mutation["field"], None)
    elif op == "set_claim_field":
        for claim in out.get("claims", []):
            if claim.get("name") == mutation["name"]:
                claim[mutation["field"]] = mutation["value"]
    elif op == "set_body_field":
        out.setdefault("body", {})[mutation["field"]] = mutation["value"]
    elif op == "rename_surface_key":
        claims = out["body"]["conditional_evidence_claims"]
        claims[mutation["to"]] = claims.pop(mutation["from"])
    elif op == "remove_artifact_class":
        out["body"]["conditional_evidence_claims"][mutation["surface"]].pop(mutation["class"], None)
    elif op == "set_artifact_class":
        out["body"]["conditional_evidence_claims"][mutation["surface"]][mutation["class"]] = mutation["claims"]
    elif op == "swap_artifact_classes":
        classes = out["body"]["conditional_evidence_claims"][mutation["surface"]]
        first, second = mutation["classes"]
        classes[first], classes[second] = classes[second], classes[first]
    else:
        raise SystemExit(f"corpus declares an unknown mutation op: {op}")
    return out


def resolve_registry_chain(base, base_bytes, extension, expected) -> tuple[str, str]:
    """Resolve a claim-registry extension against its pinned base."""
    pin = extension.get("extends")
    if not isinstance(pin, dict):
        return "refused", "CHAIN_BASE_UNPINNED"
    if pin.get("artifact_id") != expected["base_artifact_id"]:
        return "refused", "CHAIN_BASE_ARTIFACT_MISMATCH"
    if "version" not in pin:
        return "refused", "CHAIN_BASE_VERSION_ABSENT"
    if pin["version"] != base.get("version"):
        return "refused", "CHAIN_BASE_VERSION_MISMATCH"
    if "sha256" not in pin:
        return "refused", "CHAIN_BASE_DIGEST_ABSENT"
    if pin["sha256"] != sha256_bytes(base_bytes):
        return "refused", "CHAIN_BASE_DIGEST_MISMATCH"

    if set(extension.get("verdict_enum", [])) != VERDICTS:
        return "refused", "CHAIN_VERDICT_ENUM_CHANGED"

    claims = extension.get("claims")
    if not isinstance(claims, list) or not claims:
        return "refused", "CHAIN_CLAIM_SET_MISMATCH"
    for claim in claims:
        if set(claim.get("verdict_enum", [])) != VERDICTS:
            return "refused", "CHAIN_VERDICT_ENUM_CHANGED"
        if not claim.get("does_not_establish"):
            return "refused", "CHAIN_CLAIM_CEILING_ABSENT"

    names = [c.get("name") for c in claims]
    if len(names) != len(set(names)):
        return "refused", "CHAIN_CLAIM_DUPLICATED"

    # The base union is transitive: every claim any released registry defined.
    inherited = {
        claim.get("name")
        for version in expected["inherited_registries"]
        for claim in json.loads((ROOT / version).read_text(encoding="utf-8")).get("claims", [])
    }
    if set(names) & inherited:
        return "refused", "CHAIN_CLAIM_REDEFINED"
    if any(substituted(name) for name in names):
        return "refused", "CHAIN_SEMANTIC_SUBSTITUTION"
    if set(names) != set(expected["added_claims"]):
        return "refused", "CHAIN_CLAIM_SET_MISMATCH"
    if walk_keys(extension, set()) & FORBIDDEN_KEYS:
        return "refused", "CHAIN_SCOPE_VIOLATION"
    return "resolved", "CHAIN_RESOLVED"


def resolve_recipe_chain(base, base_bytes, extension, expected) -> tuple[str, str]:
    """Resolve a universal-verification recipe extension against its base."""
    pin = extension.get("extends")
    if not isinstance(pin, dict):
        return "refused", "RECIPE_BASE_UNPINNED"
    if pin.get("artifact_id") != expected["base_artifact_id"]:
        return "refused", "RECIPE_BASE_ARTIFACT_MISMATCH"
    if "version" not in pin:
        return "refused", "RECIPE_BASE_VERSION_ABSENT"
    if pin["version"] != base.get("version"):
        return "refused", "RECIPE_BASE_VERSION_MISMATCH"
    if "sha256" not in pin:
        return "refused", "RECIPE_BASE_DIGEST_ABSENT"
    if pin["sha256"] != sha256_bytes(base_bytes):
        return "refused", "RECIPE_BASE_DIGEST_MISMATCH"

    body = extension.get("body", {})
    if body.get("claim_registry_version") != expected["claim_registry_version"]:
        return "refused", "RECIPE_CLAIM_REGISTRY_MISMATCH"

    conditional = body.get("conditional_evidence_claims", {})
    # An enforcement surface key is a surface key. Swapping it for a semantic
    # registry selector would re-file these claims under another contract's
    # meaning, so it is named as substitution rather than a generic mismatch.
    if any(substituted(key) for key in conditional):
        return "refused", "RECIPE_SEMANTIC_SUBSTITUTION"
    if set(conditional) != {expected["surface_key"]}:
        return "refused", "RECIPE_SURFACE_KEY_MISMATCH"

    classes = conditional[expected["surface_key"]]
    if set(classes) != set(expected["artifact_classes"]):
        return "refused", "RECIPE_ARTIFACT_CLASS_MAP_MISMATCH"

    mapped = [name for names in classes.values() for name in names]
    if any(substituted(name) for name in mapped):
        return "refused", "RECIPE_SEMANTIC_SUBSTITUTION"
    if set(mapped) != set(expected["added_claims"]):
        return "refused", "RECIPE_CLAIM_SET_MISMATCH"
    if classes != expected["artifact_classes"]:
        return "refused", "RECIPE_ARTIFACT_CLASS_BINDING_MISMATCH"
    if walk_keys(extension, set()) & FORBIDDEN_KEYS:
        return "refused", "RECIPE_SCOPE_VIOLATION"
    return "resolved", "RECIPE_RESOLVED"


RESOLVERS = {"claim_registry": resolve_registry_chain, "universal_verification": resolve_recipe_chain}


def execute(vector: dict) -> tuple[str, str]:
    chain = CORPUS["chains"][vector["chain"]]
    base_path, ext_path = ROOT / chain["base"], ROOT / chain["extension"]
    base_bytes = base_path.read_bytes()
    base = json.loads(base_bytes.decode("utf-8"))
    extension = json.loads(ext_path.read_text(encoding="utf-8"))

    mutation = vector.get("mutation")
    if mutation:
        if mutation["target"] == "base":
            base = apply_mutation(base, mutation)
            base_bytes = canonical_bytes(base)
        else:
            extension = apply_mutation(extension, mutation)

    return RESOLVERS[vector["chain"]](base, base_bytes, extension, chain["expected"])


def main() -> int:
    fails = 0
    for vector in CORPUS["vectors"]:
        outcome, reason = execute(vector)
        want = vector["expected"]
        ok = outcome == want["outcome"] and reason == want["reason"]
        fails += not ok
        print(f"{'OK ' if ok else 'XX '}{vector['id']:<48} got={outcome}/{reason}")
        if not ok:
            print(f"      want={want['outcome']}/{want['reason']}")
    total = len(CORPUS["vectors"])
    print(f"\n{total} vectors, {fails} mismatch")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
