#!/usr/bin/env python3
"""Reference executor for keel.permit.action_classification_derivation.v1.

Not the product verifier. Executes the ruleset's normative decision_algorithm by
hand against the corpus, purely from the spec, to test that two implementers get
identical outcomes without an undocumented choice. Every place this script had to
decide something the spec did not state is a spec gap.

The verifier's environment is an explicit per-vector input `given`:
  trusted_registry_digests: [digest, ...]      -- the immutable trust set
  store: [{digest, content_utf8}, ...]          -- byte-concrete extra store entries
The pinned canonical registry digest always resolves to the real registry bytes.
A store entry whose content_utf8 does not hash to its digest triggers step-3
dependency_integrity; hash-correct content that is not a valid registry triggers
step-4 dependency_artifact_invalid.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent
def S(*p):
    return HERE.joinpath(*p)
CORPUS = json.loads(S("corpus.json").read_text())
RULESET = json.loads(
    S("..", "..", "..", "semantics", "permit", "action_classification_derivation_v1.json").read_text()
)["body"]
REG_PATH = S("..", "..", "..", "semantics", "permit", "value_movement_classification_v1.json")
REGISTRY = json.loads(REG_PATH.read_text())

GRAMMAR = re.compile(RULESET["identifier_grammar"]["grammar"])
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
KNOWN_KINDS = set(RULESET["classification_subject_variants"].keys())
MEMBERS = {(e["connector_identity"], e["canonical_tool_name"]) for e in REGISTRY["body"]["entries"]}
PINNED = "sha256:" + hashlib.sha256(REG_PATH.read_bytes()).hexdigest()


def _input_digest(ci, tn):
    obj = {"profile": "keel.registered_tool_classification_input.v1",
           "connector_identity": ci, "canonical_tool_name": tn}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def execute(facts, given):
    t = []
    cls = facts.get("classification", {})
    subject = cls.get("subject", {})
    prov = cls.get("provenance", {})
    reg_digest = prov.get("registry", {}).get("artifact_digest", "")
    in_digest = prov.get("input", {}).get("digest", "")

    # Step 1 COMMON ENVELOPE — common signed-field syntax BEFORE variant dispatch.
    if not DIGEST_RE.match(reg_digest):
        return "invalid", [*t, f"1:malformed common registry digest {reg_digest!r}"]
    if not DIGEST_RE.match(in_digest):
        return "invalid", [*t, f"1:malformed common input digest {in_digest!r}"]
    t.append("1:common envelope ok")

    # Step 2 SUBJECT DISPATCH
    kind = subject.get("kind")
    if kind in KNOWN_KINDS:
        for label in ("connector_identity", "canonical_tool_name"):
            v = subject.get(label, "")
            if not subject.get(label) or not GRAMMAR.match(v):
                return "invalid", [*t, f"2:variant field/grammar fail {label}={v!r}"]
        t.append("2:known variant, fields+grammar ok")
    else:
        return "no_derivation", [*t, f"2:unknown subject kind {kind!r} (common envelope already validated)"]

    # Step 3 DEPENDENCY RESOLUTION (hash-verifying, byte-concrete)
    trusted = set(given.get("trusted_registry_digests", []))
    if reg_digest not in trusted:
        return "unverifiable", [*t, f"3:registry {reg_digest[:14]}.. not trusted -> artifact_unavailable"]
    # Resolve bytes: the pinned registry for its own digest, else the store.
    store = {e["digest"]: e["content_utf8"].encode() for e in given.get("store", [])}
    if reg_digest == PINNED:
        reg_bytes = REG_PATH.read_bytes()
    elif reg_digest in store:
        reg_bytes = store[reg_digest]
    else:
        return "unverifiable", [*t, "3:trusted digest but no bytes in store -> artifact_unavailable"]
    if "sha256:" + hashlib.sha256(reg_bytes).hexdigest() != reg_digest:
        return "invalid", [*t, "3:store bytes do not hash to trusted digest -> dependency_integrity"]
    t.append("3:resolved by exact digest, hash-verified")

    # Step 4 DEPENDENCY VALIDATION
    try:
        rb = json.loads(reg_bytes.decode())
        body = rb.get("body", {})
        valid = (rb.get("kind") == "value_movement_tool_classification"
                 and body.get("classification") == "value_movement"
                 and isinstance(body.get("entries"), list))
    except Exception:
        valid = False
    if not valid:
        return "invalid", [*t, "4:resolved registry fails schema/version -> dependency_artifact_invalid"]
    t.append("4:dependency registry valid")

    # Step 5 INTERNAL DIGEST AGREEMENT — v1: exactly one authoritative ref, no-op.

    # Step 6 INPUT DIGEST (self-contained)
    if in_digest != _input_digest(subject["connector_identity"], subject["canonical_tool_name"]):
        return "invalid", [*t, "6:input_digest mismatch"]
    t.append("6:input_digest ok")

    # Step 7 RULE MATCH SET
    def fact_at(path):
        node = facts
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return node
    matched = [r for r in RULESET["rules"]
               if all(fact_at(c["fact"]) == c["value"] for c in r["applies_when"]["all"])]
    if len(matched) == 0:
        return "no_derivation", [*t, "7:zero rules match"]
    if len(matched) > 1:
        return "invalid", [*t, f"7:{len(matched)} rules match -> invalid"]
    rule = matched[0]
    t.append(f"7:exactly one rule ({rule['rule_id']})")

    # Step 8 REQUIRES (ordered substeps)
    known_predicates = {"classification_registry_membership"}
    for req in rule["requires"]:
        if "predicate" in req and req["predicate"] not in known_predicates:
            return "invalid", [*t, f"8a:unevaluable predicate {req['predicate']}"]  # 8a
    for req in rule["requires"]:  # 8b membership (only per-rule predicate)
        if (
            req.get("predicate") == "classification_registry_membership"
            and (subject["connector_identity"], subject["canonical_tool_name"]) not in MEMBERS
        ):
            return "no_derivation", [*t, "8b:membership absent -> no_derivation"]
    for req in rule["requires"]:  # 8c enforcement
        if "fact" in req and fact_at(req["fact"]) != req["value"]:
            return "no_derivation", [*t, f"8c:{req['fact']} != {req['value']} -> no_derivation"]
    t.append("8:requires ok")

    # Step 9 DERIVE
    return "valid", [*t, f"9:derive {rule['derives']['authorized_action']}"]


def main():
    fails = 0
    for v in CORPUS["vectors"]:
        got, tr = execute(v["facts"], v.get("given", {}))
        want = v["expected"]["outcome"]
        ok = got == want
        fails += not ok
        print(f"{'OK ' if ok else 'XX '}{v['id']:<50} got={got:<13} want={want}")
        if not ok:
            for line in tr:
                print(f"      {line}")
    print(f"\n{len(CORPUS['vectors'])} vectors, {fails} mismatch")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
