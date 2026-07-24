#!/usr/bin/env python3
"""Reference executor for keel.permit.action_classification_derivation.v1.

Not the product verifier. This executes the ruleset's normative decision_algorithm
by hand against the corpus, purely from the spec, to answer one question: can two
implementers run this algorithm and get identical outcomes for every vector without
making an undocumented choice? Every place this script had to decide something the
spec did not state is a spec gap and is flagged.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent
CORPUS = json.loads((HERE / "corpus.json").read_text())
RULESET = json.loads((HERE / ".." / ".." / ".." / "semantics" / "permit" / "action_classification_derivation_v1.json").read_text())["body"]
REGISTRY = json.loads((HERE / ".." / ".." / ".." / "semantics" / "permit" / "value_movement_classification_v1.json").read_text())

GRAMMAR = re.compile(RULESET["identifier_grammar"]["grammar"])
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
KNOWN_SUBJECT_KINDS = set(RULESET["classification_subject_variants"].keys())
REGISTRY_MEMBERS = {(e["connector_identity"], e["canonical_tool_name"])
                    for e in REGISTRY["body"]["entries"]}
PINNED_REGISTRY_DIGEST = "sha256:" + hashlib.sha256(
    (HERE / ".." / ".." / ".." / "semantics" / "permit" / "value_movement_classification_v1.json").read_bytes()
).hexdigest()


def _input_digest(ci, tn):
    obj = {"profile": "keel.registered_tool_classification_input.v1",
           "connector_identity": ci, "canonical_tool_name": tn}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def execute(facts, given):
    """Run decision_algorithm steps in order; first terminal step wins."""
    trace = []
    cls = facts.get("classification", {})
    subject = cls.get("subject", {})
    prov = cls.get("provenance", {})

    # Step 1 STRUCTURAL
    kind = subject.get("kind")
    if kind == "registered_tool":
        if not subject.get("connector_identity") or not subject.get("canonical_tool_name"):
            return "invalid", trace + ["1:structural: registered_tool missing required fields"]
    trace.append("1:structural ok")

    # Step 2 SUBJECT KIND
    if kind not in KNOWN_SUBJECT_KINDS:
        return "no_derivation", trace + [f"2:unknown subject kind {kind!r}"]
    trace.append("2:subject-kind known")

    # Step 3 IDENTIFIER GRAMMAR (validate the signed values directly)
    for label in ("connector_identity", "canonical_tool_name"):
        val = subject.get(label, "")
        if not GRAMMAR.match(val):
            return "invalid", trace + [f"3:grammar fail {label}={val!r}"]
    trace.append("3:grammar ok")

    # digest well-formedness is part of structural validity of a digest field
    reg_digest = prov.get("registry", {}).get("artifact_digest", "")
    if not DIGEST_RE.match(reg_digest):
        return "invalid", trace + [f"3b:malformed registry digest {reg_digest!r}"]

    # Step 4 DEPENDENCY RESOLUTION (resolve ONLY by embedded digest, from the
    # verifier's trusted set; unknown digest -> unverifiable, never substitute)
    trusted = set(given.get("trusted_registry_digests", []))
    if reg_digest not in trusted:
        return "unverifiable", trace + [f"4:registry digest {reg_digest[:14]}.. not in trusted set -> artifact_unavailable"]
    trace.append("4:dependency resolved by exact digest")

    # Step 5 ARTIFACT INTEGRITY: trusted set is integrity-verified by construction.
    # Step 6 INTERNAL DIGEST AGREEMENT: single registry digest field here; nothing to disagree.
    # (A future second signed digest field would be compared here.)

    # Step 7 INPUT DIGEST
    recomputed = _input_digest(subject["connector_identity"], subject["canonical_tool_name"])
    if prov.get("input", {}).get("digest") != recomputed:
        return "invalid", trace + ["7:input_digest mismatch"]
    trace.append("7:input_digest ok")

    # Step 8 RULE MATCH SET (evaluate ALL rules against the same facts)
    def fact_at(path):
        node = facts
        for part in path.split("."):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return node if not isinstance(node, dict) or node else (node if node != {} else None)

    matched = []
    for rule in RULESET["rules"]:
        if all(fact_at(c["fact"]) == c["value"]
               for c in rule["applies_when"]["all"] if c["op"] == "equals"):
            matched.append(rule)
    if len(matched) == 0:
        return "no_derivation", trace + ["8:zero rules match"]
    if len(matched) > 1:
        return "invalid", trace + [f"8:{len(matched)} rules match -> invalid"]
    rule = matched[0]
    trace.append(f"8:exactly one rule matched ({rule['rule_id']})")

    # Step 9 REQUIRES
    for req in rule["requires"]:
        if "predicate" in req:
            p = req["predicate"]
            if p == "classification_registry_membership":
                key = (subject["connector_identity"], subject["canonical_tool_name"])
                if key not in REGISTRY_MEMBERS:
                    return "no_derivation", trace + [f"9:{p} absent -> no_derivation"]
            elif p == "classification_registry_digest_match":
                if reg_digest != PINNED_REGISTRY_DIGEST:
                    return "invalid", trace + [f"9:{p} mismatch -> invalid"]
            elif p == "classification_input_digest_match":
                pass  # already checked at step 7
            else:
                return "unverifiable", trace + [f"9:unknown predicate {p}"]
        else:  # fact predicate
            if fact_at(req["fact"]) != req["value"]:
                # control.mode != enforced_in_path is a no_derivation per spec
                return "no_derivation", trace + [f"9:required fact {req['fact']} != {req['value']}"]
    trace.append("9:requires ok")

    # Step 10 DERIVE
    return "valid", trace + [f"10:derive {rule['derives']['authorized_action']}"]


def main():
    fails = 0
    for v in CORPUS["vectors"]:
        outcome, trace = execute(v["facts"], v.get("given", {}))
        expected = v["expected"]["outcome"]
        ok = outcome == expected
        fails += not ok
        mark = "OK " if ok else "XX "
        print(f"{mark}{v['id']:<52} got={outcome:<13} want={expected}")
        if not ok:
            for t in trace:
                print(f"      {t}")
    print(f"\n{len(CORPUS['vectors'])} vectors, {fails} mismatch")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
