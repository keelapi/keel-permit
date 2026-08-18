#!/usr/bin/env python3
"""Assert that fact-profile v1 stays frozen and v2 keeps its stronger rule.

A frozen evidence format is only frozen if something enforces it. v1 does not
constrain salt generation for commitments over low-entropy values; v2 does,
through an operative disclosure contract. That difference is the reason evidence
pinned to v1 carries a weaker hiding guarantee than evidence pinned to v2.

Repairing v1 by tightening it would change what already-issued v1 evidence
means, so the correct posture is to keep v1 exactly as it was and require new
issuance to use v2. This check makes both halves of that posture verifiable:

- v1 MUST NOT acquire the v2 low-entropy disclosure contract. If someone
  "fixes" v1 later, this fails, because that fix would silently reinterpret
  historical evidence.
- v2 MUST keep it. If the successor's stronger rule is dropped or weakened,
  this fails, because then there is nowhere for new issuance to go.

Note on scope: the >=128-bit magnitude is stated in prose, in
spec/permit-universal-verification-v1.md section 8. What is machine-checkable
here is the presence of the disclosure contract and the per-field low-entropy
flags, so that is what this asserts. Claiming to verify the bit-length would
overstate what the registries encode.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_KEY = "plain_hash_for_low_entropy_forbidden"


def load(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "fact_profiles" / name).read_text(encoding="utf-8"))


def disclosure_contract(registry: dict[str, Any]) -> dict[str, Any]:
    contract = registry.get("disclosure_contract")
    return contract if isinstance(contract, dict) else {}


def low_entropy_flagged_fields(registry: dict[str, Any]) -> int:
    count = 0
    for profile in registry.get("profiles", []):
        if not isinstance(profile, dict):
            continue
        for field in profile.get("fields", []):
            if isinstance(field, dict) and "low_entropy_possible" in field:
                count += 1
    return count


def main() -> int:
    errors: list[str] = []

    v1, v2 = load("v1.json"), load("v2.json")

    # v1 is frozen: it never carried the low-entropy disclosure contract, and
    # acquiring one now would reinterpret evidence already issued under it.
    if CONTRACT_KEY in disclosure_contract(v1):
        errors.append(
            f"fact_profiles/v1.json declares {CONTRACT_KEY}. v1 is frozen; adding the v2 "
            "low-entropy contract would change the meaning of evidence already issued under v1. "
            "Publish the stronger rule in a successor profile instead."
        )
    if low_entropy_flagged_fields(v1):
        errors.append(
            "fact_profiles/v1.json carries per-field low_entropy_possible flags. Those are a v2 "
            "construct; v1 must remain as issued."
        )

    # v2 is where new issuance goes: its stronger rule must stay in force.
    if disclosure_contract(v2).get(CONTRACT_KEY) is not True:
        errors.append(
            f"fact_profiles/v2.json must declare disclosure_contract.{CONTRACT_KEY} = true. "
            "It is the operative successor to v1's unconstrained salt handling."
        )
    v2_flagged = low_entropy_flagged_fields(v2)
    if v2_flagged == 0:
        errors.append(
            "fact_profiles/v2.json declares no per-field low_entropy_possible flags, so the "
            "disclosure contract has nothing to apply to."
        )

    if errors:
        print("Fact-profile freeze check failed:")
        for error in errors:
            print(f"  {error}")
        return 1

    print(
        "Fact-profile freeze check passed: v1 remains free of the low-entropy disclosure "
        f"contract, v2 declares it over {v2_flagged} flagged fields."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
