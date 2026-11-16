#!/usr/bin/env python3
"""Reference builder for keel.review_document.v2 documents (registries v2 and v3).

Not the product. Builds a review document from
`review_document_templates/v2.json` or `v3.json` by hand, from the registry alone, so a
second implementation (keel-api) can check it produces the same bytes and
digest. Every choice the registry does not state is a registry gap.

A document is built from one Permit's inputs:

- `semantic_id`: the Permit's trusted semantic;
- `exact_facts`: its signed exact facts (top-level keys, as bound);
- `subject_facts`: facts opened from a gateway envelope, by dotted field id
  (tailored templates only);
- `review`: the Review's fields a template reads (`cause`);
- `permit_id` and the requester's explanation.

A tailored template applies when its `semantic_id` and `fact_profile_id`
match. Otherwise the generic rule set applies, from the pinned fact profile
and presentation profile. Anything else has no document.

Run with `--write-vectors [--version N]` to recompute the expected outputs of
`review_document_templates/test-vectors/vN.json` (default the newest) from
its inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import rfc8785
from review_document_tailored import Rules as TailoredRules

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_VERSIONS = (2, 3)


def registry_path(version: int) -> str:
    return f"review_document_templates/v{version}.json"


def vectors_path(version: int) -> str:
    return f"review_document_templates/test-vectors/v{version}.json"
_BIDI_CONTROLS = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))


class NoDocument(RuntimeError):
    """No template or rule set applies to these inputs."""


def load_registry(
    root: Path = ROOT, version: int = REGISTRY_VERSIONS[-1]
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]]]:
    raw = (root / registry_path(version)).read_bytes()
    registry = json.loads(raw)
    sources: dict[str, dict[str, Any]] = {}
    for name, pin in registry["source_registries"].items():
        source_raw = (root / pin["path"]).read_bytes()
        if "sha256:" + hashlib.sha256(source_raw).hexdigest() != pin["digest"]:
            raise NoDocument(f"{pin['path']} does not match its pinned digest")
        source = json.loads(source_raw)
        if source.get("version") != pin["version"]:
            raise NoDocument(f"{pin['path']} is not {pin['version']}")
        sources[name] = source
    return registry, hashlib.sha256(raw).hexdigest(), sources


# ---------------------------------------------------------------------------
# Value rules
# ---------------------------------------------------------------------------


def clean_text(value: Any, text_rule: Mapping[str, Any], *, limit: int | None = None) -> str | None:
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize(text_rule["normalization"], value).strip()
    kept = set(text_rule["kept_characters"])
    removed = set(text_rule["removed_categories"])
    cleaned = "".join(
        char
        for char in text
        if char in kept or (char not in _BIDI_CONTROLS and unicodedata.category(char) not in removed)
    ).strip()
    if not cleaned:
        return None
    return cleaned[: limit if limit is not None else int(text_rule["max_chars"])]


def label_for(key: str, rule: Mapping[str, Any]) -> str:
    text = key
    for suffix in rule["strip_suffixes"]:
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    separator = rule["word_separator"]
    words = [word for word in text.split(separator) if word and word not in rule["remove_tokens"]]
    text = " ".join(words)
    return text[:1].upper() + text[1:]


def is_money_key(key: str, amount_rule: Mapping[str, Any], separator: str = "_") -> bool:
    return amount_rule["money_key_token"] in key.split(separator)


def group(value: int, separator: str) -> str:
    return f"{value:,}".replace(",", separator)


def is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def money(amount: int, currency: Any, amount_rule: Mapping[str, Any], separator: str) -> str:
    iso = currency.strip().upper() if isinstance(currency, str) else ""
    spec = amount_rule["currencies"].get(iso)
    if spec is None:
        unit = iso or amount_rule["missing_currency_unit"]
        return f"{group(amount, separator)} {unit}{amount_rule['unknown_currency_suffix']}"
    exponent = int(spec["exponent"])
    sign = "-" if amount < 0 else ""
    whole, fraction = divmod(abs(amount), 10**exponent)
    text = group(whole, separator)
    if exponent:
        text += "." + str(fraction).zfill(exponent)
    return f"{sign}{spec['prefix']}{text}"


def code_text(value: str, values_rule: Mapping[str, Any]) -> str | None:
    acronyms = set(values_rule["acronyms"])
    words = [word for word in value.split(values_rule["code_word_separator"]) if word]
    if not words:
        return None
    return " ".join(word.upper() if word in acronyms else word[:1].upper() + word[1:] for word in words)


def scalar_text(value: Any, values_rule: Mapping[str, Any]) -> str | None:
    if isinstance(value, bool):
        return values_rule["boolean"]["true" if value else "false"]
    if is_integer(value):
        return group(value, values_rule["integer_group_separator"])
    if isinstance(value, str):
        if re.fullmatch(values_rule["code_pattern"], value):
            coded = code_text(value, values_rule)
            if coded is not None:
                return coded
        return clean_text(value, values_rule["text"])
    return None


# ---------------------------------------------------------------------------
# Generic rule set
# ---------------------------------------------------------------------------


class GenericPlan:
    """Which facts of one fact profile are shown in clear, hidden or left out."""

    def __init__(self, rules: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
        self.rules = rules
        self.profile = profile
        self.fields = [dict(field, key=field["path"][1:]) for field in profile["fields"]]
        self.by_key = {field["key"]: field for field in self.fields}
        self.targets = {path[1:] for path in profile["target_fact_paths"]}
        self.material = [path[1:] for path in profile["material_request_fact_paths"]]

    def omitted(self, key: str) -> bool:
        omit = self.rules["omit"]
        field = self.by_key[key]
        return (
            key in omit["fact_keys"]
            or any(key.endswith(suffix) for suffix in omit["key_suffixes"])
            or field["value_type"] in omit["value_types"]
        )

    def hidden(self, key: str) -> bool:
        rule = self.rules["disclosure"]
        field = self.by_key[key]
        if field["value_type"] in rule["hidden_value_types"]:
            return True
        if rule["hide_target_fact_paths"] and key in self.targets:
            return True
        if field["disclosure"][rule["audience"]] != rule["clear_disclosure"]:
            return True
        return field["classification"] not in rule["clear_classifications"]

    def clear(self, key: str) -> bool:
        return key in self.by_key and not self.omitted(key) and not self.hidden(key)


def from_base(key: str, rule: Mapping[str, str]) -> str | None:
    """The shared base of a pair's first fact: `current_x` → `x`, `x_before` → `x`."""

    if "prefix" in rule and key.startswith(rule["prefix"]):
        return key[len(rule["prefix"]) :] or None
    if "suffix" in rule and key.endswith(rule["suffix"]):
        return key[: -len(rule["suffix"])] or None
    return None


def affix(base: str, rule: Mapping[str, str]) -> str:
    return rule["prefix"] + base if "prefix" in rule else base + rule["suffix"]


def _presentation(sources: Mapping[str, dict[str, Any]], semantic_id: str, fallback_id: str) -> dict[str, Any]:
    registry = sources["presentation_registry"]
    matches = [profile for profile in registry["profiles"] if profile.get("semantic_id") == semantic_id]
    if len(matches) == 1:
        return matches[0]
    fallback = [
        profile for profile in registry["fallback_profiles"] if profile["presentation_profile_id"] == fallback_id
    ]
    if len(fallback) != 1:
        raise NoDocument(f"fallback presentation profile {fallback_id} is not defined")
    return fallback[0]


def _sentence(text: str, rule: Mapping[str, Any]) -> str:
    for word in rule["remove_words"]:
        text = re.sub(rf"\b{re.escape(word)}\s+", "", text, flags=re.IGNORECASE)
    text = " ".join(text.split())
    end = rule["terminal_punctuation"]
    return text if text.endswith((".", "!", "?")) else text + end


def _field(
    field_id: str, label: str, value: str | None, labels: Mapping[str, str], *, hidden: bool = False
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "field_id": field_id,
        "label": label,
        "value": value,
        "provenance": "keel_checked",
        "provenance_label": labels["keel_checked"],
    }
    if hidden:
        entry["hidden"] = True
    return entry


def build_generic(
    registry: Mapping[str, Any],
    sources: Mapping[str, dict[str, Any]],
    *,
    semantic_id: str,
    exact_facts: Mapping[str, Any],
    review: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    rules = registry["generic"]
    profile_id = exact_facts.get("fact_profile_id")
    profiles = [p for p in sources["fact_profiles"]["profiles"] if p["fact_profile_id"] == profile_id]
    if len(profiles) != 1 or semantic_id not in profiles[0]["semantic_ids"]:
        raise NoDocument("no pinned fact profile for this semantic")
    semantics = [e for e in sources["semantic_registry"]["entries"] if e["semantic_id"] == semantic_id]
    if len(semantics) != 1 or semantics[0].get("fact_profile_id") != profile_id:
        raise NoDocument("the pinned semantic registry does not select this fact profile")
    profile = profiles[0]
    plan = GenericPlan(rules, profile)
    labels = {kind["id"]: kind["label"] for kind in registry["provenance_kinds"]}
    values_rule = rules["values"]
    amount_rule = rules["amount"]
    separator = values_rule["integer_group_separator"]
    currency = exact_facts.get(amount_rule["currency_fact"])

    def present(key: str) -> bool:
        return exact_facts.get(key) is not None

    def shown(key: str) -> str | None:
        value = exact_facts.get(key)
        if is_integer(value) and is_money_key(key, amount_rule, rules["labels"]["word_separator"]):
            return money(value, currency, amount_rule, separator)
        return scalar_text(value, values_rule)

    cards: list[dict[str, Any]] = []
    used: set[str] = set()

    # Amount card: the first clear *amount_minor integer in profile order that
    # is not a before/after/remaining-style amount, else the first of any.
    candidates = [
        field["key"]
        for field in plan.fields
        if field["key"].endswith(amount_rule["key_suffix"])
        and plan.clear(field["key"])
        and is_integer(exact_facts.get(field["key"]))
    ]
    primary = [key for key in candidates if not any(word in key for word in amount_rule["primary_excludes"])]
    amount_key = (primary or candidates or [None])[0]
    if amount_key is not None:
        iso = currency.strip().upper() if isinstance(currency, str) and currency.strip() else None
        cards.append(
            {
                "card_id": amount_key,
                "kind": "amount",
                "label": label_for(amount_key, rules["labels"]),
                "value": shown(amount_key),
                "currency": iso,
                "field_ids": [amount_key],
                "provenance": "keel_checked",
                "provenance_label": labels["keel_checked"],
            }
        )
        used.add(amount_key)

    # Change cards: pairs of displayable scalar facts, in profile order.
    change_types = set(rules["changes"]["value_types"])

    def pairable(key: str) -> bool:
        field = plan.by_key.get(key)
        return (
            field is not None
            and key not in used
            and field["value_type"] in change_types
            and not plan.omitted(key)
            and present(key)
        )

    for field in plan.fields:
        if len([card for card in cards if card["kind"] == "change"]) >= rules["changes"]["max_cards"]:
            break
        key = field["key"]
        for pair in rules["changes"]["pairs"]:
            base = from_base(key, pair["from"])
            if not base:
                continue
            to_key = next(
                (
                    candidate
                    for candidate in (affix(base, option) for option in pair["to"])
                    if candidate in plan.by_key and present(candidate)
                ),
                None,
            )
            if to_key is None or not pairable(key) or not pairable(to_key):
                continue
            if plan.hidden(key) and plan.hidden(to_key):
                continue
            hidden_text = rules["disclosure"]["hidden_text"]
            card: dict[str, Any] = {
                "card_id": key,
                "kind": "change",
                "label": label_for(base, rules["labels"]),
                "from": hidden_text if plan.hidden(key) else shown(key),
                "to": hidden_text if plan.hidden(to_key) else shown(to_key),
                "field_ids": [key, to_key],
                "provenance": "keel_checked",
                "provenance_label": labels["keel_checked"],
            }
            hidden_sides = [side for side, fact in (("from", key), ("to", to_key)) if plan.hidden(fact)]
            if hidden_sides:
                card["hidden"] = hidden_sides
            cards.append(card)
            used.update((key, to_key))
            break

    # Rows: every other fact in profile order. Present facts that are not left
    # out are shown in clear or as Hidden; a missing material fact is listed
    # with no value so the reviewer sees what is missing.
    material = set(plan.material)
    rows: list[dict[str, Any]] = []
    provenance: dict[str, str] = {}
    for field in plan.fields:
        key = field["key"]
        if key in used:
            provenance[key] = "keel_checked"
            continue
        label = label_for(key, rules["labels"])
        if not present(key):
            if key in material:
                rows.append(_field(key, label, None, labels))
                provenance[key] = "keel_checked"
            continue
        if plan.omitted(key):
            continue
        if plan.hidden(key):
            rows.append(_field(key, label, rules["disclosure"]["hidden_text"], labels, hidden=True))
        else:
            text = shown(key)
            if text is None:
                continue
            rows.append(_field(key, label, text, labels))
        provenance[key] = "keel_checked"

    sections: list[dict[str, Any]] = []
    for section in rules["sections"]:
        if section["content"] == "exact_facts":
            fields = rows
        else:
            fields = []
            for spec in section["fields"]:
                value = review.get(spec["field_id"]) if spec["source"] == "review" else None
                fields.append(
                    {
                        "field_id": spec["field_id"],
                        "label": spec["label"],
                        "value": value if isinstance(value, str) and value else None,
                        "provenance": spec["provenance"],
                        "provenance_label": labels[spec["provenance"]],
                    }
                )
                provenance[spec["field_id"]] = spec["provenance"]
        if fields:
            sections.append({"section_id": section["section_id"], "label": section["label"], "fields": fields})

    missing = [key for key in plan.material if not present(key)]
    presentation = _presentation(sources, semantic_id, rules["fallback_presentation_profile_id"])
    document = {
        "template_id": rules["template_id"],
        "template_kind": "generic",
        "semantic_id": semantic_id,
        "fact_profile_id": profile_id,
        "presentation_profile_id": presentation["presentation_profile_id"],
        "title": presentation[rules["title"]["presentation_field"]],
        "sentence": _sentence(presentation[rules["sentence"]["presentation_field"]], rules["sentence"]),
        "cards": cards,
        "sections": sections,
        "beneficiary": None,
    }
    return document, missing, provenance


# ---------------------------------------------------------------------------
# Tailored templates (the v1 shape)
# ---------------------------------------------------------------------------


def build_tailored(
    registry: Mapping[str, Any],
    template: Mapping[str, Any],
    *,
    exact_facts: Mapping[str, Any],
    subject_facts: Mapping[str, Any],
    review: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    labels = {kind["id"]: kind["label"] for kind in registry["provenance_kinds"]}
    text_rule = registry["generic"]["values"]["text"]
    tailored = TailoredRules(registry, money=money, clean_text=clean_text)
    missing: list[str] = []
    provenance: dict[str, str] = {}
    sections = []
    for section in template["sections"]:
        fields = []
        for field in section["fields"]:
            source = field["source"]
            field_id = field["field_id"]
            if source == "exact_facts":
                value = exact_facts.get(field_id)
            elif source == "subject_facts":
                value = subject_facts.get(field_id)
            elif source == "review":
                value = review.get(field_id)
            else:
                value = field.get("constant")
            if source == "exact_facts" and "format" in field:
                # Phase 3 field formats (amount, request code, Hidden, ...).
                shown = tailored.display(field, exact_facts)
            elif value is None:
                shown = None
            else:
                key = ("true" if value else "false") if isinstance(value, bool) else str(value)
                shown = field["values"].get(key) if isinstance(field.get("values"), Mapping) else key
            if source == "subject_facts" and isinstance(shown, str):
                shown = clean_text(shown, text_rule, limit=256)
            if shown is None and field["essential"]:
                missing.append(field_id)
            provenance[field_id] = field["provenance"]
            entry: dict[str, Any] = {
                "field_id": field_id,
                "label": field["label"],
                "value": shown,
                "provenance": field["provenance"],
                "provenance_label": labels[field["provenance"]],
            }
            if "commitment" in field:
                entry["checked_against"] = field["commitment"]
            if field.get("format") == "hidden" and shown is not None:
                entry["hidden"] = True
            fields.append(entry)
        sections.append({"section_id": section["section_id"], "label": section["label"], "fields": fields})
    document = {
        "template_id": template["template_id"],
        "template_kind": "tailored",
        "semantic_id": template["semantic_id"],
        "fact_profile_id": template["fact_profile_id"],
        "presentation_profile_id": template["presentation_profile_id"],
        "title": template["title"],
        "sentence": tailored.sentence(template.get("sentence"), exact_facts)[0],
        "cards": tailored.cards(template.get("cards", []), exact_facts, labels["keel_checked"]),
        "sections": sections,
        "beneficiary": template.get("beneficiary"),
    }
    return document, missing, provenance


def build(
    registry: Mapping[str, Any],
    registry_digest: str,
    sources: Mapping[str, dict[str, Any]],
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    semantic_id = inputs["semantic_id"]
    exact = inputs.get("exact_facts") or {}
    review = inputs.get("review") or {}
    matches = [
        template
        for template in registry["templates"]
        if template["semantic_id"] == semantic_id and template["fact_profile_id"] == exact.get("fact_profile_id")
    ]
    if len(matches) == 1:
        body, missing, provenance = build_tailored(
            registry, matches[0], exact_facts=exact, subject_facts=inputs.get("subject_facts") or {}, review=review
        )
        explanation_spec = matches[0]["requester_explanation"]
    elif any(template["semantic_id"] == semantic_id for template in registry["templates"]):
        raise NoDocument("the tailored template's fact profile does not match")
    else:
        body, missing, provenance = build_generic(
            registry, sources, semantic_id=semantic_id, exact_facts=exact, review=review
        )
        explanation_spec = registry["generic"]["requester_explanation"]
    document = {
        "format": registry["document_format"],
        "registry_version": registry["version"],
        "registry_digest": registry_digest,
        "permit_id": inputs["permit_id"],
        **body,
        "requester_explanation": {
            "label": explanation_spec["label"],
            "provenance": explanation_spec["provenance"],
            "authoritative": False,
            "text": clean_text(
                inputs.get("requester_explanation"),
                registry["generic"]["values"]["text"],
                limit=int(explanation_spec["max_chars"]),
            ),
        },
    }
    document_bytes = rfc8785.dumps(document)
    return {
        "document": document,
        "digest": hashlib.sha256(document_bytes).hexdigest(),
        "missing_essential": missing,
        "fact_provenance": provenance,
    }


def run_vectors(root: Path = ROOT, *, write: bool = False, version: int = REGISTRY_VERSIONS[-1]) -> int:
    registry, registry_digest, sources = load_registry(root, version)
    path = root / vectors_path(version)
    corpus = json.loads(path.read_text(encoding="utf-8"))
    mismatches = 0
    for vector in corpus["vectors"]:
        try:
            got: dict[str, Any] = build(registry, registry_digest, sources, vector["inputs"])
        except NoDocument:
            got = {"no_document": True}
        if write:
            vector["expected"] = got
            continue
        if got != vector["expected"]:
            mismatches += 1
            print(f"MISMATCH {vector['id']}")
        else:
            print(f"OK {vector['id']:<48} digest={got.get('digest', 'no document')[:16]}")
    if write:
        path.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {len(corpus['vectors'])} vectors")
        return 0
    print(f"\n{len(corpus['vectors'])} vectors, {mismatches} mismatch")
    return 1 if mismatches else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    chosen = int(args[args.index("--version") + 1]) if "--version" in args else REGISTRY_VERSIONS[-1]
    sys.exit(run_vectors(write="--write-vectors" in args, version=chosen))
