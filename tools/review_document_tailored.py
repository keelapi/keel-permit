#!/usr/bin/env python3
"""Reference rules for tailored review templates: field formats, sentences, cards.

Not the product. The second implementation (keel-api
`app/services/review_document_formats.py`) must produce the same text for the
same exact facts, because the text is part of the document bytes a review
decision binds to.

Every format returns ``None`` when the fact is absent or has an unexpected
shape; the builder then counts an essential field as missing and Approve is
refused. Nothing is guessed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
SLOT = re.compile(r"\{([a-z_]+)\}")

FORMATS = ("amount", "byte_count", "code", "count", "hidden", "recorded", "request_code", "text", "timestamp_utc")
CODE_SEPARATORS = re.compile(r"[._\-/\s]+")
NOT_RECORDED = "Not recorded"
RECORDED = "Current state recorded"


def code(value: Any, acronyms: set[str]) -> str | None:
    """``stripe.payment_intent.create`` → ``Stripe Payment Intent Create``.

    The dashboard's rule for showing a code to a person: split on dots,
    underscores, hyphens, slashes and spaces; the registry's acronyms in
    capitals, every other word with a capital first letter.
    """

    if not isinstance(value, str):
        return None
    words = [word for word in CODE_SEPARATORS.split(value.strip().lower()) if word]
    if not words:
        return None
    return " ".join(word.upper() if word in acronyms else word[:1].upper() + word[1:] for word in words)


def request_code(value: Any) -> str | None:
    """``sha256:4f2a91c0…`` → ``4F2A-91C0``: a matching aid, not an identifier."""

    if not isinstance(value, str):
        return None
    match = DIGEST.fullmatch(value)
    if match is None:
        return None
    head = match.group(1)[:8].upper()
    return f"{head[:4]}-{head[4:]}"


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def count(value: Any, separator: str) -> str | None:
    if not _is_integer(value) or value < 0:
        return None
    return f"{value:,}".replace(",", separator)


def byte_count(value: Any, separator: str) -> str | None:
    shown = count(value, separator)
    if shown is None:
        return None
    return f"{shown} byte" if value == 1 else f"{shown} bytes"


def timestamp_utc(value: Any) -> str | None:
    """Truncated to the minute, never rounded up: a deadline never reads later."""

    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def hidden(value: Any, hidden_text: str) -> str | None:
    if not isinstance(value, Mapping):
        return None
    digest = value.get("digest")
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        return None
    return hidden_text


def recorded(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if DIGEST.fullmatch(value) is None and RAW_DIGEST.fullmatch(value) is None:
        return None
    return RECORDED


class Rules:
    """The generic rule set's value, amount and disclosure rules, reused by tailored templates."""

    def __init__(self, registry: Mapping[str, Any], *, money, clean_text) -> None:
        generic = registry["generic"]
        self.values = generic["values"]
        self.amount = generic["amount"]
        self.hidden_text = generic["disclosure"]["hidden_text"]
        self.separator = self.values["integer_group_separator"]
        self._money = money
        self._clean_text = clean_text

    def display(self, spec: Mapping[str, Any], exact: Mapping[str, Any]) -> str | None:
        if "constant" in spec:
            return spec["constant"]
        value = exact.get(spec["field_id"])
        if value is None:
            return None
        labels = spec.get("values")
        if isinstance(labels, Mapping):
            key = ("true" if value else "false") if isinstance(value, bool) else str(value)
            return labels.get(key)
        name = spec.get("format")
        if name is None:
            if isinstance(value, (Mapping, list)):
                return None
            text = ("true" if value else "false") if isinstance(value, bool) else str(value)
            return self._clean_text(text, self.values["text"])
        if name == "amount":
            if not _is_integer(value):
                return None
            return self._money(value, exact.get(self.amount["currency_fact"]), self.amount, self.separator)
        if name == "text":
            return self._clean_text(value, self.values["text"])
        if name == "request_code":
            return request_code(value)
        if name == "code":
            return code(value, set(self.values["acronyms"]))
        if name == "count":
            return count(value, self.separator)
        if name == "byte_count":
            return byte_count(value, self.separator)
        if name == "timestamp_utc":
            return timestamp_utc(value)
        if name == "hidden":
            return hidden(value, self.hidden_text)
        if name == "recorded":
            return recorded(value)
        raise ValueError(f"unknown field format {name}")

    def sentence(self, sentence: Any, exact: Mapping[str, Any]) -> tuple[str | None, list[str]]:
        """A string is a constant sentence; an object picks a variant and fills its slots once."""

        if sentence is None or isinstance(sentence, str):
            return sentence, []
        chosen = next(item for item in sentence["variants"] if matches(item.get("when", {}), exact))
        slots = sentence.get("slots", {})
        missing: list[str] = []

        def fill(match: re.Match[str]) -> str:
            spec = slots[match.group(1)]
            shown = self.display(spec, exact)
            if shown is None:
                if spec["field_id"] not in missing:
                    missing.append(spec["field_id"])
                return NOT_RECORDED
            return shown

        return SLOT.sub(fill, chosen["text"]), missing

    def cards(
        self, cards: list[Mapping[str, Any]], exact: Mapping[str, Any], provenance_label: str
    ) -> list[dict[str, Any]]:
        rendered: list[dict[str, Any]] = []
        for card in cards:
            if card["kind"] == "amount":
                currency = exact.get(self.amount["currency_fact"])
                entry: dict[str, Any] = {
                    "card_id": card["card_id"],
                    "kind": "amount",
                    "label": card["label"],
                    "value": self.display({"field_id": card["field_id"], "format": "amount"}, exact),
                    "currency": currency.strip().upper() if isinstance(currency, str) and currency.strip() else None,
                    "field_ids": [card["field_id"]],
                }
            elif card["kind"] == "change":
                entry = {
                    "card_id": card["card_id"],
                    "kind": "change",
                    "label": card["label"],
                    "from": self.display(card["from"], exact),
                    "to": self.display(card["to"], exact),
                    "field_ids": [side["field_id"] for side in (card["from"], card["to"]) if "field_id" in side],
                }
            else:
                raise ValueError(f"unknown card kind {card['kind']}")
            entry["provenance"] = "keel_checked"
            entry["provenance_label"] = provenance_label
            rendered.append(entry)
        return rendered


def matches(conditions: Mapping[str, Any], exact: Mapping[str, Any]) -> bool:
    """Type-strict equality: ``1`` never matches ``true``."""

    for fact, expected in conditions.items():
        actual = exact.get(fact)
        if type(actual) is not type(expected) or actual != expected:
            return False
    return True
