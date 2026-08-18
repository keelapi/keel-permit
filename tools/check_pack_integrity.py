#!/usr/bin/env python3
"""Verify the verifier-claim corpus packs match their declared integrity claims.

Every corpus record that declares a pack also declares a manifest carrying a
`content_hash` over the export file. Those hashes were previously unenforced:
nothing extracted an archive or recomputed a digest, so a fixture could drift
from its own manifest and the corpus would quietly stop meaning what it says.

Checks performed:

1. Every file path referenced by a corpus record exists on disk.
2. Every declared `content_hash` matches SHA-256 over the export file bytes.
3. Every archive member list matches the manifest's `files` declaration, so a
   binary fixture cannot gain or lose a member unnoticed.
4. Every compressed member decompresses and, where the payload is JSON or JSONL,
   parses -- which is what makes these archives reviewable rather than opaque.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = ROOT / "test-vectors/verifier_claims/v0"
CORPUS = CORPUS_ROOT / "corpus.json"
FIXTURE_REF_RE = re.compile(r"^(?:fixtures|trust_roots)/[\w./-]+$")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def referenced_paths(node: Any, found: set[str]) -> None:
    """Collect every fixture-relative path string anywhere in a record."""
    if isinstance(node, dict):
        for value in node.values():
            referenced_paths(value, found)
    elif isinstance(node, list):
        for item in node:
            referenced_paths(item, found)
    elif isinstance(node, str) and FIXTURE_REF_RE.match(node):
        found.add(node)


def expects_absence(record: dict[str, Any]) -> bool:
    """True when a record's expected failure is itself an absent artifact.

    Negative fixtures such as scope-faithfulness-neg-sidecar-missing declare a
    path and then deliberately omit the file, because the omission is the
    condition under test. Requiring those paths to exist would make the corpus
    unable to express a missing-evidence case.
    """
    codes = json.dumps(
        [record.get("expected_code"), record.get("expected_current"), record.get("claims")]
    ).upper()
    return "MISSING" in codes or "ABSENT" in codes


def check_referenced_files_exist(records: list[dict[str, Any]], errors: list[str]) -> tuple[int, int]:
    seen: set[str] = set()
    intentional = 0
    for record in records:
        refs: set[str] = set()
        referenced_paths(record, refs)
        seen |= refs
        for ref in sorted(refs):
            if (CORPUS_ROOT / ref).exists():
                continue
            if expects_absence(record):
                intentional += 1
                continue
            fail(errors, f"{record.get('id', '?')}: references missing file {ref}")
    return len(seen), intentional


def check_content_hash(export_path: Path, manifest: dict[str, Any], label: str, errors: list[str]) -> bool:
    declared = manifest.get("content_hash")
    if not isinstance(declared, str):
        return False
    actual = "sha256:" + hashlib.sha256(export_path.read_bytes()).hexdigest()
    if actual != declared:
        fail(
            errors,
            f"{label}: manifest content_hash {declared} does not match export bytes {actual}",
        )
    return True


def check_archive_members(export_path: Path, manifest: dict[str, Any], label: str, errors: list[str]) -> None:
    """A zip fixture must contain exactly the members its manifest declares."""
    if export_path.suffix != ".zip":
        return
    try:
        with zipfile.ZipFile(export_path) as archive:
            members = sorted(archive.namelist())
            for name in members:
                # Reviewability: every member must be extractable and, when it
                # claims to be JSON or JSONL, must parse.
                payload = archive.read(name)
                parse_json_payload(payload, f"{label}:{name}", errors)
    except zipfile.BadZipFile as exc:
        fail(errors, f"{label}: not a readable zip archive: {exc}")
        return

    declared_files = manifest.get("files")
    if not isinstance(declared_files, list):
        return
    declared = sorted(
        entry["name"] for entry in declared_files if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    )
    if declared != members:
        missing = sorted(set(declared) - set(members))
        extra = sorted(set(members) - set(declared))
        fail(errors, f"{label}: archive members do not match manifest files; missing={missing}, unexpected={extra}")


def parse_json_payload(payload: bytes, label: str, errors: list[str]) -> None:
    """Parse JSON or JSONL bytes, tolerating empty members."""
    text = payload.decode("utf-8", errors="strict") if payload else ""
    if not text.strip():
        return
    if label.endswith(".jsonl"):
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                fail(errors, f"{label}: line {lineno} is not valid JSON: {exc}")
        return
    if label.endswith(".json"):
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            fail(errors, f"{label}: not valid JSON: {exc}")


def check_gzip_member(export_path: Path, label: str, errors: list[str]) -> None:
    if export_path.suffix != ".gz":
        return
    try:
        payload = gzip.decompress(export_path.read_bytes())
    except OSError as exc:
        fail(errors, f"{label}: not a readable gzip member: {exc}")
        return
    inner = export_path.with_suffix("").name
    parse_json_payload(payload, f"{label}:{inner}", errors)


def main() -> int:
    errors: list[str] = []
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    records = corpus.get("records", [])
    if not records:
        print("corpus.json declares no records", file=sys.stderr)
        return 1

    ref_count, intentional_absences = check_referenced_files_exist(records, errors)

    hashed = archives = 0
    for record in records:
        pack = record.get("pack") or {}
        export_ref, manifest_ref = pack.get("export_file"), pack.get("manifest")
        if not export_ref or not manifest_ref:
            continue
        export_path, manifest_path = CORPUS_ROOT / export_ref, CORPUS_ROOT / manifest_ref
        label = record.get("id", export_ref)
        if not export_path.exists() or not manifest_path.exists():
            continue  # already reported by the reference check

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if check_content_hash(export_path, manifest, label, errors):
            hashed += 1
        if export_path.suffix in {".zip", ".gz"}:
            archives += 1
            check_archive_members(export_path, manifest, label, errors)
            check_gzip_member(export_path, label, errors)

    if errors:
        print("Pack integrity check failed:")
        for error in errors:
            print(f"  {error}")
        return 1

    print(
        f"Pack integrity check passed: {hashed} declared content hashes verified, "
        f"{archives} archives extracted and parsed, {ref_count} referenced paths resolved "
        f"({intentional_absences} intentionally absent in negative fixtures)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
