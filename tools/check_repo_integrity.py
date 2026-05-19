#!/usr/bin/env python3
"""Repository-level checks for public spec consistency."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
CODE_RE = re.compile(r"`([A-Z][A-Z0-9_]+)`")

EXAMPLE_SCHEMA_PAIRS = [
    ("examples/permit-allow.json", "schemas/permit-v1.schema.json"),
    ("examples/permit-deny.json", "schemas/permit-v1.schema.json"),
    ("examples/chain-entry.json", "schemas/chain-entry.schema.json"),
    ("examples/closure-v2-closed.json", "schemas/closure-v2.schema.json"),
    ("examples/audit-export-bundle-v2.json", "schemas/audit-export-bundle.schema.json"),
]


def git_files() -> list[Path]:
    files: list[Path] = []
    for args in (["git", "ls-files"], ["git", "ls-files", "--others", "--exclude-standard"]):
        proc = subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True)
        files.extend(ROOT / line for line in proc.stdout.splitlines() if line)
    return sorted(set(files))


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def check_json_parse(files: list[Path], errors: list[str]) -> None:
    for path in files:
        if path.suffix != ".json":
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - report parser detail.
            fail(errors, f"{path.relative_to(ROOT)}: invalid JSON: {exc}")


def check_markdown_links(files: list[Path], errors: list[str]) -> None:
    for path in files:
        if path.suffix != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = match.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = target.strip("<>")
            local = target.split("#", 1)[0]
            if not local:
                continue
            if local.startswith("/"):
                fail(errors, f"{path.relative_to(ROOT)}: absolute local link: {target}")
                continue
            resolved = (path.parent / local).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                continue
            if not resolved.exists():
                line_no = text[: match.start()].count("\n") + 1
                fail(errors, f"{path.relative_to(ROOT)}:{line_no}: missing link target {target}")


def collect_failure_codes(node: Any, codes: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"failure_code", "failure_codes", "expected_failure_codes", "primary_failure_code"}:
                if isinstance(value, str):
                    codes.add(value)
                elif isinstance(value, list):
                    codes.update(item for item in value if isinstance(item, str))
            collect_failure_codes(value, codes)
    elif isinstance(node, list):
        for item in node:
            collect_failure_codes(item, codes)


def check_failure_codes(files: list[Path], errors: list[str]) -> None:
    defined = set(CODE_RE.findall((ROOT / "spec/failure-codes.md").read_text(encoding="utf-8")))
    used: set[str] = set()
    for path in files:
        if path.suffix != ".json":
            continue
        try:
            collect_failure_codes(json.loads(path.read_text(encoding="utf-8")), used)
        except Exception:
            continue

    for code in sorted(code for code in used if code and code not in defined):
        fail(errors, f"failure code {code} is used in JSON fixtures but not defined in spec/failure-codes.md")


def check_manifest_summary(errors: list[str]) -> None:
    manifest = json.loads((ROOT / "test-vectors/MANIFEST.json").read_text(encoding="utf-8"))
    categories = manifest["categories"]
    vectors = [vector for category in categories for vector in category["vectors"]]
    summary = manifest["summary"]

    computed = {
        "total_categories": len(categories),
        "total_planned_vectors": len(vectors),
        "mvp_v0_1_count": sum(1 for vector in vectors if vector.get("priority") == "mvp_v0_1"),
        "deferred_post_v0_1_count": sum(1 for vector in vectors if vector.get("priority") == "deferred_post_v0_1"),
        "scaffolded": sum(1 for vector in vectors if vector.get("status") == "scaffolded"),
        "todo": sum(1 for vector in vectors if vector.get("status") == "TODO"),
    }
    for key, value in computed.items():
        if summary.get(key) != value:
            fail(errors, f"test-vectors/MANIFEST.json summary.{key}={summary.get(key)!r}, expected {value!r}")

    priority_mvp = {
        f"{category['id']}/{vector['id']}"
        for category in categories
        for vector in category["vectors"]
        if vector.get("priority") == "mvp_v0_1"
    }
    milestone_mvp = set(manifest["version_milestones"]["v0.1"]["vector_ids"])
    if priority_mvp != milestone_mvp:
        missing = sorted(priority_mvp - milestone_mvp)
        extra = sorted(milestone_mvp - priority_mvp)
        fail(errors, f"v0.1 milestone mismatch; missing={missing}, extra={extra}")


def check_examples_against_schemas(require_jsonschema: bool, errors: list[str]) -> None:
    try:
        import jsonschema
    except ImportError:
        if require_jsonschema:
            fail(errors, "jsonschema is required but is not installed")
        else:
            print("jsonschema not installed; skipping example schema validation.")
        return

    for example_path, schema_path in EXAMPLE_SCHEMA_PAIRS:
        instance = json.loads((ROOT / example_path).read_text(encoding="utf-8"))
        schema = json.loads((ROOT / schema_path).read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        failures = sorted(validator.iter_errors(instance), key=lambda err: list(err.path))
        if failures:
            first = failures[0]
            location = ".".join(str(part) for part in first.path) or "<root>"
            fail(errors, f"{example_path} fails {schema_path} at {location}: {first.message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-jsonschema", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []
    files = git_files()
    check_json_parse(files, errors)
    check_markdown_links(files, errors)
    check_failure_codes(files, errors)
    check_manifest_summary(errors)
    check_examples_against_schemas(args.require_jsonschema, errors)

    if errors:
        print("Repository integrity check failed:")
        for error in errors:
            print(f"  {error}")
        return 1

    print("Repository integrity check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
