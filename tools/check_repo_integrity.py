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
SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")

EXAMPLE_SCHEMA_PAIRS = [
    ("examples/permit-allow.json", "schemas/permit-v1.schema.json"),
    ("examples/permit-deny.json", "schemas/permit-v1.schema.json"),
    ("examples/chain-entry.json", "schemas/chain-entry.schema.json"),
    ("examples/closure-v2-closed.json", "schemas/closure-v2.schema.json"),
    ("examples/audit-export-bundle-v2.json", "schemas/audit-export-bundle.schema.json"),
    ("examples/require-co-signature.json", "schemas/require-co-signature-v1.schema.json"),
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
        except Exception as exc:
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


def check_claim_registry_v1_superset(errors: list[str]) -> None:
    """Prevent a successor registry from silently dropping released claims."""

    registries: dict[str, dict[str, Any]] = {}
    for version in ("v0", "v1"):
        path = ROOT / "claim_registry" / f"{version}.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(errors, f"{path.relative_to(ROOT)} could not be loaded: {exc}")
            return
        if not isinstance(payload, dict):
            fail(errors, f"{path.relative_to(ROOT)} must be a JSON object")
            return
        registries[version] = payload

    names: dict[str, list[str]] = {}
    for version, payload in registries.items():
        raw_claims = payload.get("claims")
        if not isinstance(raw_claims, list):
            fail(errors, f"claim_registry/{version}.json claims must be an array")
            return
        names[version] = [
            str(claim.get("name"))
            for claim in raw_claims
            if isinstance(claim, dict) and isinstance(claim.get("name"), str)
        ]
        duplicates = sorted(
            name for name in set(names[version]) if names[version].count(name) > 1
        )
        if duplicates:
            fail(
                errors,
                f"claim_registry/{version}.json has duplicate claims: {duplicates}",
            )

    missing = sorted(set(names["v0"]) - set(names["v1"]))
    if missing:
        fail(
            errors,
            "claim_registry/v1.json must preserve every v0 claim name; "
            f"missing={missing}",
        )


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

    category_ids = {category["id"] for category in categories}
    for level, level_categories in manifest.get("conformance_levels", {}).items():
        unknown = sorted(set(level_categories) - category_ids)
        if unknown:
            fail(errors, f"conformance level {level} references unknown categories: {unknown}")
    level_5 = set(manifest.get("conformance_levels", {}).get("level_5_permit_chains", []))
    if "cat-08-permit-chains" in category_ids and "cat-08-permit-chains" not in level_5:
        fail(errors, "cat-08-permit-chains exists but is not included in level_5_permit_chains")


def check_version_metadata(errors: list[str]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    manifest = json.loads((ROOT / "test-vectors/MANIFEST.json").read_text(encoding="utf-8"))

    badge_match = re.search(r"img\.shields\.io/badge/spec-([0-9A-Za-z.-]+)-blue", readme)
    status_match = re.search(r"\| Spec document version \| ([0-9A-Za-z.-]+) \|", readme)
    # Match both "## [1.19.0]" and "## 1.19.0" headings. A bracket-only pattern
    # silently skips a heading written without brackets and falls through to an
    # older release, which lets README drift behind CHANGELOG undetected.
    latest_changelog_match = re.search(
        r"^## \[?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?", changelog, re.MULTILINE
    )

    if not badge_match:
        fail(errors, "README spec badge version is missing")
    if not status_match:
        fail(errors, "README status table spec document version is missing")
    if not latest_changelog_match:
        fail(errors, "CHANGELOG latest released version heading is missing")

    if badge_match and status_match and badge_match.group(1) != status_match.group(1):
        fail(errors, f"README spec badge {badge_match.group(1)} does not match status table {status_match.group(1)}")
    if status_match and latest_changelog_match and status_match.group(1) != latest_changelog_match.group(1):
        fail(
            errors,
            f"README spec version {status_match.group(1)} does not match "
            f"latest CHANGELOG version {latest_changelog_match.group(1)}",
        )

    # test-vectors/MANIFEST.json records the fixture suite's spec baseline, not
    # the current repository release (see test-vectors/README.md). Requiring it
    # to equal the README version would force it to claim the vectors were
    # rebuilt against every spec release. Instead require that it names a spec
    # version the CHANGELOG actually documents.
    released_versions = set(
        re.findall(r"^## \[?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?", changelog, re.MULTILINE)
    )
    permit_spec_version = manifest.get("permit_spec_version")
    if not isinstance(permit_spec_version, str) or not permit_spec_version:
        fail(errors, "test-vectors/MANIFEST.json permit_spec_version is missing")
    elif not SEMVER_RE.fullmatch(permit_spec_version):
        fail(errors, f"test-vectors/MANIFEST.json permit_spec_version is not semver-like: {permit_spec_version!r}")
    elif released_versions and permit_spec_version not in released_versions:
        fail(
            errors,
            "test-vectors/MANIFEST.json permit_spec_version "
            f"{permit_spec_version} is not a version documented in CHANGELOG.md",
        )


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


def check_json_schemas_self_validate(require_jsonschema: bool, errors: list[str]) -> None:
    try:
        import jsonschema
    except ImportError:
        if require_jsonschema:
            fail(errors, "jsonschema is required but is not installed")
        else:
            print("jsonschema not installed; skipping schema self-validation.")
        return

    for schema_path in sorted((ROOT / "schemas").glob("*.schema.json")):
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator.check_schema(schema)
        except Exception as exc:
            fail(errors, f"{schema_path.relative_to(ROOT)} is not a valid draft-2020-12 schema: {exc}")


def check_permit_co_signature_vectors(require_jsonschema: bool, errors: list[str]) -> None:
    try:
        import jsonschema
        from referencing import Registry, Resource
    except ImportError:
        if require_jsonschema:
            fail(errors, "jsonschema and referencing are required but are not installed")
        else:
            print("jsonschema not installed; skipping permit co-signature vector validation.")
        return

    schema_documents = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    ]
    registry = Registry()
    for schema in schema_documents:
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            registry = registry.with_resource(schema_id, Resource.from_contents(schema))

    key_schema = json.loads(
        (ROOT / "schemas/permit-co-signer-key-v1.schema.json").read_text(encoding="utf-8")
    )
    key_validator = jsonschema.Draft202012Validator(
        key_schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    required_vector_ids = {
        "positive-es256",
        "positive-eddsa",
        "negative-wrong-challenge",
        "negative-wrong-origin",
        "negative-wrong-rp-id-hash",
        "negative-uv-zero",
        "negative-tampered-authenticator-data",
        "negative-tampered-signature",
        "negative-replay-different-permit",
    }

    required_key_fields = {
        "aaguid",
        "attestation_format",
        "attestation_statement",
        "backup_eligible",
        "backup_state",
        "sign_count",
        "cose_alg",
        "rp_id",
        "credential_id",
    }
    if not required_key_fields.issubset(set(key_schema.get("required", []))):
        missing = sorted(required_key_fields - set(key_schema.get("required", [])))
        fail(errors, f"permit co-signer key schema is missing required recorded fields: {missing}")

    for version in ("v1", "v2"):
        claim_schema = json.loads(
            (ROOT / f"schemas/permit-co-signature-{version}.schema.json").read_text(
                encoding="utf-8"
            )
        )
        claim_validator = jsonschema.Draft202012Validator(
            claim_schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        )
        corpus_path = ROOT / f"test-vectors/permit_co_signature/{version}/corpus.json"
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        vectors = corpus.get("vectors")
        if not isinstance(vectors, list) or len(vectors) < 8:
            fail(errors, f"permit co-signature {version} corpus must contain at least 8 vectors")
            continue

        by_id = {
            vector.get("id"): vector
            for vector in vectors
            if isinstance(vector, dict) and isinstance(vector.get("id"), str)
        }
        missing_vector_ids = sorted(required_vector_ids - set(by_id))
        if missing_vector_ids:
            fail(
                errors,
                f"permit co-signature {version} corpus is missing required vectors: "
                f"{missing_vector_ids}",
            )

        for vector_id, expected_alg in (("positive-es256", -7), ("positive-eddsa", -8)):
            vector = by_id.get(vector_id, {})
            assertion = vector.get("claim", {}).get("assertion", {})
            expected = vector.get("expected", {})
            if (
                assertion.get("cose_alg") != expected_alg
                or expected.get("verdict") != "supported"
            ):
                fail(
                    errors,
                    f"permit co-signature {version} vector {vector_id} "
                    f"must support COSE alg {expected_alg}",
                )

        negative_vectors = [
            vector
            for vector_id, vector in by_id.items()
            if vector_id.startswith("negative-")
        ]
        negative_reasons = [
            vector.get("expected", {}).get("reason") for vector in negative_vectors
        ]
        if any(
            vector.get("expected", {}).get("verdict") != "disproved"
            for vector in negative_vectors
        ):
            fail(
                errors,
                f"all permit co-signature {version} negative vectors must be disproved",
            )
        if len(negative_reasons) != len(set(negative_reasons)):
            fail(
                errors,
                f"permit co-signature {version} negative vectors must have distinct "
                "primary reasons",
            )

        for vector in vectors:
            vector_id = (
                vector.get("id", "<missing-id>")
                if isinstance(vector, dict)
                else "<invalid>"
            )
            if not isinstance(vector, dict):
                fail(
                    errors,
                    f"permit co-signature {version} vector {vector_id} is not an object",
                )
                continue
            for label, validator, instance in (
                ("claim", claim_validator, vector.get("claim")),
                ("registered_cose_key", key_validator, vector.get("registered_cose_key")),
            ):
                failures = sorted(
                    validator.iter_errors(instance), key=lambda err: list(err.path)
                )
                if failures:
                    first = failures[0]
                    location = ".".join(str(part) for part in first.path) or "<root>"
                    fail(
                        errors,
                        f"permit co-signature {version} vector {vector_id} {label} "
                        f"fails schema at {location}: {first.message}",
                    )

            if version == "v2":
                decision = vector.get("verification_context", {}).get("permit_decision")
                if (
                    not isinstance(decision, dict)
                    or decision.get("claim_name") != "permit.decision.v1"
                    or decision.get("verdict") != "supported"
                ):
                    fail(
                        errors,
                        f"permit co-signature v2 vector {vector_id} lacks a separately "
                        "supported Permit decision context",
                    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-jsonschema", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []
    files = git_files()
    check_json_parse(files, errors)
    check_markdown_links(files, errors)
    check_failure_codes(files, errors)
    check_claim_registry_v1_superset(errors)
    check_manifest_summary(errors)
    check_version_metadata(errors)
    check_json_schemas_self_validate(args.require_jsonschema, errors)
    check_examples_against_schemas(args.require_jsonschema, errors)
    check_permit_co_signature_vectors(args.require_jsonschema, errors)

    if errors:
        print("Repository integrity check failed:")
        for error in errors:
            print(f"  {error}")
        return 1

    print("Repository integrity check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
