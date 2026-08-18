#!/usr/bin/env python3
"""Build a deterministic release bundle and its digest manifest.

A release of this project is the published specification distribution at a given
tag. Not all of it is normative, and the manifest says which parts are: the
specification text, JSON Schemas, registries and semantics are normative; the
conformance corpus is a test artifact; the examples are illustrative; the control
framework mappings are a draft evidence-support aid. Development-time tooling is excluded via `export-ignore`
in `.gitattributes`, because a consumer needs none of it to verify a Permit
artifact.

Determinism is the point. The bundle is produced with `git archive`, which emits
byte-identical output for a given tree, so anyone can rebuild a published release
from the tag and confirm the digest rather than trusting the publisher's word.
Rebuilding is the check; the signature only says who did the building.

Usage:
    python3 tools/build_release_bundle.py --ref v1.19.0 --out dist/

Produces, for version X:
    keel-permit-X.tar.gz     the bundle
    SHA256SUMS               sha256sum-compatible digests of the release assets
    release-manifest.json    per-file digests and bundle digest

The manifest carries no embedded signature. It records that explicitly, along
with the provenance path that does cover it: a Sigstore-backed GitHub artifact
attestation over the published assets. A maintainer-held signing key is a
separate, additive path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str]) -> bytes:
    proc = subprocess.run(args, cwd=ROOT, check=True, capture_output=True)
    return proc.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_version(ref: str) -> str:
    """A tag names its own version; any other ref is identified by commit."""
    if ref.startswith("v") and ref[1:2].isdigit():
        return ref[1:]
    return run(["git", "rev-parse", "--short", ref]).decode().strip()


def build_bundle(ref: str, out_dir: Path, version: str) -> Path:
    bundle = out_dir / f"keel-permit-{version}.tar.gz"
    prefix = f"keel-permit-{version}/"
    # --worktree-attributes is deliberately NOT used: export-ignore must come
    # from the archived tree, so a release always reflects the composition rules
    # committed at that tag rather than whatever is in the builder's checkout.
    data = run(["git", "archive", f"--prefix={prefix}", "--format=tar.gz", ref])
    bundle.write_bytes(data)
    return bundle


def manifest_for(bundle: Path, ref: str, version: str) -> dict:
    commit = run(["git", "rev-parse", ref]).decode().strip()
    files = []
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            payload = handle.read()
            files.append(
                {
                    "path": member.name.split("/", 1)[1],
                    "size": member.size,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    files.sort(key=lambda entry: entry["path"])
    return {
        "schema": "keel.release_manifest/v1",
        "project": "keel-permit",
        "version": version,
        "ref": ref,
        "commit": commit,
        "bundle": {
            "name": bundle.name,
            "size": bundle.stat().st_size,
            "sha256": sha256_file(bundle),
        },
        "content_classes": {
            "normative": ["spec/", "schemas/", "claim_registry/", "semantic_registry/",
                          "presentation_registry/", "consequence_registry/",
                          "comparator_registry/", "fact_profiles/", "semantics/",
                          "artifact-manifests/"],
            "conformance_artifacts": ["test-vectors/"],
            "illustrative": ["examples/"],
            "draft_evidence_support": ["mappings/"],
            "project_documentation": ["README.md", "CHANGELOG.md", "CONTRIBUTING.md",
                                      "GOVERNANCE.md", "SECURITY.md", "LICENSE",
                                      "PUBLIC_DOCS_POLICY.md"],
        },
        "file_count": len(files),
        "files": files,
        "signing": {
            "manifest_embedded_signature": False,
            "release_provenance": "github-artifact-attestation",
            "verify": f"gh attestation verify {bundle.name} -R keelapi/keel-permit",
            "note": (
                "This manifest carries no embedded signature. The published release assets, "
                "including this manifest, are subjects of a Sigstore-backed GitHub artifact "
                "attestation bound to the workflow identity that built them."
            ),
        },
        "reproduce": (
            f"git archive --prefix=keel-permit-{version}/ --format=tar.gz {ref} "
            f"| sha256sum  # expect {sha256_file(bundle)}"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="HEAD", help="tag or commit to release")
    parser.add_argument("--out", default="dist", help="output directory")
    args = parser.parse_args()

    out_dir = (ROOT / args.out) if not Path(args.out).is_absolute() else Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    version = resolve_version(args.ref)
    bundle = build_bundle(args.ref, out_dir, version)
    manifest = manifest_for(bundle, args.ref, version)

    manifest_path = out_dir / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sums_path = out_dir / "SHA256SUMS"
    lines = [f"{sha256_file(path)}  {path.name}" for path in sorted([bundle, manifest_path], key=lambda p: p.name)]
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"version      : {version}")
    print(f"commit       : {manifest['commit']}")
    print(f"bundle       : {bundle.name}  ({bundle.stat().st_size} bytes)")
    print(f"bundle sha256: {manifest['bundle']['sha256']}")
    print(f"files        : {manifest['file_count']}")
    print(f"wrote        : {bundle.name}, {manifest_path.name}, {sums_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
