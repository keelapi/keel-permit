#!/usr/bin/env python3
"""Fail on local-path and internal-process leaks in public repo files."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv"}
SKIP_SUFFIXES = {
    ".bin",
    ".der",
    ".gz",
    ".ico",
    ".jpg",
    ".jpeg",
    ".ots",
    ".pdf",
    ".png",
    ".sig",
    ".tsr",
    ".zip",
}

LEAK_PATTERNS = [
    ("macOS home path", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("Linux home path", re.compile(r"/home/[A-Za-z0-9._-]+/")),
    ("Windows user path", re.compile(r"[A-Za-z]:\\\\Users\\\\[^\\\\]+\\\\")),
    ("local Desktop path", re.compile(r"\bDesktop/(?:Business|Personal|Downloads)?")),
    ("internal design-review attribution", re.compile(r"\bChatGPT design review\b")),
]


def iter_public_text_files() -> list[Path]:
    files: list[Path] = []
    try:
        candidates = []
        for args in (["git", "ls-files"], ["git", "ls-files", "--others", "--exclude-standard"]):
            proc = subprocess.run(
                args,
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            candidates.extend(ROOT / line for line in proc.stdout.splitlines())
    except (OSError, subprocess.CalledProcessError):
        candidates = list(ROOT.rglob("*"))

    for path in candidates:
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path == Path(__file__).resolve():
            continue
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        files.append(path)
    return files


def main() -> int:
    findings: list[str] = []
    for path in iter_public_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        rel = path.relative_to(ROOT)
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, pattern in LEAK_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{rel}:{line_no}: {label}")

    if findings:
        print("Public hygiene check failed:")
        for finding in findings:
            print(f"  {finding}")
        return 1

    print("Public hygiene check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
