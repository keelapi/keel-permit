# Input artifacts — 02-01-record-hash-modified

This directory will contain:

- `export.jsonl` — 5-entry chain segment, with entry at sequence 2 having its `record_hash` field modified by one byte.
- `manifest.json` — manifest whose `content_hash` is the hash of the **modified** export (so manifest verification passes; only chain walk fails).
- `signature.bin` — detached Ed25519 signature over the modified manifest (still valid signature, modified content).
- `trust-root.json` — test-only trust root.

**Currently TODO.** See the tamper construction recipe in `../description.md` for how to generate this fixture deterministically.
