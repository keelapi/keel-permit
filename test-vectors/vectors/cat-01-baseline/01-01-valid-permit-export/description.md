# 01-01 — Valid Permit + Signed Export Bundle

## What this exercises

The baseline happy path: a single Permit emitted into an audit export bundle, with a manifest signed by a known signing key, and chain entries that link consistently to a genesis entry. A conforming verifier MUST report `PASS`.

This is the simplest case that exercises the full verification flow:

1. Parse manifest, verify Ed25519 signature.
2. Verify manifest's `content_hash` matches the actual content bytes.
3. Walk the chain entries, recomputing each `record_hash` and confirming the `prev_hash` chain.
4. Validate the Permit's structure against `schemas/permit-v1.schema.json`.

## Inputs

- `input/permit.json` — single Permit, `decision = "allow"`.
- `input/export.jsonl` — newline-delimited records (genesis chain entry + Permit-creation event + Permit + closure record).
- `input/manifest.json` — manifest with `content_hash` of the export.
- `input/signature.bin` — detached Ed25519 signature over `manifest.json` UTF-8 bytes.
- `input/trust-root.json` — test-only trust root containing the public key used to sign (see `tools/test-keys/`).

## Expected behavior

A conforming verifier:

- Reports `result: "PASS"`.
- Reports `failure_codes: []`.
- Inspects 4 records (1 chain genesis + 1 permit-creation event + 1 permit + 1 closure record).
- Resolves trust root from explicit `--trust-root` flag pointing to `input/trust-root.json` (not from bundled wheel — this is test-mode behavior).

## Why this is "scaffolded" not "complete"

Fixture content currently uses placeholder hashes and a placeholder signature. To make this a real conformance vector, the fixtures must be generated using a script that:

1. Builds a canonical export bundle with real content.
2. Computes real SHA-256 hashes for each chain entry.
3. Signs the manifest with a dedicated test-only Ed25519 key.
4. Commits the resulting fixtures + the public key (test trust root) under `tools/test-keys/`.

The reference implementation in `keel-api` has the canonicalization, hashing, and signing logic — extracting a fixture-generator script that produces deterministic outputs from this logic is a follow-up task (~1-2 hours of work).
