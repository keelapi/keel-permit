# Contributing

Thanks for helping improve the Permit specification.

This repository is a public specification and conformance-artifact repo. Changes should preserve verifier interoperability, be reviewable as text, and avoid introducing implementation-private assumptions.

## Good Contributions

- Clarify normative spec language without changing wire-format behavior.
- Add or correct JSON Schemas.
- Add deterministic test vectors with clear expected verifier output.
- Improve verifier-claim, comparator, or semantic artifact documentation.
- Fix broken links, stale README sections, or public-facing metadata.

## Change Guidelines

- Keep wire-format changes explicit. Breaking changes require a new format version such as `v2`, `closure_v3`, or a new semantic artifact version.
- Keep schemas and prose aligned. If a field is allowed by a closed schema, the relevant spec should describe it.
- Keep conformance fixtures byte-stable. Fixture hashes and expected outputs are part of the public contract.
- Do not commit local filesystem paths, private implementation notes, credentials, production keys, or customer data.
- Use LF line endings. `.gitattributes` enforces this for text fixtures.

## Test Policy

New normative behaviour must ship with automated coverage in the same change.
Concretely: a new claim type, failure code, wire-format field, or semantic
artifact must come with either conformance vectors carrying an `expected.json`,
or an integrity check in `tools/`, wired into the `repo-integrity` CI job so it
runs on every pull request. A change that only clarifies existing prose does not
need new coverage.

## Before Opening a PR

Run the full check suite:

```sh
make check
```

Or run the steps individually:

```sh
python tools/check_public_hygiene.py
python tools/check_repo_integrity.py
```

If `jsonschema` is installed, run the stricter check:

```sh
python tools/check_repo_integrity.py --require-jsonschema
```

Install the pinned check dependencies with `pip install -r requirements.txt`.
Lint with `ruff check .` before opening a PR; CI enforces it.

## Generated Schemas

Most schemas in `schemas/` are generated from the reference implementation and post-processed by `tools/export_schemas.py`. Hand-maintained schemas are documented in the README. Do not manually edit generated schema output unless the matching post-processing rule is also updated.

## License

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
