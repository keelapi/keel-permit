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

## Dependencies

The published artifacts — specification text, JSON Schemas, registries, and
conformance fixtures — have **no runtime dependencies**. Verifying a Permit
artifact requires only a JSON parser, an RFC 8785 canonicalizer, and standard
cryptographic primitives available in every major language. No Keel code is
required.

Dependencies exist only for the development-time check suite, and are governed
as follows.

**Selection.** A new dependency is added only when the alternative is
reimplementing a cryptographic primitive, a canonicalization algorithm, or a
schema validator by hand. Preference order is: the language standard library,
then a widely used implementation of a published standard, then anything else.
The Node reference verifiers under `test-vectors/` are deliberately
dependency-free and use only `node:crypto` — that constraint is part of their
value as reference implementations and should not be relaxed.

**Obtaining.** Python dependencies are declared in
[`requirements.txt`](requirements.txt) with bounded version ranges and installed
with `pip install -r requirements.txt`. CI installs from that file rather than
naming packages inline, so the pipeline and a local checkout resolve the same
set. There is no `package.json` because the JavaScript in this repository has no
third-party dependencies.

**Tracking.** The current set is small enough to review directly:

| Dependency | Purpose | Why it is not hand-rolled |
|---|---|---|
| `jsonschema` | Validate examples and fixtures against the published schemas | Draft 2020-12 is large; a partial validator would validate incorrectly |
| `rfc8785` | JSON canonicalization in the derivation reference executor | Byte-exactness against a published standard is the whole point |
| `ruff` | Lint | Development tooling only |

Upper version bounds are pinned so a major release cannot silently change
validation or canonicalization behaviour. Bumping a bound is a normal pull
request and must keep the full check suite passing, including the exact-byte
artifact manifests — a canonicalization change would show up there first.

## Developer Certificate of Origin

Every commit must be signed off, asserting that you are legally authorized to
submit it under the project's licence. This is the
[Developer Certificate of Origin 1.1](https://developercertificate.org/); the
sign-off is your assertion of it.

Add it automatically with `-s`:

```sh
git commit -s -m "your message"
```

which appends:

```text
Signed-off-by: Your Name <your.email@example.com>
```

The `dco` status check verifies that every commit in a pull request carries a
sign-off matching its author. If you forget, amend with
`git commit --amend -s` or, for several commits, rebase with
`git rebase --signoff origin/main`.

## License

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
