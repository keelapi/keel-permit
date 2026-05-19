# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for suspected security vulnerabilities in the Permit specification, verifier semantics, test vectors, schemas, or released artifacts.

Report privately to `security@keelapi.com` with:

- Affected file, spec section, schema, or artifact version.
- A concise description of the issue and expected verifier impact.
- Reproduction steps or a minimal fixture when possible.
- Whether the issue may affect already-published evidence packs or verifier results.

Keel API will acknowledge actionable reports and coordinate disclosure timing when a fix requires a spec, schema, verifier, or artifact update.

## Scope

In scope:

- Wire-format ambiguities that could cause incompatible verifier behavior.
- Schema gaps that allow invalid evidence to validate.
- Test vectors with incorrect expected outcomes.
- Cryptographic verification semantics that could permit false positives.
- Public artifact integrity issues.

Out of scope:

- Product-support questions.
- Vulnerabilities only in downstream implementations that do not follow this specification.
- Reports requiring access to private customer data or systems.
