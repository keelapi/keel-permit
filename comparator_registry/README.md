# Comparator Registry

Versioned authority-envelope comparator semantics for [Permit Chains](../spec/permit-chain-v1.md).

Each registry version is a JSON artifact declaring, for every field in an `authority_envelope`, its type, order semantics, and canonicalization rule. The registry is the single source of truth for how envelope fields are compared during issuance-validity and execution-validity checks.

## Versions

| File | Envelope version | Status |
|---|---|---|
| [`v0.json`](v0.json) | `authority-envelope.v0` | Current |

## Hash-addressing

A signed evidence pack containing a permit chain MUST either inline the registry artifact OR hash-address it in the bundle manifest. A verifier walking permit-chain claims that cannot resolve the registry from the pack MUST return `insufficient_evidence` and emit `WALK_PERMIT_CHAIN_MISSING_COMPARATOR`. See `spec/permit-chain-v1.md` §4.2.

## Versioning

Changing comparator semantics for any field — even adding a new field with a new comparator type — REQUIRES bumping the envelope version. The verifier maintains an explicit allowlist of supported envelope versions and MUST reject anything outside it as `unverifiable_scope`.

## Adding a new version

A new envelope version (e.g., `authority-envelope.v1`) requires:

1. A new file `vN.json` with the full set of fields and their comparator semantics.
2. A spec revision in `spec/` declaring the version and any new fields.
3. Verifier support added to the verifier's allowlist.
4. Test vectors covering each new comparator field and any compatibility expectations with prior versions.

Versions coexist indefinitely once published; verifiers MUST carry support for every released version.
