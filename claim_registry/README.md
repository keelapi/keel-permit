# Claim Registry

Versioned verifier-claim definitions for Keel evidence packs.

Each registry version is a JSON artifact declaring stable claim names, the
assertion each claim evaluates, the evidence required to evaluate it, and the
only verdict values a conforming verifier may emit for that claim. The registry
defines claim semantics; it does not declare current implementation support in
any verifier build.

Standing rule:

> No emitted evidence field, artifact, event payload, or manifest claim ships as externally product-real unless it maps to a stable named verifier claim in claim_registry/ and public keel-verifier independently adjudicates that claim.

The four `permit.work_*` / `permit_chain.execution_authorized_at_boundary.v1`
entries are contract-first definitions. Their presence in the registry does not
declare producer or verifier implementation support; a coordinated released
public verifier remains mandatory before external support claims.

## Versions

| File | Claim registry version | Status |
|---|---|---|
| [`v0.json`](v0.json) | `verifier-claims.v0` | Frozen historical |
| [`v1.json`](v1.json) | `verifier-claims.v1` | Released historical |
| [`v2.json`](v2.json) | `verifier-claims.v2` | Released historical |
| [`v3.json`](v3.json) | `verifier-claims.v3` | Released historical |
| [`v4.json`](v4.json) | `verifier-claims.v4` | Released historical |
| [`v5.json`](v5.json) | `verifier-claims.v5` | Current candidate |

## Hash-addressing

A signed evidence pack containing verifier claims MUST either inline the claim
registry artifact OR hash-address it in the bundle manifest. A verifier
evaluating claims that cannot resolve the registry from the pack MUST return
`insufficient_evidence` for claims that depend on the missing registry
semantics.

## Versioning

Changing claim semantics for any released claim REQUIRES a new registry version.
The verifier maintains an explicit allowlist of supported registry versions and
MUST reject anything outside it as `unverifiable_scope`.

Released registry versions are immutable. Once published, a version remains
available indefinitely so historical evidence packs continue to resolve the same
claim definitions.

## Adding a new version

A new claim registry version requires:

1. A new file `vN.json` with the full set of claim definitions for that
   version.
2. A spec revision in `spec/` declaring any new claim, verdict, or
   pack-pinning semantics.
3. Verifier support added to the verifier's allowlist.
4. Test vectors covering each new or changed claim definition.

Versions coexist indefinitely once published; verifiers MUST carry support for
every released version they claim to implement.
