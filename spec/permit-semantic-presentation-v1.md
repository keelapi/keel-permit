# Trusted Permit Semantics and Presentation v1

This document separates three concepts:

1. a trusted semantic identity established from server-owned provenance;
2. customer presentation derived from that identity; and
3. evidence-section emphasis over already-computed verifier facts.

Only the first can enter signed Permit material. Neither presentation nor
evidence emphasis is an authorization or verdict input.

## 1. Canonical artifacts

- [`semantic_registry/v1.json`](../semantic_registry/v1.json) is the
  security-sensitive semantic selector registry.
- [`presentation_registry/v1.json`](../presentation_registry/v1.json) is the
  title, definition, leading-field, evidence-emphasis, fallback, and static
  release-posture registry.
- [`permit-semantic-binding-v1.schema.json`](../schemas/permit-semantic-binding-v1.schema.json)
  defines the signed semantic projection for new Permits.

Generated consumers MUST pin and verify the canonical artifact bytes or their
lowercase `sha256:` content digest. Consumer copies are not independently
editable registries.

## 2. Trusted selection

The selector receives only server-established normalized facts:

- trusted source kind;
- chain role;
- exact action and operation where required;
- governed surface;
- available evidence capabilities; and
- Permit product.

An entry matches only when all stated requirements match and the Permit product
is not excluded. Exactly one match produces a trusted `semantic_id`. Zero
matches uses a fallback. Multiple matches are a registry defect and fail closed
without a specific identity.

Caller action text, tool names, connector labels, Declared purpose, broad
read/write classification, and renamable slugs never establish trusted source
provenance.

## 3. Signed semantic binding

New specific Permits carry:

- semantic identifier;
- selector registry version and digest;
- selected entry digest;
- trusted source kind;
- chain role;
- governed surface;
- exact action/operation when applicable; and
- derivation time.

The optional pinned presentation-profile identifier is explicitly
non-authorizing. Customer title text is derived output and is not signed
authorization truth.

## 4. Presentation non-interference

The presentation registry may:

- choose a customer title and one-line record definition;
- choose leading fields from the closed normalized field set;
- order or emphasize allowlisted evidence sections; and
- state facts the record does not establish.

It MUST NOT:

- determine Policy outcome or executable authority;
- create or select a verifier claim;
- change cryptographic validation, JSON verdicts, or process exit status;
- treat a customer value as a trusted label or field path; or
- imply consent, identity, authority to represent, legality, completion,
  provider success, truth, quality, settlement, or comprehensive recording not
  established by evidence.

## 5. Historical and fallback behavior

Reports pin the presentation artifact version and digest used for rendering.
Old artifacts remain resolvable for reproducibility. When historical
presentation material is unavailable, render:

> AI Permit — specific title unavailable for this record

Do not silently apply the latest title. A legacy Permit without a trusted
semantic binding remains `AI Permit`. A caller-controlled or otherwise
untrusted action request renders `Unclassified action request` when the product
needs to distinguish insufficient identity from a known generic Permit.

`cost_permit` is excluded from selector admission and retains its existing
public vocabulary.
