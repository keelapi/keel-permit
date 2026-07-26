# Permit Fact Profiles v1

## 1. Purpose

A Permit-to-X title is trustworthy only when the consequential facts implied by
that title are typed, bound, and independently checkable. The semantic selector
establishes the action kind. A fact profile defines the exact authorization
facts for that kind.

The first eligible profile is `keel.facts.payment_exact.v1`, used by
`keel.action.payment_execute.v1`. Future Permit-to-X types add new registry
entries and schemas. They do not add title-controlled authorization logic.

## 2. Canonical artifacts

- [`fact_profiles/v1.json`](../fact_profiles/v1.json) is the fact-profile
  registry.
- [`fact_profiles/v1.schema.json`](../fact_profiles/v1.schema.json) validates
  the registry.
- [`payment-exact-facts-v1.schema.json`](../schemas/payment-exact-facts-v1.schema.json)
  defines the first exact-action fact payload.
- [`semantic_registry/v3.json`](../semantic_registry/v3.json) associates a
  trusted semantic identity with a fact-profile identifier.

Consumers MUST pin the exact registry and schema bytes, or their lowercase
`sha256:` digests.

## 3. Binding rule

For an eligible semantic with `fact_profile_id`, an issuer MUST:

1. derive facts only from the server-owned normalized action request;
2. validate them against the profile's pinned schema;
3. canonicalize the complete facts object with RFC 8785;
4. place `sha256(canonical facts)` in the signed Permit semantic binding; and
5. retain enough evidence for an offline verifier to recompute that digest.

Missing or invalid required facts fail closed to the generic `AI Permit`
presentation. A specific title MUST NOT be recovered from caller text,
connector labels, or an unsigned summary.

## 4. Exact payment facts

`keel.facts.payment_exact.v1` binds:

- positive integer amount in minor currency units;
- uppercase three-letter currency code;
- salted commitment to the exact recipient reference;
- optional salted commitment to a display name;
- the governed payment rail; and
- the digest of the exact request dispatched or held for approval.

The recipient opening is not part of the immutable fact object. When a
requester is authorized to receive it, an exact-permit evidence pack may carry
the value and random salt so the verifier can recompute the commitment.
Low-entropy names MUST NOT use an unsalted hash.

## 5. Privacy and disclosure

Fact profiles distinguish bulk compliance exports from exact-permit evidence
packs. Bulk export defaults MUST omit financial and personal values unless a
separate export contract explicitly requires them. Exact packs disclose only
the minimum fields permitted by the profile.

`erasable: true` does not mean that signed bytes can be silently rewritten. It
means storage may replace the value through a signed erasure transition that
binds the original and replacement integrity states. After that transition, a
verifier reports the original fact as intentionally unavailable.

## 6. Presentation non-interference

Presentation registries may choose labels and ordering for verified facts.
They MUST NOT:

- supply a missing fact;
- change the fact digest;
- decide disclosure eligibility;
- turn a commitment into an established identity; or
- imply provider success or financial settlement.

For `AI Permit-to-Pay`, exact authorization and later execution outcomes remain
separate claims.
