# Permit fact profiles

This directory defines the authorization facts that make a trusted Permit
semantic materially specific. Semantic identity answers what kind of action was
authorized. A fact profile answers which typed values must be bound to prove
the exact authorization.

Fact profiles are security-sensitive and non-presentational:

- the fact-profile identifier is selected only by a trusted semantic registry
  entry;
- required facts are derived at a server-owned action boundary;
- canonical fact bytes are bound into the signed Permit;
- bulk exports follow the profile's bulk-disclosure policy;
- an exact-permit evidence pack may disclose only the fields allowed by the
  exact-pack policy; and
- erasing a bound fact requires an explicit signed erasure transition. A
  verifier must then report the original value as intentionally unavailable,
  not unchanged.

Presentation profiles may label already-verified facts. They cannot create,
alter, or complete them.
