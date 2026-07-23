# Permit semantic selector registry

This directory defines the security-sensitive mapping from server-established
provenance to stable Permit semantics. A matching action or operation string is
necessary but never sufficient. Selection also requires an allowlisted trusted
source kind, chain role, governed surface, evidence capabilities, and a
non-excluded Permit product.

Selection is fail closed:

- exactly one eligible entry matches: bind that `semantic_id`;
- no entry matches: use the generic or unclassified fallback outside this
  registry;
- more than one entry matches: treat the selector registry as ambiguous and do
  not bind a specific semantic identity.

Caller-controlled action names, tool names, connector labels, and Declared
purpose are not trusted source kinds. Generated consumers MUST verify the
canonical artifact digest before using the registry.
