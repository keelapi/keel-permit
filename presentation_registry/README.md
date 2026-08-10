# Permit presentation registry

This directory defines customer-facing titles, one-line definitions, leading
fields, and evidence-section emphasis for trusted Permit semantics. It is a
presentation artifact, not an authorization or verifier-claim registry.

Implementations MUST NOT use any field from this registry to decide whether an
action is allowed, executable, complete, successful, or settled. A presentation
profile may order already-computed fact groups; it cannot select verifier
claims, alter adjudication, change JSON verdicts, or change process exit status.

New reports pin the presentation artifact version and digest for reproducible
historical rendering. If that artifact cannot be resolved, render the
`historical_specific_title_unavailable` fallback rather than silently applying
the newest title. Legacy Permits without a trusted semantic binding remain
generic.

`v3` adds the human-artifact contract used by dashboards and offline
verifiers. It makes the human view the default, requires verifier-derived state
titles and end summaries, inventories advanced cryptographic representations,
and keeps packaged HTML and package manifests non-authoritative. The signed
evidence remains the trust root.
