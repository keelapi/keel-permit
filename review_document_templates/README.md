# Review document templates

This directory defines the documents a reviewer reads before deciding a held
Permit request. A template names, for one trusted Permit semantic, which facts
the review document shows, how each fact is labelled, where it comes from and
whether it is essential. It is a presentation artifact, not an authorization
or verifier-claim registry.

Implementations MUST NOT use any field from this registry to decide whether an
action is allowed, executable, complete, successful, or settled. A template can
label and order facts that are already bound or checked; it cannot create,
alter, or complete them, select verifier claims, change JSON verdicts, or
change process exit status.

## Shape

Each template pins a `semantic_id`, the `fact_profile_id` that semantic
selects, and the `presentation_profile_id` that titles it. Its sections hold
fields, and each field states:

- `source`: `exact_facts` (the Permit's signed exact facts), `subject_facts`
  (facts opened from the identity gateway's encrypted envelope and checked
  against the exact facts' commitments), `review` (the Review that holds the
  request), or `template` (a constant the template states);
- `provenance`: `keel_checked` or `gateway_reported`, from the declared
  `provenance_kinds`;
- `essential`: an implementation refuses Approve when an essential fact is
  missing;
- optional `values` labels, which cover exactly the values the bound fact can
  take, and an optional `commitment` naming the salted-commitment exact fact a
  subject fact is checked against.

The requester's explanation is `agent_reported` and never authoritative.
`status_outside_digest` lists the review state (votes, deadline, filing state)
that is shown beside the document but kept out of its digest, so the document
digest stays stable while the review progresses. `beneficiary` names the
committed subject fact that receives the access, and `protected_class_rule`
names the exact-facts enum values that put a request in a protected class.

## Digest and versioning

The registry is canonicalized with RFC 8785 (JCS). Consumers pin the registry
version and its digest with each review document, so a published document
stays reproducible. A published version is never edited: a new or changed
template is a new registry version, and earlier versions stay byte-identical.

## Checks

`tools/check_review_document_templates.py` validates `v1.json` against
`v1.schema.json` and resolves every template against the newest semantic,
presentation and fact-profile registries: each `exact_facts` field must be a
property of the fact profile's schema def, each `commitment` a salted-commitment
target fact, and each protected value a value of the named fact's enum.
