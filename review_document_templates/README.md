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

## v2: the generic rule set

`v2.json` (document format `keel.review_document.v2`) carries the v1
template unchanged and adds `generic`, a versioned rule set an implementation
applies when no tailored template matches a Permit's semantic id and fact
profile. v1 stays byte-identical, so documents built from it stay
reproducible.

v2 pins the registries the rules read by version and digest
(`source_registries`: semantic registry v23, presentation registry v24, fact
profiles v20). The rules apply to a Permit when the pinned semantic registry
maps its semantic to the exact facts' `fact_profile_id`, and otherwise give no
document. The rules:

- **Title and sentence:** the pinned presentation profile's `customer_title`
  and `type_definition`, with the words in `remove_words` dropped and a full
  stop added. A semantic with no presentation profile uses the
  `generic_ai_permit` fallback profile.
- **Shown in clear:** a present fact whose `disclosure.authorized` is
  `cleartext`, whose `classification` is `operational` or `financial`, whose
  value type is not a commitment and whose path is not one of the profile's
  `target_fact_paths`.
- **Hidden:** every other present fact that is not left out shows the text
  `Hidden`, never its value. This covers every `*_commitment` fact and every
  target fact.
- **Left out:** the `omit` fact keys (Keel's plumbing), keys ending in
  `_digest` or `_hash`, and digest, timestamp, array and null facts.
- **Amount card:** the earliest clear integer fact ending in `amount_minor`,
  in profile order, that is not a before, after, current, projected,
  remaining, outstanding or refundable amount (else the earliest of any). Every integer fact
  whose key has the word `minor` is formatted as money from the profile's
  `currency` fact, with the fixed prefixes and minor-unit exponents in
  `amount.currencies`; an unlisted currency is shown in minor units.
- **Change cards:** up to two pairs, in profile order: `current_x` with
  `target_x`, `projected_x`, `requested_x` or `desired_x`, and `x_before` with
  `x_after` or `requested_x`. A side that is Hidden shows `Hidden`.
- **Rows:** every other fact, in profile order, in one `checked_facts`
  section, followed by `why_review` (the Review's cause).
- **Labels:** the key with `_reference_commitment`, `_commitment` or `_minor`
  stripped from its end, the word `minor` removed, underscores as spaces, and
  the opening character upper-cased (`total_amount_minor` → "Total amount").
- **Values:** booleans as Yes or No, integers with comma grouping, lowercase
  codes (`^[a-z0-9_]+$`) as capitalized words with the listed acronyms in
  capitals, and other text NFC-normalized, without control or format
  characters, cut to 256 characters.
- **Essential facts:** the profile's `material_request_fact_paths`. A missing
  one is listed in `checked_facts` with no value, and an implementation
  refuses Approve.

Any change to these rules, or to a pinned registry, is a new registry version.

`test-vectors/v2.json` gives inputs and the expected document, digest,
missing essential facts and fact provenance for each, built by
`tools/review_document_reference.py`. Regenerate the expected outputs with
`python3 tools/review_document_reference.py --write-vectors` together with a
new registry version, never for a published one.

## Checks

`tools/check_review_document_templates.py` validates `v1.json` against
`v1.schema.json` and resolves every template against the newest semantic,
presentation and fact-profile registries: each `exact_facts` field must be a
property of the fact profile's schema def, each `commitment` a salted-commitment
target fact, and each protected value a value of the named fact's enum.

For v2 it also checks the pinned registries' digests, resolves the tailored
templates against them, applies the generic rules to every pinned fact profile
and fails if a commitment, a target fact, a fact not authorized in cleartext,
or a personal, sensitive or free-text fact would be shown in clear, and
recomputes the test vectors.
