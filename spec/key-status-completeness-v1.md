# Key Status Completeness v1

This document specifies the `key.status.completeness.v1` verifier claim. The
claim proves that a signed key-status manifest is fresh, pinned to trusted
issuer keys, and complete for witnessed `key.status.v1` events up to a
checkpoint scope-state boundary.

The claim is public verification metadata. It is vendor/soak material until the
foundation verifier artifacts are explicitly ratified for publication.

## 1. Required Evidence

The verifier MUST require all of the following evidence:

- A signed `permit_v2.key_status_manifest.v1` manifest.
- A subject tuple containing `account_id`, `key_scope`, `key_id`,
  `comparison_instant`, and `comparison_instant_source`.
- A supported `checkpoint.scope_state.v1` sidecar and its referenced checkpoint.
- Pinned trust-root keys for `permit_binding_signing`, `scope_state`, and
  `integrity_checkpoint`.

The subject `comparison_instant_source` MUST be `signed_bytes`. A caller-supplied
time is not sufficient.

For Permit binding v7 and later, a Permit v2 slot subject's `account_id` and
registry-partition selector MUST come from the signed permit bytes. A caller
manifest or other unsigned metadata is not sufficient to select the account for
key-status completeness, and manifest drift from the signed permit selector
prevents support.

## 2. Manifest Requirements

The key-status manifest MUST pass the schema and signature rules in
[`key-status-manifest-v1.md`](key-status-manifest-v1.md). The manifest signature
MUST resolve through the pinned `permit_binding_signing` key. Verifiers MUST NOT
accept an untrusted caller manifest for this signer resolution.

The manifest `computed_at` timestamp MUST be strictly greater than the subject
`comparison_instant`.

## 3. Scope-State Composition

The sidecar and checkpoint MUST support `checkpoint.scope_state.v1`. The
sidecar MUST contain a commitment for:

```json
{
  "version": "keel.scope_predicate.v1",
  "operator": "and",
  "equals": {
    "event_type": "key.status.v1"
  },
  "ranges": {
    "sequence_number": {
      "gte": 0,
      "lte": "<checkpoint chain head sequence_number>"
    }
  }
}
```

The commitment's `matching_count` MUST equal the number of distinct
`key.status.v1` `event_refs` in the signed key-status manifest. Every referenced
event sequence number MUST be in `[1, checkpoint_head]`. Duplicate event
identities are rejected.

## 4. Key-Status Sufficiency

For a revocation completeness subject (`expected_status: "revoked"`), the
manifest MUST contain a key entry whose signed `account_id`, `key_scope`, and
`key_id` exactly match the subject. That entry MUST have `status: "revoked"`,
`revoked_at` MUST be at or before the signed `comparison_instant`, and the entry
MUST include at least one `key.status.v1` event reference with
`status: "revoked"`.

For a slot-liveness subject (`expected_status: "not_revoked"`), the manifest
MUST contain a key entry whose signed `account_id`, `key_scope`, and `key_id`
exactly match the subject. The claim is supported only when neither
`revoked_at` nor `compromised_at` is at or before the signed
`comparison_instant`. A bounded-zero event domain is sufficient only when the
checkpoint scope-state commitment's `matching_count` is zero and the signed
manifest also carries zero `key.status.v1` references.

All requirements compose with logical AND. Missing or unsupported scope-state
evidence prevents the completeness claim from being supported even when the
manifest signature is valid.
