# Synthetic Aidbox exact administrative facts v1

Status: local canonical-artifact candidate, not released, enrolled or live-qualified.

The [exact-facts schema](../schemas/aidbox-fhir-exact-facts-v1.schema.json) defines three distinct administrative requests: complete mailing-address update, appointment rescheduling and a defined external records release. [Selector v23](../semantic_registry/v23.json) preserves every v22 entry and adds exactly those actions. [Fact profiles v20](../fact_profiles/v20.json) preserves every v19 profile and its disclosure contract. Existing artifact bytes are unchanged.

These contracts bind minimized facts to server-derived requests. They carry scoped patient, recipient, document-set and provider-state commitments, verification/disclosure deadlines and bounded single use. They contain no clinical record text, patient name, address, phone number or verification code. The [schema examples](../fact_profiles/test-vectors/aidbox-v1.json) are synthetic conformance fixtures, not issued Permits or provider evidence.

Schema validity creates no grant. Independent identity verification, fresh exact preflight, bounded positive policy grants, release REVIEW and managed dispatch remain required. Approval never overrides DENY, THROTTLE, revoked/expired verification or application controls. A release request or authorization does not prove a document transfer. No compliance or clinical suitability is established.

The freeze and disclosure requirements in [Permit Fact Profiles v1](permit-fact-profiles-v1.md) continue unchanged. New issuance must not reinterpret historical registry versions. The public verifier must vendor these exact bytes and release them before an issuer relies on the new versions. No presentation profile or new curated title is added by this change.

Run `python tools/check_aidbox_contract.py` and the repository's `make check`. The Aidbox check is also part of the existing Permit-to-X contract checker. It rejects missing, rewritten or duplicate historical entries in both successor registries and validates minimized positive and malformed/missing-field examples. Runtime identity, temporal freshness, policy decisions and provider effects require separate implementation tests.
