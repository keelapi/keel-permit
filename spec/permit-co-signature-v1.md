# Permit Co-Signature v1

`permit.co_signature.v1` records a human co-signature over a governed Permit
operation using a registered WebAuthn credential. It is an additive verifier
claim contract. It does not add a field to Permit v1 or Permit v2.

The assertion is a WebAuthn assertion. It is **not** a signature over raw
canonical Permit bytes and it is **not** necessarily Ed25519. A conforming
verifier verifies the authenticator-signed byte sequence and supports the COSE
algorithms declared by this profile.

## 1. Conformance keywords

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Encodings and algorithm profile

All assertion-envelope byte strings use unpadded base64url. Verifiers MUST
reject non-canonical base64url rather than silently accepting standard base64,
padding, ignored characters, or alternate encodings.

`permit_canonical_hash` keeps the existing Permit convention: 64 lowercase
hexadecimal characters representing the raw 32-byte SHA-256 digest of the
canonical Permit bytes.

This profile supports:

| `cose_alg` | Name | COSE key | Assertion signature encoding |
|---|---|---|---|
| `-7` | ES256 | EC2, P-256 (`kty=2`, `crv=1`) | ASN.1 DER ECDSA signature, as returned by WebAuthn |
| `-8` | EdDSA | OKP Ed25519 (`kty=1`, `crv=6`) | 64-byte Ed25519 signature |

ES256 is a first-class path, not a compatibility fallback. Producers and
verifiers MUST select verification from the registered COSE key and MUST NOT
assume Ed25519.

## 3. WebAuthn assertion envelope

The closed envelope is defined by
[`webauthn-assertion-envelope-v1.schema.json`](../schemas/webauthn-assertion-envelope-v1.schema.json):

```json
{
  "credential_id": "base64url(rawId)",
  "authenticator_data": "base64url(authenticatorData)",
  "client_data_json": "base64url(exact clientDataJSON bytes)",
  "signature": "base64url(assertion signature)",
  "cose_alg": -7
}
```

The envelope deliberately does not duplicate `origin`, `rp_id`, UP, UV, BE,
BS, or `sign_count`. `origin` is parsed from the exact `clientDataJSON` bytes;
the remaining values are derived from `authenticatorData` and the registered
key record. Duplicated caller-supplied interpretations would not be trusted.

The exact decoded `client_data_json` bytes MUST be hashed. A verifier MUST NOT
parse and reserialize JSON before hashing it.

## 4. Challenge construction

The request ceremony MUST provide the raw 32 bytes represented by
`permit_canonical_hash` as `PublicKeyCredentialRequestOptions.challenge`.
WebAuthn serializes those bytes into `clientDataJSON.challenge` as unpadded
base64url. Therefore the precise equality check is:

```text
base64url_decode(clientDataJSON.challenge)
  == hex_decode(permit.co_signature.v1.permit_canonical_hash)
```

Equivalently, a verifier can compare `clientDataJSON.challenge` to the
unpadded base64url encoding of the raw canonical-hash bytes. Comparing the
client-data string directly to the 64-character hexadecimal field is wrong.

## 5. `permit.co_signature.v1` claim

The closed claim is defined by
[`permit-co-signature-v1.schema.json`](../schemas/permit-co-signature-v1.schema.json).
It contains exactly:

| Field | Meaning |
|---|---|
| `payload_type` | Domain separator; MUST equal `permit.co_signature.v1`. |
| `permit_id` | Permit receiving the co-signature. |
| `permit_canonical_hash` | Lowercase hexadecimal SHA-256 of canonical Permit bytes. |
| `action` | Governed action from the independently verified Permit context. |
| `resource` | Governed resource from the independently verified Permit context. |
| `modality` | Governed operation modality. |
| `co_signer_id` | Opaque identifier of the human co-signer. |
| `role` | `approver` or `witness`. |
| `key_id` | Registered co-signer-key identifier. |
| `custody_tier` | MUST equal `human_passkey`. |
| `signed_at` | Recorded assertion acceptance time. |
| `assertion` | The WebAuthn assertion envelope from section 3. |

The WebAuthn signature binds the challenge, and the challenge binds the
canonical Permit hash. The verifier MUST additionally compare `permit_id`,
`permit_canonical_hash`, `action`, `resource`, and `modality` with an
independently verified target-Permit context. It MUST NOT treat unverified
fields copied from this claim as the target context. This comparison is what
distinguishes replay of an otherwise valid assertion onto a different Permit
from a malformed challenge produced for the correct Permit.

The claim proves that the registered credential signed the challenge under the
verified WebAuthn ceremony constraints. It does not by itself prove a
hardware-bound credential, an independently rooted identity, notarization, or
third-party independence.

## 6. Offline pack binding

The assertion authenticates the WebAuthn challenge; it does not separately
sign every JSON field in the semantic claim. In particular, `signed_at` is the
recorded assertion-acceptance time, not an authenticator-provided timestamp.

For an offline `supported` verdict, the evidence pack MUST integrity-protect
the complete `permit.co_signature.v1` claim and the key-status material that
resolves its registered co-signer key. A signed pack manifest MUST content-hash
those artifacts. Without verified enclosing pack integrity and trusted key
resolution, an offline verifier returns `insufficient_evidence` even if the
standalone WebAuthn mathematics succeeds.

The canonical Permit hash is computed from the frozen Permit bytes before the
co-signature record is attached; including the co-signature in its own
challenge hash would be circular.

The Phase 0 reference verifier is intentionally a protocol-unit harness. Its
vector inputs treat the target-Permit context and registered COSE key record as
already trusted so it can prove the WebAuthn reconstruction and binding rules
without implementing an evidence-pack verifier.

## 7. Normative verification

A verifier receives the claim, the target-Permit context, the registered
co-signer key record, the expected RP ID, an allowed-origin set, and the
effective `require_user_verification` value. It MUST apply these checks in
order:

1. Validate the closed claim and envelope shapes.
2. Compare the claim's Permit binding fields (`permit_id`,
   `permit_canonical_hash`, `action`, `resource`, and `modality`) with the
   independently verified target-Permit context.
3. Resolve `key_id`; require `credential_id` and `cose_alg` to equal the
   registered key record.
4. Base64url-decode the exact `client_data_json` bytes and parse them as UTF-8
   JSON without changing the bytes.
5. Require `clientDataJSON.type == "webauthn.get"`.
6. Require the challenge equality from section 4.
7. Require `clientDataJSON.origin` to equal one member of the configured
   allowed-origin set. Origins are serialized origins and are compared exactly;
   prefix, suffix, path, and wildcard matching are forbidden.
8. Decode `authenticator_data`; require at least 37 bytes. Require bytes
   `0..31` (`rpIdHash`) to equal `SHA-256(UTF-8(rp_id))`.
9. Parse the flags byte at index 32. Require UP (`0x01`) to be set. Require UV
   (`0x04`) when `require_user_verification` is true; omission of that policy
   field means true.
10. Require the registered COSE key's `alg`, key type, and curve to match the
    declared `cose_alg` profile in section 2.
11. Construct the signed bytes without canonicalization or reserialization:

    ```text
    decoded_authenticator_data || SHA-256(decoded_client_data_json)
    ```

12. Verify the decoded assertion signature over those bytes against the
    registered COSE public key.

BE (`0x08`), BS (`0x10`), and the big-endian `signCount` at bytes `33..36` MAY
be extracted for recording and reporting. This Phase 0 contract does not turn
them into an assurance decision. BS set while BE is clear is malformed
authenticator data.

## 8. `require_co_signature` requirement

The closed policy requirement is defined by
[`require-co-signature-v1.schema.json`](../schemas/require-co-signature-v1.schema.json).

`signer_set` is a non-empty array whose members select exactly one `user_id`,
`email`, or `group`. `min_approvals` has one of three forms:

- integer `1`;
- `{ "n": N, "of": M }` for N-of-M, where producers MUST require
  `1 <= N <= M` and M MUST equal the number of eligible expanded signers; or
- string `"all"`, meaning every eligible expanded signer.

`separation_of_duties` excludes the governed operation's requester when true.
`timeout_seconds` is a positive duration. `role=approver` requires
`phase=pre_execution`; `role=witness` requires `phase=post_execution`.

The forward-compatible assurance fields are:

| Field | Default | Phase 1 behavior |
|---|---|---|
| `min_assurance` | `any` | Recorded; `device_bound` and `hardware_attested` are reserved and MUST NOT be claimed as enforced. |
| `allowed_aaguids` | absent | Recorded if supplied; no allowlist enforcement. |
| `require_user_verification` | `true` | Enforced as the UV check; omission means true. |

JSON Schema `default` values are annotations. Implementations MUST apply the
documented defaults when fields are absent; validation does not mutate input.

## 9. Registered co-signer key record

[`permit-co-signer-key-v1.schema.json`](../schemas/permit-co-signer-key-v1.schema.json)
defines the `permit_co_signer_keys` record contract. It stores the registered
COSE key and requires the following forward-compatible fields to be present:

- `aaguid`;
- `attestation_format`;
- `attestation_statement` (inline, SHA-256 commitment, reference, or null);
- `backup_eligible` (BE);
- `backup_state` (BS);
- `sign_count`;
- `cose_alg`;
- `rp_id`; and
- `credential_id`.

The record also carries `public_key_cose`, `key_id`, `co_signer_id`, and
`custody_tier`. Phase 1 registration uses `attestation_format="none"` and does
not enforce attestation, AAGUID allowlists, BE/BS state, or sign-count clone
detection. Assurance metadata (`aaguid`, attestation material, BE, BS, and
`sign_count`) is nullable; assertion-critical `credential_id`, `cose_alg`,
`rp_id`, and `public_key_cose` are required and non-null because the v1
assertion cannot be verified without them. Nullable does not mean disposable:
producers SHOULD record a value whenever the ceremony supplies one and MUST
preserve historical key records for offline verification.

Later hardware-bound policy can require verified attestation, an AAGUID
allowlist, and `backup_eligible=false`. A later independently rooted identity
can bind an identity root to the same key record. Recording the protocol facts
now keeps both changes additive policy decisions rather than assertion-format
changes.

## 10. Failure reasons and verdicts

The claim uses the repository's four verdicts. A complete valid assertion is
`supported`. A present assertion that violates a binding, ceremony, or
signature rule is `disproved`. Missing trusted key or target-Permit evidence is
`insufficient_evidence`. An unsupported COSE algorithm or curve is
`unverifiable_scope` unless a stricter enclosing profile rejects it earlier.
Golden vectors use `CO_SIGNATURE_VERIFIED` as the non-failure reason for a
`supported` result.

Normative co-signature reason codes are listed in
[`failure-codes.md`](failure-codes.md). When more than one violation is present,
the order in section 7 determines the primary reason. Verifiers MAY also report
additional independently detected reasons.

## 11. Offline vectors

The golden corpus and executable reference verifier are under
[`test-vectors/permit_co_signature/v1/`](../test-vectors/permit_co_signature/v1/).
The vectors exercise positive ES256 and EdDSA assertions and distinct negative
paths for challenge, origin, RP ID hash, UV, authenticator-data tampering,
signature tampering, and cross-Permit replay.
