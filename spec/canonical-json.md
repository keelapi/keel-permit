# Canonical JSON

This document specifies the canonicalization profile used by Keel and by Permit v1 hashing. Two distinct profiles are defined:

- **Wire-body canonicalization** (§3) — applied to provider/tool request bodies before computing `binding_request_hash`.
- **Payload canonicalization** (§4) — applied to closure payloads, audit-export-bundle filter sets, and similar issuer-internal hash inputs.

The profiles intentionally use familiar properties from JSON canonicalization systems such as sorted object keys and insignificant-whitespace removal, but this document does not claim full [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) / JCS compliance. Cross-language implementations MUST prove byte equivalence with shared test vectors before relying on hashes across implementations.

---

## 1. Conformance keywords

MUST, MUST NOT, SHOULD, MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Common rules

Both canonicalization profiles share these rules:

1. **Object keys** MUST be sorted lexicographically by Unicode codepoint.
2. **Whitespace** between tokens MUST be absent. Separators are `,` and `:` only — no spaces.
3. **Strings** MUST be encoded as valid UTF-8.
4. **Output encoding** MUST be UTF-8 bytes. The byte sequence is what is fed to SHA-256.
5. **Numbers** MUST follow the JSON serialization rules of the issuer's pinned canonicalization profile. Issuers SHOULD avoid floating-point numbers in hash inputs; integer or string representations are preferred for amounts, identifiers, and counts.

In Python, both profiles can be produced via:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

`ensure_ascii=False` is normative: non-ASCII characters MUST be preserved as UTF-8 bytes, not escaped.

## 3. Wire-body canonicalization

Used when computing `binding_request_hash` from a provider/tool request payload. The input is the provider/tool request body as a JSON-serializable Python object (dict, list, primitive). The output is canonical UTF-8 bytes.

### 3.1 Volatile-key stripping

Before applying §2's common rules, the issuer MUST strip volatile observability metadata from the payload. Volatile keys are matched **case-insensitively, with non-alphanumeric characters removed before comparison**. The following normalized keys are stripped:

- `requestid`
- `traceid`
- `spanid`
- `idempotencykey`
- `keelrequestid`
- `xrequestid`
- `xkeeltimestamp`
- `timestamp`
- `keelidempotencykey`

Issuers MAY extend this list with additional issuer-internal observability keys, provided that:

- The extension is documented in the issuer's specification supplement.
- Extension keys are stripped consistently across the hash side and the dispatch side; failure to do so produces silent byte-fidelity gaps that nullify dispatch-time equality checks.

### 3.2 Sensitive-key stripping

The following normalized keys MUST also be stripped before canonicalization:

- `authorization`
- `apikey`
- `xapikey`
- `openaiapikey`
- `anthropicapikey`
- `xgoogapikey`
- `proxyauthorization`

These belong in HTTP headers, not in provider/tool request bodies, but defensive stripping prevents accidental commitment of credentials to long-lived hashes.

### 3.3 Required properties

The wire-body canonicalization function MUST be:

- **Deterministic.** Identical inputs under the same pinned canonicalization profile MUST produce byte-identical output across runs, processes, machines, and language runtime versions. Implementations SHOULD pin golden test vectors in CI.
- **Pure.** No I/O, no clock reads, no random sources, no environment lookups, no global-state mutation.
- **Single source of truth.** The same function MUST produce both the bytes that feed `binding_request_hash` and the bytes dispatched as the HTTP request body. Implementations MUST NOT serialize the request body via a different code path; doing so reintroduces the byte-fidelity gap that this spec exists to close.
- **Versioned.** The `v1` rules in this spec are stable. Future bumps MUST use a new function name (e.g., `canonical_provider_wire_body_v2`) and MUST migrate adapter-by-adapter, never silently.

### 3.4 Adapter-specific request shapes

Different providers accept different request shapes (e.g., OpenAI vs. Anthropic vs. Google). The canonicalization function operates on the post-adapter, pre-dispatch request body — i.e., the bytes that will be sent to the provider. The Permit spec is agnostic to which adapter shape was chosen; the dispatch-time equality check guarantees that whatever was bound is what was sent.

## 4. Payload canonicalization

Used when computing the canonical hash of a closure payload (per [`closure-v2.md`](closure-v2.md) §7) or an audit-export-bundle filter set (per [`audit-export-bundle.md`](audit-export-bundle.md) §5).

The rules are §2's common rules applied directly. No volatile-key stripping is performed at this layer; payloads are issuer-controlled and do not contain external request metadata.

The output is `SHA-256(canonical_json(payload))` as a hex digest.

## 5. Library guidance

Implementations are free to use any JSON serialization or canonicalization library that produces output equivalent to the rules above. Guidance:

- **Python**: built-in `json.dumps` with `sort_keys=True, separators=(",", ":"), ensure_ascii=False`.
- **JavaScript/TypeScript**: a library configured to sort object keys, remove insignificant whitespace, preserve UTF-8 string bytes, and match the issuer's number serialization profile.
- **Go**: a library or wrapper that sorts object keys and matches the issuer's number serialization profile; `encoding/json` alone is not sufficient because it does not sort keys.
- **Rust**: a serializer or canonicalization crate configured to match this profile.

Cross-language implementations MUST produce byte-identical output for any equivalent input. Pinning golden test vectors that span all participating languages is RECOMMENDED.

## 6. Forbidden constructs

The following are **out of scope** of this spec and MUST NOT be relied upon for byte-identical canonicalization across implementations:

- **Unicode normalization** (NFC vs. NFD). Issuers using non-ASCII content MUST document a normalization rule; this spec does not mandate one.
- **Floating-point edge cases.** Issuers SHOULD avoid floats in hash inputs; integer or string representations are preferred for amounts, identifiers, and counts.
- **Insignificant whitespace inside strings.** Whitespace inside string values is significant and is preserved verbatim.

## 7. Verifier requirements

A conforming verifier MUST use byte-identical canonicalization to the issuer when recomputing any hash defined in this spec. A drift between issuer canonicalization and verifier canonicalization produces silent verification failures.

Implementations SHOULD ship golden test vectors and exercise them in CI on every change.

## 8. Library version pinning

Where a third-party canonicalization library is used, its major version MUST be pinned in the issuer's and verifier's dependency manifests. A library upgrade that changes byte output for any input is a breaking change requiring coordinated rollout across producer and consumer; in the worst case, it requires a `chain_format_version` bump.
