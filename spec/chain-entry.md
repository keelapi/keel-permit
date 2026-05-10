# Chain Entry (v1)

A **chain entry** is a record committed to a per-scope hash chain. Each entry's record hash incorporates the previous entry's record hash, so any modification to a past entry invalidates every subsequent entry's hash. A standalone unsigned chain-entry JSON object does not prove itself; tamper-evidence is established when a verifier walks entries delivered in a signed export bundle or compares them with an anchored checkpoint.

This document specifies the chain entry format `v1` and the rules a verifier follows to walk a chain.

---

## 1. Conformance keywords

MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL are interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Chain entry object

```json
{
  "event_id": "string",
  "event_type": "string",
  "resource_type": "string|null",
  "resource_id": "string|null",
  "outcome": "string|null",
  "severity": "string",
  "chain_scope": "string|null",
  "sequence_number": 1,
  "record_hash": "hex-sha256",
  "prev_hash": "hex-sha256",
  "payload_json": { },
  "created_at": "RFC 3339",
  "chain_format_version": "v1"
}
```

| Field | Required | Notes |
|---|---|---|
| `event_id` | yes | Globally unique identifier for the entry. |
| `event_type` | yes | Implementation-defined event type label. |
| `resource_type` | yes (nullable) | Resource type the event references, or null. |
| `resource_id` | yes (nullable) | Resource identifier, or null. |
| `outcome` | yes (nullable) | Optional outcome label, or null. |
| `severity` | yes | Severity label (e.g., `"info"`, `"warning"`, `"error"`). MUST NOT be null. |
| `chain_scope` | yes (non-null) | Scope identifier (e.g., `"project:<uuid>"`, `"admin:global"`). MUST NOT be null in audit-export form. |
| `sequence_number` | yes (non-null) | Monotonically increasing within `chain_scope`, starting at 1. MUST NOT be null in audit-export form. |
| `record_hash` | yes (non-null) | Hex SHA-256 produced by the algorithm in §3. MUST NOT be null in audit-export form. |
| `prev_hash` | yes (non-null) | The `record_hash` of the previous entry in the same `chain_scope`, or a sentinel for the first entry. MUST NOT be null in audit-export form. |
| `payload_json` | yes | Implementation-defined event payload. |
| `created_at` | yes | RFC 3339 timestamp; MUST be UTC (see §3). |
| `chain_format_version` | yes | MUST be `"v1"` for entries hashed under this spec. MUST NOT be null. |

## 3. Record-hash algorithm (`v1`)

The record-hash algorithm `v1` produces:

```
record_hash = sha256_hex(
    event_id + "|" +
    event_type + "|" +
    (resource_type or "") + "|" +
    (resource_id or "") + "|" +
    (outcome or "") + "|" +
    severity + "|" +
    timestamp_str + "|" +
    prev_hash + "|" +
    str(sequence_number)
)
```

`timestamp_str` is the wall-clock representation of `created_at` formatted as `%Y-%m-%dT%H:%M:%S.%f` (microsecond precision, no timezone suffix).

`created_at` MUST be UTC. Conforming emitters MUST produce UTC timestamps; conforming verifiers MAY accept ISO-8601 strings ending in `Z` or `+00:00` and normalize to a naive UTC datetime before formatting. Non-UTC offsets are out of scope: the reference verifier strips the timezone marker without converting, so a non-UTC input would hash its wall-clock components and produce a different `record_hash` than the UTC equivalent. Implementations that emit non-UTC timestamps are non-conforming.

The fractional seconds component MUST be exactly 6 digits. Trailing or leading whitespace in any string component is significant — implementations MUST NOT trim. Null fields are represented as the empty string `""` between the pipe separators, not as the JSON null literal.

## 4. Continuity invariants

A conforming chain MUST satisfy all of:

1. Within each `chain_scope`, `sequence_number` values are strictly increasing with no duplicates.
2. Within each `chain_scope`, every entry's `prev_hash` MUST equal the `record_hash` of the immediately preceding entry. This invariant is what enforces the no-gap property: a missing entry produces a `prev_hash` that does not match any present entry's `record_hash`, surfacing as `WALK_PREV_HASH_DISCONTINUITY`.
3. The `record_hash` of every entry MUST equal the result of the algorithm in §3 applied to the entry's own fields.
4. `chain_format_version` MUST be `"v1"` for entries hashed under this algorithm. Future versions will register additional `chain_format_version` values, each with its own hashing rule.

Note: a conforming verifier checks invariants (1)–(4) above for the supplied entries. It does NOT check that `sequence_number` values are densely consecutive (e.g., that `[1, 2, 3, ...]` has no integer gaps); densely consecutive numbering is an issuer convention, not a normative requirement. Deletion inside a supplied contiguous segment is detected through invariant (2). A partial export window does not by itself prove that entries before the first supplied entry or after the last supplied entry were included unless the window is tied to an anchored checkpoint or another documented continuity proof.

## 5. Verifier walk procedure

Given a set of chain entries grouped by `chain_scope`, a conforming verifier MUST:

1. Group entries by `chain_scope`.
2. For each scope, sort by `sequence_number` ascending.
3. Detect duplicates: if two entries share `(chain_scope, sequence_number)`, fail with `WALK_SEQUENCE_INVERSION`.
4. Detect inversions: if the as-received order does not match the sorted order, fail with `WALK_SEQUENCE_INVERSION`.
5. For each entry, recompute `record_hash` per §3; on mismatch, fail with `WALK_RECORD_HASH_MISMATCH`.
6. For each entry after the first, check that `prev_hash` equals the previous entry's `record_hash`; on mismatch, fail with `WALK_PREV_HASH_DISCONTINUITY`.
7. If `chain_format_version` is unrecognized, fail with `WALK_UNKNOWN_CHAIN_FORMAT`.

A walk that completes without emitting a failure code constitutes a successful chain integrity verification for the supplied entries. It does not prove completeness outside the export window being verified.

## 6. Scope semantics

Chain scopes partition entries into independent integrity domains. Common scope shapes:

- `project:<uuid>` — per-project chain. The default for project-emitted events.
- `admin:global` — system-wide operator events not attached to any project.

This spec is agnostic to scope naming. Implementations MAY define additional scopes provided that the partitioning is total — every entry MUST have exactly one scope.

Cross-scope ordering is **not** part of chain integrity. Two entries in different scopes have no relative ordering relationship even if their `created_at` timestamps suggest one. A verifier MUST NOT compare `sequence_number` values across scopes.

## 7. The first entry in a scope

The first entry in a `chain_scope` (`sequence_number == 1`) MUST have `prev_hash` set to a sentinel value defined by the implementation. Common choices:

- The string `"0"` repeated 64 times (zero-prefixed sentinel).
- The hex SHA-256 of the empty string.
- An implementation-defined origin marker recorded in the issuer's documentation.

A verifier MUST accept the sentinel chosen by the issuer. The sentinel value MUST be stable for the lifetime of the chain; rotating the sentinel is a breaking change requiring a new `chain_format_version`.

## 8. Tamper detection properties

By construction:

- Modifying any field of any entry changes its `record_hash`. The verifier reports `WALK_RECORD_HASH_MISMATCH` at the position of the modification.
- Replacing one entry with another changes its `record_hash` — and even if the new `record_hash` is computed correctly, the next entry's `prev_hash` no longer matches, so `WALK_PREV_HASH_DISCONTINUITY` fires at position `n+1`.
- Reordering entries within a scope produces `WALK_SEQUENCE_INVERSION` (when the as-received sequence is non-monotonic) or `WALK_PREV_HASH_DISCONTINUITY` (when sequence numbers are rewritten but hashes do not match).
- Deleting an entry from inside a supplied contiguous chain segment makes the next included entry's `prev_hash` fail to match the previous included entry's `record_hash`, producing `WALK_PREV_HASH_DISCONTINUITY`.
- Inserting a forged entry without rebuilding the chain produces `WALK_PREV_HASH_DISCONTINUITY` at the next legitimate entry.

These properties hold for entries whose ordering and bytes are committed by a signed bundle manifest or an anchored checkpoint, against any party who cannot produce a valid issuer signature or anchor. Defenses against signing-key compromise are outside the scope of this document; see the issuer's trust model.

## 9. Reserved field names

The following field names are reserved for future versions and MUST NOT be repurposed:

- `record_hash_v2` and similar future-version fields.
- `signature` (reserved for entry-level signatures in a future spec revision).

## 10. Future versions

`chain_format_version` is the discriminator for hash algorithm versions. A future `v2` may, for example, replace pipe-delimited string concatenation with canonical JSON, or add new fields to the hash input. Such a change MUST:

- Use a new `chain_format_version` value (e.g., `"v2"`).
- Be specified in a new spec document under this directory.
- Coexist with `v1` indefinitely; verifiers MUST carry both algorithms.
