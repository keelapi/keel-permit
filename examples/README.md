# Examples

Reference artifacts illustrating the wire formats specified in [`../spec/`](../spec/).

## Files

- [`permit-allow.json`](permit-allow.json) — allow-decision permit in audit-export form, with `binding_request_hash` set.
- [`permit-deny.json`](permit-deny.json) — deny-decision permit with `decision_details`.
- [`closure-v2-closed.json`](closure-v2-closed.json) — `closure_v2` envelope with `closure_status: closed` and all three digest fields (`dispatch_request_digest_v1`, `provider_response_digest_v1`, `client_response_digest_v1`).
- [`chain-entry.json`](chain-entry.json) — single chain entry illustrating the v1 record-hash structure.
- [`audit-export-bundle-v2.json`](audit-export-bundle-v2.json) — illustrative `schema_version: 2` bundle with one record and three chain entries (permit evaluation, dispatch binding, closure). It is schema-valid but is not a full verifier-complete reference bundle.
- [`require-co-signature.json`](require-co-signature.json) — `require_co_signature` approver requirement showing a mixed signer set, N-of-M quorum, separation of duties, and default-off assurance fields.

## Caveat

These examples are **schema-valid illustrative fixtures**, not byte-perfect cryptographic reference bundles. Unless an example is explicitly marked as a cryptographically verifiable reference bundle, it should be used only for schema and shape inspection. Specifically:

- Hash digests, signatures, and key identifiers are **placeholders** that do not cryptographically verify against any real key. They are syntactically valid (correct length, correct base64 / hex character set) so JSON-schema validation works against them, but they are not the output of running SHA-256 or Ed25519 over the example payloads.
- Real chain entries have hashes computed by the algorithm in [`../spec/chain-entry.md`](../spec/chain-entry.md). To inspect real values, run the reference verifier against a real export.
- A full closure verification walk also needs the corresponding provider/client digest chain events. The bundled example keeps the chain short for readability and should not be presented as end-to-end verifier-complete.

For working artifacts that verify end-to-end:

```
pip install keel-verifier
keel-verify export --export-file <bundle.json> --manifest <manifest.json>
```
