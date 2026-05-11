# Fixture Generator Notes

Committed fixture bytes are the conformance product. Generator tooling is a
reproducibility aid for maintainers and is not required to consume the public
test vectors.

Public test-vector tooling should remain deterministic, text-reviewable, and
portable across Linux, macOS, and Windows runners. Generated fixtures must be
byte-stable, use LF line endings, and isolate exactly one expected verifier
failure when testing negative cases.

The public contract for verifier behavior is defined by:

- [`test-vectors/README.md`](../README.md)
- [`test-vectors/CONFORMANCE.md`](../CONFORMANCE.md)
- [`test-vectors/MANIFEST.json`](../MANIFEST.json)
- Fixture-level `expected.json` files

Design notes, implementation diaries, open-decision logs, and planning notes
for fixture-generation work belong in ignored local-only workpaper folders.
