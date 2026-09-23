# Verifier Claims v8

`verifier-claims.v8` adds `mcp.review_journey.v1` to the immutable v7 claim
registry. The canonical artifact is [`claim_registry/v8.json`](../claim_registry/v8.json).
The claim applies only to a self-attesting `keel.evidence_bundle/v2` with body
profile `keel.mcp_review_journey/v1`. A verifier must explicitly adjudicate
that profile; a valid outer signature alone is not a supported journey claim.

The bundle contains a reviewed MCP Permit exact export, an optional distinct
execution Permit exact export, and an optional signed execution closure payload.
Each Permit remains a separate signed decision. The reviewed Permit does not
gain the execution Permit's closure, provider receipts, or status.

## Verification

The verifier checks both inner bundle signatures, the trusted Permit decision
signatures, and the reviewed Permit's signed human approval transition. The
execution Permit must sign a citation to the reviewed Permit ID. The reviewed
Permit's signed resource attributes must contain the same action, fact profile,
and exact request digest as the execution Permit's signed resource attributes.
The request digest must equal the execution Permit's signed final request hash.
For a reported
closure, the verifier checks its signature, execution Permit ID, signed request
digest, and closure hash against the execution export.

An export without an approval transition may verify as
`review_without_approval_transition_in_export`.
An approved review without an execution Permit may verify as
`review_approved_execution_not_in_export`. Neither state proves that no
execution exists elsewhere. A recorded closure must include its signed payload;
a receipt field alone is insufficient.

The execution Permit's review hash and approval requirement hash are signed
citations, but the reviewed Permit exact export does not supply an independent
signed source for those values. The v8 claim does not adjudicate their validity.
It also does not establish dispatch timing or uniqueness, provider completion,
settlement, or any external effect. The signed closure records Keel's observed
request and response digests; it is not an independent downstream oracle.
