# pinned-neg-required-permit-chain-no-evidence

Pinned negative sibling of `pinned-valid-export-integrity`. The export payload and signature are valid, but the claim_set requires `permit_chain.delegation_denied_correctly.v1` while the pack carries no permit-chain evidence path. A conforming verifier must emit the required claim as `insufficient_evidence` and fail the pack.
