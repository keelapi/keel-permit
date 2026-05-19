# pinned-neg-required-checkpoint-tsa-no-receipt

Pinned negative sibling of `pinned-valid-checkpoint-legacy-single-tsa`. The checkpoint composite hash and signature are valid, but the claim_set requires `checkpoint.tsa_imprint.v1` while the pack carries no TSA receipt. A conforming verifier must emit the required claim as `insufficient_evidence` and fail the pack.
