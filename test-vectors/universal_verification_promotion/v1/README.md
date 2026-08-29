# Universal Verification Promotion Corpus v1

These vectors define the additive promotion from the immutable candidate recipe
[`keel.permit.universal_verification.v6`](../../../semantics/permit/universal_verification_v6.json)
to the released recipe
[`keel.permit.universal_verification.v7`](../../../semantics/permit/universal_verification_v7.json).

The promotion changes no Action Mapping rule. Version v7 pins the exact v6
bytes, uses `status: "released"`, and repeats the v6 `body` byte-for-value after
JSON parsing. Version v6 remains available with its original candidate bytes so
historical pins continue to resolve.

Run the dependency-free reference executor with:

```sh
python3 test-vectors/universal_verification_promotion/v1/reference_executor.py
```

The corpus establishes only promotion-chain integrity. A public verifier must
still explicitly allowlist recipe v7 and ship the exact bytes before evidence
packs may rely on the released recipe identity.
