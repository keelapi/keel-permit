# Stripe payout-account change exact facts v1

Status: local canonical-artifact candidate, not released, enrolled or live-qualified.

The [exact-facts schema](../schemas/stripe-payout-account-change-exact-facts-v1.schema.json) defines one exact request, `stripe.external_account.create`: attach a tokenized bank account to a Stripe Connect connected account and make it the default payout destination for its currency (`POST /v1/accounts/{account}/external_accounts` with `default_for_currency=true`). Stripe's update endpoint cannot change bank details, so a payout-destination change is this create call. The action moves no money in the call; it changes where later payouts go.

[Selector v24](../semantic_registry/v24.json) preserves every v23 entry and adds exactly this action. [Fact profiles v21](../fact_profiles/v21.json) preserves every v20 profile and its disclosure contract. Existing artifact bytes are unchanged. [`tools/build_stripe_payout_account_change_registries.py`](../tools/build_stripe_payout_account_change_registries.py) rebuilds all of them deterministically.

The facts a reviewer judges are read by the gateway from Stripe, never taken from the agent's arguments: the connected account (a salted commitment plus a state digest), whether the new bank account's fingerprint is new to that account, the new account's last 4 digits, country and currency from Stripe's token object, the last 4 digits of the default it replaces (`none` if there is none) and the existing external-account count. `change_channel` is attested by the gateway deployment that mints the preflight (voice call, staff console, chat, email or API), not by the agent. No routing number, account number, holder name or raw provider identifier is carried; the schema rejects extra fields.

Schema validity creates no grant. A fresh exact preflight, a bounded positive policy grant, REVIEW and managed dispatch remain required. An issuer classifies this action as high impact so every request is held for review by default. A request or authorization does not prove the provider attached the account; only an independent provider readback does.

The public verifier must vendor these exact bytes and release them before an issuer relies on the new versions. No presentation profile or curated title is added by this change.

Run `python tools/check_stripe_payout_account_change_contract.py` and the repository's `make check`. The check is also part of the Permit-to-X contract checker. It rejects dropped, rewritten or duplicate historical entries in both successor registries, proves the committed bytes equal a fresh build, and validates the positive example plus missing-field and malformed-value cases.
