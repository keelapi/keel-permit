# Merge-to-Production exact-action contract v1

This extension defines three release actions whose provider effects and failure
boundaries are materially different. They must not share a generic deployment
authorization.

| Exact action | Provider operation | Human artifact |
| --- | --- | --- |
| `repository.pull_request.merge` | GitHub `PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge` with the expected head SHA | `AI Permit-to-Merge-Pull-Request` |
| `deployment.commit.deploy` | Fly Machines full-config update with a new immutable image digest | `AI Permit-to-Deploy-Commit` |
| `deployment.rollback` | Fly Machines full-config update with a gateway-recorded prior release config | `AI Permit-to-Roll-Back-Deployment` |

## Trusted preflight

Each action requires a short-lived, gateway-authenticated provider preflight.
The signed facts bind the connector contract, exact request, provider
environment and API version, observed provider state, preflight expiry,
idempotency identity, and requested mutation. The agent cannot supply trusted
provider observations, release-ledger records, or gateway authentication.

The controlled gateway must re-read every material provider fact immediately
before execution and reject drift. A Keel allow decision authorizes only the
bound mutation. It is not a reusable provider credential and it is not evidence
that dispatch or provider success occurred.

## Merge invariant

The merge authorization binds the allowlisted repository, pull-request number,
exact head commit, exact base branch and observed base tip, and merge method.
The gateway requires an open, non-draft, provider-mergeable pull request whose
protected base branch enforces strict passing status checks, at least one
approval, stale-review dismissal, last-push approval, conversation resolution,
and enforcement for administrators. The gateway submits the bound head SHA to
GitHub's merge endpoint so a changed head fails at the provider boundary too.

Approval and check counts are provider observations in the authorization
preflight. They do not replace Keel policy review or co-signature when the Keel
policy requires it.

## Deploy invariant

The deployment authorization binds an allowlisted GitHub source repository and
verified commit, an immutable `ghcr.io` image digest, a production Fly app and
Machine, the current Machine instance and full-config digest, and the exact
target full-config digest. The only permitted config delta is the image.

The gateway reads OCI registry metadata and requires
`org.opencontainers.image.revision` to equal the source commit. This establishes
a provider-observed metadata relationship; it is not an independent build
attestation. The gateway records the provider-observed prior full configuration
in its durable release ledger before dispatch.

Fly updates require both an active Machine lease and `current_version` equal to
the preflight `instance_id`. The gateway sends the entire provider-read Machine
configuration with only the bound image changed, waits for the Machine, and
performs a provider readback. At least one configured health check is required.

## Rollback invariant

Rollback is not an arbitrary image selection. The gateway's durable release
ledger must contain both the failed current release and the immediately prior
release. A fresh Fly read must match the failed release's Machine, instance,
image, and config before Keel is asked to authorize the rollback. The exact
prior image and full-config digest, rollback reason commitment, and both release
record digests are material authorization facts.

Execution again requires a Machine lease and `current_version`, sends the entire
prior configuration, waits, and reads the provider state back. Rolling back a
Machine does not reverse database migrations, messages, payments, or other
external effects caused by the failed release.

## Evidence boundary

The Permit establishes exact pre-execution authorization. A dispatch record
establishes that the controlled gateway attempted the bound provider call.
GitHub or Fly responses and later provider reads can support provider outcome,
but they are not independent attestations. Merge authorization does not prove a
merge or deployment. Deploy and rollback authorization do not prove provider
acceptance, health, traffic serving, data integrity, or reversal of external
effects. These limits remain explicit in every presentation profile.
