# Governance

Permit Spec is maintained by Keel API, Inc. This document records who holds
access, who is responsible for what, and how decisions are made. It describes
the process actually in use, not an aspirational one.

## Current state

This is a **single-maintainer project**. Every role below is currently held by
the same person. That is stated plainly rather than disguised behind role names,
because the distinction matters to anyone assessing the project: there is no
separation of duties today, and no second reviewer.

| Role | Holder | Responsibilities |
|---|---|---|
| **Maintainer** | [@sftimeless](https://github.com/sftimeless) | Reviews and merges pull requests; approves normative specification changes; cuts releases; administers repository settings and branch protection. |
| **Security contact** | `security@keelapi.com` (monitored by the maintainer) | Receives private vulnerability reports; acknowledges within three business days; coordinates disclosure and publishes advisories. See [`SECURITY.md`](SECURITY.md). |
| **Release manager** | [@sftimeless](https://github.com/sftimeless) | Assigns version identifiers, writes CHANGELOG entries, and creates GitHub Releases. |

### Access to sensitive resources

Administrative and write access to this repository is held by
[@sftimeless](https://github.com/sftimeless) alone. There are no other
collaborators, no deploy keys, and no automation tokens with write access.

Access is constrained by enforced controls rather than convention:

- Direct commits to `main` are blocked for **all** users, administrators
  included (`enforce_admins` is enabled).
- Every change reaches `main` through a pull request that passes the
  `repo-integrity` status check.
- Force pushes to `main` and deletion of `main` are blocked.
- Multi-factor authentication is required to authenticate to the account
  holding this access.

## Decision making

**Editorial changes** — clarifying prose, fixing links, correcting typos — are
merged once CI passes.

**Normative changes** — anything altering what a conforming implementation must
do — additionally require that the change be expressible as a version bump under
the rules in [`CONTRIBUTING.md`](CONTRIBUTING.md). Breaking wire-format changes
require a new format version; previous versions remain valid indefinitely so
historical artifacts continue to verify.

**Disagreements** are resolved in the public issue or pull request thread. As a
single-maintainer project there is no tie-break procedure, because there is no
tie to break. If the project gains additional maintainers this section will be
replaced with a real one.

## What this project does not have

Stated explicitly, because their absence is material to a security assessment:

- **No non-author review.** Pull requests are authored and merged by the same
  person. Automated checks are the only gate.
- **No separation of duties** between contribution, review, release, and
  security response.
- **No formal succession plan.** If the maintainer becomes unavailable, the
  specification remains available under Apache-2.0 and can be forked, but no
  continuity arrangement is in place.

## Becoming a maintainer

There is no maintainer-nomination process yet, because there has been no second
contributor. Sustained, high-quality contribution is the path; open an issue to
start the conversation. Any future grant of elevated access will be recorded in
this document.

## Changes to this document

Changes to governance follow the same pull-request process as any other change
and are recorded in the git history of this file.
