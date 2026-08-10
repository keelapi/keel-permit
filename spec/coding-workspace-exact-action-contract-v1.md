# Coding Workspace exact action contract v1

This contract defines the three externally meaningful actions in Keel's
Coding Workspace habitat. A model may propose them, but only gateway-derived
facts can select the exact semantic or satisfy policy.

| Tool | Real boundary | Permit |
| --- | --- | --- |
| `code.package.install` | Exact public package/version installed with lifecycle scripts disabled inside one allowlisted disposable workspace | `AI Permit-to-Install-Package` |
| `repository.branch.push` | One complete bounded workspace tree published as one new commit on one allowlisted non-protected GitHub branch | `AI Permit-to-Push-Branch` |
| `repository.pull_request.create` | One GitHub pull request opened from an exact provider-observed head SHA into one exact provider-observed base SHA | `AI Permit-to-Create-Pull-Request` |

## Required enforcement order

1. The agent supplies only Keel credentials and stable demo aliases.
2. The Keel-controlled gateway resolves aliases and reads the current
   workspace, npm registry, and/or GitHub state.
3. The gateway signs a short-lived preflight binding the exact arguments and
   fact snapshot to the connector audience.
4. Keel validates the action-specific fact contract and evaluates policy.
5. Immediately before a new effect, the gateway authenticates the preflight,
   checks its exactly-once journal, re-reads authoritative state, and refuses
   any drift.
6. The gateway dispatches the exact effect and reads the resulting local or
   GitHub state back.

## Install-package boundary

Package names and versions are operator allowlisted. The action cannot choose
an arbitrary registry or version range. The target is a disposable workspace,
not the gateway host or a developer's home directory. Installation uses exact
versions, disables lifecycle scripts, and enforces file/size/time ceilings.
The Permit does not establish package safety, maintainer identity, absence of
malicious package contents, or successful application behavior.

## Push-branch boundary

The target branch must be absent, non-protected, under an operator-approved
prefix, and based on the exact observed base SHA. The gateway derives the full
tree and changed-path digests from its own workspace. It rejects symlinks,
binary/unbounded files, protected paths outside policy, force-pushes, and
updates to an existing ref. The Permit authorizes publishing one exact commit;
it does not authorize a pull request, merge, deployment, or code correctness.

## Create-PR boundary

GitHub must report the exact head and base SHAs, a bounded compare result, and
zero existing open pull requests for the same head/base pair. Creating the PR
does not authorize merging it. The Permit does not establish review approval,
passing checks, mergeability, deployment, or code correctness.

## Outcome and evidence boundary

Keel authorization, gateway dispatch, provider response, and provider readback
are distinct evidence layers. npm process output and GitHub JSON are ordinary
Keel-mediated observations, not independent provider attestations. Unknown or
partially completed Git Database outcomes are never retried blindly; operator
reconciliation is required.
