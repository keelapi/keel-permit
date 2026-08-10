# Identity and Security Exact-Action Contract v1

This contract defines the first exact identity/security consequences. An agent
may propose a target, but it cannot author any current-status, membership,
privilege, factor, ruleset, or duplicate-rule fact used for authorization.
Those facts are read from the named provider by a Keel-controlled gateway and
bound into a short-lived authenticated preflight envelope.

| Exact action | Provider operation | Human artifact title |
|---|---|---|
| `identity.mfa.reset` | Okta `POST /api/v1/users/{id}/lifecycle/reset_factors` | `AI Permit-to-Reset-MFA` |
| `identity.sessions.revoke` | Okta `DELETE /api/v1/users/{id}/sessions?oauthTokens=true` | `AI Permit-to-Revoke-Sessions` |
| `identity.disable` | Okta `POST /api/v1/users/{id}/lifecycle/deactivate?sendEmail=false` | `AI Permit-to-Disable-Identity` |
| `identity.group_access.grant` | Okta `PUT /api/v1/groups/{groupId}/users/{userId}` | `AI Permit-to-Grant-Group-Access` |
| `identity.group_access.remove` | Okta `DELETE /api/v1/groups/{groupId}/users/{userId}` | `AI Permit-to-Remove-Group-Access` |
| `security.indicator.block` | Cloudflare `POST /zones/{zoneId}/rulesets/{rulesetId}/rules` with `action=block` | `AI Permit-to-Block-Indicator` |

## Mandatory boundary

- The agent receives only Keel credentials.
- Okta and Cloudflare credentials, provider object identifiers, MCP bearer
  secrets, preflight HMAC keys, and commitment salt stay in Keel or the
  Keel-controlled identity/security gateway.
- The effect call requires the exact unexpired preflight envelope returned by
  the matching `.preflight` tool. Missing, replayed, expired, or materially
  changed envelopes fail before provider egress.
- Provider identities, groups, factors, memberships, roles, zones, rulesets,
  and existing matching rules are re-read immediately before dispatch.
- A successful authorization does not establish provider acceptance or the
  post-action provider state. Those require separate response and readback
  evidence.

## Invariants

- MFA reset requires at least one currently enrolled factor and binds the
  complete enrollment-state digest.
- Session revocation explicitly includes OAuth tokens. Okta does not expose a
  reliable preflight count of all active sessions, so the signed facts state
  that they are not enumerable instead of inventing a count.
- Identity disable binds current status, role assignments, app assignments,
  group memberships, and an explicit destructive-deprovisioning acknowledgement.
- Group grant requires current membership `false` and target membership `true`.
- Group removal requires current membership `true`, target membership `false`,
  and refuses a last-privileged-member target.
- Indicator block requires an active zone, the custom-firewall phase, an
  enabled `block` rule, zero matching rules at preflight, and an exact one-rule
  count increase. Keel authorizes the block; it does not attest that the
  indicator is malicious.
