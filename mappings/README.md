# Permit v1 → Control Framework Mappings

Machine-readable mapping from Permit v1 wire-format fields and audit-export-bundle artifacts to specific control IDs in major AI / security / privacy frameworks. Use this when you need to answer "which Permit field satisfies which control evidence requirement?"

## Status

**Draft, version 0.1.0.** Three verification tiers reflected in the JSON's `verification_status` block:

| Tier | Frameworks | Status |
|---|---|---|
| **Verbatim verified** (`verified_2026_05_10`) | CCPA §1798.105(d), 11 CCR §7001/§7150/§7152/§7155, EU AI Act Art 26(6), GDPR Art 17(3)(b), NIST AI RMF 1.0, OWASP LLM Top 10 (2025) | Subsection IDs and verbatim titles confirmed from official source documents on 2026-05-10 |
| **Verified structurally** (`verified_structurally_only`) | AICPA SOC 2 TSC, ISO/IEC 42001:2023 | Category-level / clause-level structure confirmed from public framework knowledge; **sub-criterion verbatim titles NOT independently verified** (SOC 2 TSC requires AICPA registration; ISO 42001 standard text is paywalled). Mappings are cited at category/clause level. Confirm sub-criterion verbatim from authoritative source before customer-facing publication. |
| **Draft / unverified** (`draft_unverified`) | MITRE ATLAS, OWASP API Security / ASVS | Not yet mapped in this revision |

## Files

- `control-frameworks.schema-mapping.json` — the machine-readable mapping artifact.
- This README.

## Verified citations (2026-05-10)

### Verbatim verified

| Citation | Source | Verification method |
|---|---|---|
| California Civil Code §1798.105(d)(2) | leginfo.legislature.ca.gov | Direct WebFetch, verbatim |
| California Civil Code §1798.105(d)(8) | leginfo.legislature.ca.gov | Direct WebFetch, verbatim |
| 11 CCR §7001(e) (ADMT definition) | CPPA Final Adopted Text Sep 22 2025 | Direct PDF read, verbatim |
| 11 CCR §7150(b) (risk assessment triggers) | CPPA Final Adopted Text | Direct PDF read, verbatim |
| 11 CCR §7152(a) (Risk Assessment Requirements) | CPPA Final Adopted Text | Direct PDF read, verbatim |
| 11 CCR §7155(a) (timing/retention) | CPPA Final Adopted Text | Direct PDF read, verbatim |
| EU AI Act Article 26(6) | artificialintelligenceact.eu | Pre-existing direct fetch (per internal memo) |
| GDPR Article 17(3)(b) | gdpr-info.eu | Pre-existing direct fetch (per internal memo) |
| NIST AI RMF 1.0 — Functions GOVERN/MAP/MEASURE/MANAGE | nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf | Direct PDF read, verbatim for GOVERN/MAP/MEASURE subcategories; structural for MANAGE |
| OWASP Top 10 for LLM Applications (2025) — LLM01:2025 through LLM10:2025 | genai.owasp.org/llm-top-10/ | Direct WebFetch, verbatim |

### Verified single-source (medium confidence)

| Framework | What's single-source | Notes |
|---|---|---|
| ISO/IEC 42001:2023 individual Annex A controls | 38 control IDs and verbatim titles (e.g., A.6.2.8 AI-System Recording of Event Logs) | Sourced from ISMS.online only. Section structure (A.2-A.10) and total count (38) corroborated by Vanta + Advisera. Individual control titles within sections need second-source verification — confirm against the official standard or an audit-firm copy before customer-facing publication. |

### Verified structurally only

| Framework | Public structure | Paywall / gating |
|---|---|---|
| AICPA SOC 2 TSC | CC1-CC9 category structure is public knowledge; mapped at category level (CC3 Risk Assessment, CC6 Logical and Physical Access, CC7 System Operations, CC8 Change Management, CC9 Risk Mitigation) | AICPA TSC 2017 (with 2022 revisions) requires registration/download from aicpa-cima.com — sub-criterion verbatim titles NOT independently verified in this pass |

## Critical scoping notes

### What §7152 covers (FINAL ADOPTED text)

A risk assessment under 11 CCR §7152 is required when a business uses Automated Decisionmaking Technology (ADMT) to **replace or substantially replace human decisionmaking** for a "significant decision" (financial/lending, housing, insurance, education, employment, healthcare, essential goods, criminal justice — §7150(b)(3)), OR trains ADMT for those uses or for facial-recognition / emotion-recognition / identity-verifying / biological-identification or profiling technology (§7150(b)(6)).

Pure copilots and recommendation systems with meaningful human review (where the reviewer satisfies the §7001(e)(1) human-involvement test) are **NOT** in scope.

### What was REMOVED from proposed → final adopted text

These provisions appeared in the November 2024 proposed text but were **removed before final adoption**. Do NOT cite them as current law:

- §7150(b)(4)(E) "operation of generative models, such as large language models"
- §7150(b)(4)(D) deepfake training trigger
- §7001(c) separate "Artificial intelligence" definition
- §7152(a)(2)(B) ADMT "quality of personal information" sub-block
- §7152(a)(6)(B) detailed ADMT evaluation framework (collapsed to (a)(6)(A)(iv))
- ADMT scope language "execute a decision" and "substantially facilitate"

### Always include the section prefix on CCPA citations

Use `California Civil Code §1798.105(d)(2)` rather than bare `(d)(2)`. Bare-shorthand references caused a downstream LLM (ChatGPT, May 2026) to misroute to 11 CCR §7152 — an unrelated regulation about Risk Assessment Requirements. The section prefix prevents that ambiguity.

## Effective dates

| Provision | Effective |
|---|---|
| 11 CCR Article 9 (Cybersecurity Audits) | January 1, 2026 (phased-in compliance per §7121) |
| 11 CCR Article 10 (Risk Assessments — §7150 thru §7157) | January 1, 2026 |
| 11 CCR Article 11 (ADMT — notice, opt-out, access provisions) | January 1, 2027 |
| EU AI Act Article 26(6) for new high-risk AI | August 2, 2026 |
| EU AI Act Article 26(6) for legacy systems | August 2, 2027 |
| California Civil Code §1798.105(d) | In force (CPRA amendments operative 2023-01-01) |
| GDPR Article 17(3)(b) | In force |

## Schema

The JSON file structure:

```
{
  "verification_status": { ... summary of which citations are verified vs draft ... },
  "frameworks": { framework_id: { name, scope, source, effective_status, verification } },
  "mappings": [
    { permit_field, controls: [{ framework, control_id, evidence_type, rationale }] }
  ],
  "audit_export_bundle_mappings": [
    { artifact, controls: [...] }
  ],
  "explicit_non_mappings": [
    { framework, control_id, status, rationale }
  ]
}
```

`evidence_type` is one of:
- **necessary** — the field is required to satisfy the control but may need additional evidence to be sufficient
- **sufficient** — the field directly satisfies the control
- **partial** — the field contributes evidence but is not necessary nor sufficient on its own

## When to update this artifact

- A new framework is added to the priority list.
- An existing framework releases a new revision (e.g., NIST AI RMF 2.0).
- A regulation moves from proposed to adopted (or vice versa).
- The Permit Spec wire format changes such that field semantics shift.

When updating, re-verify EVERY citation against the canonical published source. Do not trust prior LLM outputs (Perplexity, ChatGPT, or otherwise) for verbatim statutory text.

## License

Apache License 2.0, same as the Permit Spec.
