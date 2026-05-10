# Permit v1 → Control Framework Mappings

Machine-readable mapping from Permit v1 wire-format fields and audit-export-bundle artifacts to specific control IDs in major AI / security / privacy frameworks. Use this when you need to answer "which Permit field satisfies which control evidence requirement?"

## Status

**Draft, version 0.1.0.** Two verification tiers remain active in the JSON's `verification_status` block:

| Tier | Frameworks | Status |
|---|---|---|
| **Verbatim verified** (`verified_2026_05_10`) | CCPA §1798.105(d), 11 CCR §7001/§7150/§7152/§7155, EU AI Act Art 26(6), GDPR Art 17(3)(b), NIST AI RMF 1.0, OWASP LLM Top 10 (2025), **ISO/IEC 42001:2023 Clauses 3-10 + subclauses + Annex structure**, **AICPA SOC 2 Trust Services Criteria CC1.1–CC9.2**, **MITRE ATLAS 14 tactics + ~50 techniques**, **OWASP API Security Top 10 (2023)**, **OWASP ASVS v5.0.0**, **FedRAMP / NIST SP 800-53 Rev 5**, **CIS Controls v8.1**, **PCI DSS v4.0.1** | Subsection IDs and verbatim titles confirmed from official source documents on 2026-05-10. ISO 42001 clauses + subclauses + Clause 3 definitions + annex structure verified from authoritative ISO/IEC publication preview distributed via iTeh Standards. SOC 2 common criteria verified verbatim from the authoritative AICPA-published TSP Section 100 (2017 TSC with Revised Points of Focus — 2022). MITRE ATLAS verified from canonical ATLAS.yaml at github.com/mitre-atlas/atlas-data. OWASP API and ASVS verified from owasp.org and github.com/OWASP/ASVS respectively. FedRAMP / NIST SP 800-53 Rev 5 control titles for the 23 mapped controls verified from csf.tools NIST-content mirror. CIS Controls v8.1 (May 2024) all 18 controls verified from cisecurity.org. PCI DSS v4.0.1 (June 2024) all 12 requirements verified. **AUTHORIZATION/VALIDATION CAVEATS: Keel is NOT FedRAMP authorized and NOT PCI-DSS validated — both mappings describe customer-side evidence support only. See dedicated sections below.** |
| **Two-source corroborated** (`verified_two_source_corroborated`) | ISO/IEC 42001:2023 individual Annex A control IDs + semantic content | ISMS.online and Mindsetcyber independently agree on all 38 control IDs, 9-section structure, control counts per section, and semantic content of each title. Differ only on stylistic conventions (Title Case + hyphenated vs lowercase + space). Exact verbatim typography remains MEDIUM CONFIDENCE pending the paywalled official Annex A pages from iso.org. Three other public summaries (Bastion, Reconn, isauditr) checked on 2026-05-10 and rejected for reproducing different draft/proposed structures — documented inline in the JSON. |

`verified_single_source`, `verified_structurally_only`, and `draft_unverified` tiers are all empty after the 2026-05-10 verification pass.

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
| ISO/IEC 42001:2023 Clauses 4-10 + all subclauses (e.g., 4.1, 6.1.1-6.1.4, 7.5.1-7.5.3, 9.2.1-9.2.2, 9.3.1-9.3.3, 10.1-10.2) | cdn.standards.iteh.ai (authoritative ISO/IEC publication preview via iTeh Standards) | Direct PDF/preview read, verbatim ToC + Clauses 1-3 text |
| ISO/IEC 42001:2023 Clause 3 Terms and Definitions (3.1-3.26) | cdn.standards.iteh.ai (iTeh authoritative preview pages 1-4) | Direct read, verbatim definitions |
| ISO/IEC 42001:2023 Annex structure (A normative, B normative, C informative, D informative) | cdn.standards.iteh.ai (iTeh authoritative preview ToC) | Direct read; correction note: Annex B is **NORMATIVE** in the final standard (earlier public drafts and some third-party summaries had Annex B as informative) |
| AICPA SOC 2 Trust Services Criteria — common criteria CC1.1 through CC9.2 (33 sub-criteria) | AICPA TSP Section 100, 2017 TSC with Revised Points of Focus — 2022 (registration-gated public download) | Direct PDF read of authoritative AICPA publication, pages 14-48; all sub-criterion titles captured verbatim |
| MITRE ATLAS — 14 tactics (AML.TA0000-AML.TA0015) and ~50 technique IDs+titles | github.com/mitre-atlas/atlas-data/dist/ATLAS.yaml (canonical machine-readable source) | Direct fetch of ATLAS.yaml on 2026-05-10; note current ATLAS terminology uses "AI" not "ML" (e.g., "AI Model Inference API Access") |
| OWASP API Security Top 10 (2023) — API1:2023 through API10:2023 | owasp.org/API-Security/editions/2023/en/0x11-t10/ | Direct WebFetch on 2026-05-10, verbatim |
| OWASP ASVS v5.0.0 — chapters V1-V17 | github.com/OWASP/ASVS/tree/master/5.0/en (canonical 5.0 source folder) | Direct fetch on 2026-05-10; ASVS v5 chapter numbering is NOT backwards-compatible with v4 |
| FedRAMP / NIST SP 800-53 Rev 5 — verbatim titles for 23 mapped controls across AU, AC, CM, CA, IR, SI, SC families | csf.tools NIST-content mirror; cross-checked with NIST CSRC publication page (csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | Direct WebFetch of family pages on 2026-05-10; NIST SP 800-53 Rev 5 originally published September 2020, latest release 5.2.0 issued August 27, 2025 |
| CIS Critical Security Controls v8.1 — all 18 controls | cisecurity.org blog post for v8.1 controls list | Direct WebFetch on 2026-05-10; v8.1 published May 2024 |
| PCI DSS v4.0.1 — all 12 requirements | Wikipedia summary cross-referenced to PCI SSC document library (pcisecuritystandards.org) | Direct WebFetch on 2026-05-10; v4.0.1 released June 2024 (v4.0 was March 2022 with full enforcement April 1, 2024); 12 top-level requirement titles have been stable across PCI DSS versions |

### Verified two-source corroborated (upgraded 2026-05-10)

| Framework | What's two-source corroborated | Notes |
|---|---|---|
| ISO/IEC 42001:2023 individual Annex A controls | All 38 control IDs + semantic content of each title | ISMS.online and Mindsetcyber (mindsetcyber.com.au/iso-42001-controls-list/) independently agree on all 38 IDs, the 9-section structure (A.2-A.10), section control counts (3+2+5+4+9+5+4+3+3=38), and the semantic content of every title. Differ only on stylistic conventions: ISMS.online uses Title Case + hyphenated "AI-System"; Mindsetcyber uses lowercase "AI system" without hyphen. JSON adopts the ISMS.online convention. **Authoritative iTeh preview ends at Clause 4.4** (Annex A is on page 17 of the paywalled section, NOT in the public preview). Exact verbatim wording (capitalization, hyphenation, singular/plural) is MEDIUM CONFIDENCE pending the paywalled official Annex A pages. |

### Sources checked and rejected for ISO 42001 Annex A (2026-05-10)

Three other commonly-cited third-party summaries were checked on 2026-05-10 and **found to materially disagree** with the two-source-corroborated structure. Most likely they reproduce earlier ISO 42001 **proposed-text drafts** rather than the final 2023 adopted standard. **Do not cite as Annex A sources.**

| Source | Why rejected |
|---|---|
| bastion.tech/learn/iso42001/annex-a-controls | Lists control IDs that don't exist in the final standard (A.3.4, A.6.2.9, A.6.2.10, A.6.2.11); A.5.4 reproduced as "Impact of AI System Documentation" which is materially different from the two-source-corroborated "Assessing AI-System Impact on Individuals or Groups of Individuals" |
| orbit.reconn.io/iso-42001-controls-guide/ | Has A.4.1, A.6.1.1, A.6.1.5 (don't exist); claims A.6.2.4 is "AI System Event Logs" (final places event logs at A.6.2.8); claims A.7.5 is "Processing of Personal Information" (final is "Data Provenance") |
| isauditr.com/blog/iso-42001-annex-a-38-controls-practical-guide-auditors | Article discusses controls conceptually but does not list a complete verbatim Annex A; not usable as a primary verification source |

### CC7.5 → CC7.2 correction (2026-05-10)

A prior draft mapped the "RFC 3161 timestamp receipt anchored to integrity checkpoint" artifact to `CC7.5 (System Operations — Logging)`. That label was a double error:

- **Wrong criterion** — CC7.5 verbatim is *"The entity identifies, develops, and implements activities to recover from identified security incidents."* Recovery, not logging.
- **No standalone "Logging" criterion exists in TSC** — log-related evidence is distributed across CC2.1 (information quality), CC4.1 (ongoing/separate evaluations), and CC7.2 (anomaly monitoring and change-detection).

Corrected mapping: **CC7.2** — *"The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events."* RFC 3161 timestamps map specifically to the "Implements Change-Detection Mechanisms" point of focus under CC7.2 (file integrity monitoring is a named example).

This is the kind of error that gets caught only by reading the authoritative AICPA text — exactly the upgrade this revision delivered.

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

## FedRAMP — mandatory framing discipline

**Keel API, Inc. is NOT a FedRAMP-authorized Cloud Service Offering.** No Joint Authorization Board (JAB) Provisional Authorization, no Agency ATO, not listed on the FedRAMP Marketplace as of 2026-05-10.

The FedRAMP mapping in this artifact describes how Keel-produced evidence (Permit records, hash-chained audit logs, Ed25519 signed exports, RFC 3161 timestamps, externally anchored checkpoints) can **support a customer's NIST SP 800-53 Rev 5 control implementations** within the customer's existing FedRAMP-authorized boundary, under that boundary's shared-responsibility model. The customer remains the FedRAMP-authorized entity.

### Correct framing in customer-facing material

✅ "Keel evidence supports NIST 800-53 Rev 5 audit-and-accountability controls (AU family) within your FedRAMP-authorized boundary."

✅ "Keel produces the evidence artifacts your 3PAO needs to demonstrate NIST 800-53 AU-9, AU-10, AU-12 compliance for AI/ML workloads under your boundary."

✅ "Keel substrate supports customers operating under FedRAMP Low / Moderate / High / LI-SaaS baselines who need cryptographically verifiable AI-decision evidence."

### Incorrect framing — do NOT use

❌ "Keel is FedRAMP authorized" — false
❌ "Keel is FedRAMP compliant" — false; only authorized CSOs are 'compliant'
❌ "Keel supports FedRAMP High" — ambiguous; correct: "Keel evidence supports customers operating under FedRAMP High baseline"
❌ "Use Keel to satisfy FedRAMP" — false; Keel does not satisfy any FedRAMP requirement on its own
❌ "Keel is on the FedRAMP Marketplace" — false

### Coverage scope

| Control family | Permit fit | Mapped controls |
|---|---|---|
| **AU** Audit and Accountability | **Strongest** | AU-2, AU-3, AU-4, AU-6, AU-7, AU-8, AU-9, AU-9(2), AU-9(3), AU-10, AU-11, AU-12 |
| **AC** Access Control | Partial | AC-3, AC-6 |
| **CM** Configuration Management | Partial | CM-3, CM-8 |
| **CA** Assessment, Authorization, and Monitoring | Partial | CA-7 |
| **IR** Incident Response | Partial | IR-4, IR-5 |
| **SI** System and Information Integrity | Strong | SI-7, SI-12 |
| **SC** System and Communications Protection | Partial | SC-13, SC-28 |

**Total: 23 mapped controls + 3 documented "uncovered high-priority controls" + 3 explicit non-mappings.** 13 of 20 NIST 800-53 control families are entirely out of scope for the Permit substrate (PE, MA, MP, PS, PL, PM, AT, etc.) and any FedRAMP claim covering them would be over-claim.

### Future path

If Keel itself pursues FedRAMP authorization in the future: (1) engage a FedRAMP 3PAO, (2) develop System Security Plan (SSP) mapping all required controls, (3) Security Assessment, (4) Agency ATO sponsorship OR JAB Provisional Authorization. Timeline: 12-18 months; cost: $250K-$1M+. This is post-revenue, post-design-partner-validation work — not pre-revenue.

## PCI DSS — narrow scope + framing discipline

**Keel API, Inc. is NOT a PCI-DSS-validated service provider.** No Attestation of Compliance (AOC), no Report on Compliance (ROC), not listed as PCI-DSS-validated as of 2026-05-10.

**More importantly: PCI DSS itself applies only to entities handling cardholder data within a defined Cardholder Data Environment (CDE).** For most B2B SaaS AI workloads — including the majority of Keel's ICP — PCI DSS does not apply at all.

### When PCI mappings are RELEVANT

Only when AI workloads touch a customer's CDE. Concrete examples:

- AI-driven fraud detection on transaction data
- AI-augmented customer service with payment context
- AI-powered chargeback processing
- AI-driven payment flow optimization

For these cases, Permit substrate maps to:

| Requirement | Permit fit | Notes |
|---|---|---|
| **Req 10** Log and monitor all access to system components and cardholder data | **Sufficient** | Hash chain + signed exports + TSA = tamper-evident audit logging satisfying Req 10.5. Enterprise tier (365d retention) recommended for PCI 12-month floor. |
| Req 6 Develop and maintain secure systems and software | Partial | policy_id + policy_version + policy diff tracking |
| Req 7 Restrict access by business need to know | Partial | Permit gating at AI-action boundary |
| Req 12 Support information security with organizational policies and programs | Partial | Permit policies are documented |

### When PCI mappings are NOT relevant

For B2B SaaS AI use cases that do not process payment card data, **do not cite PCI mappings as a general AI governance signal.** Cite SOC 2, ISO 42001, NIST AI RMF, EU AI Act, or CCPA/CPPA instead.

### Correct framing for PCI-in-scope cases

✅ "Keel evidence supports PCI DSS Requirement 10 (audit logging and monitoring) for AI workloads that touch your Cardholder Data Environment."

❌ "Keel is PCI DSS compliant" — false
❌ "Keel is PCI certified" — false
❌ "Use Keel to meet PCI" — false

## CIS Controls v8.1 — coverage scope

CIS Controls v8.1 (May 2024) is a voluntary framework with 18 controls. Permit substrate maps naturally to 6 of 18:

| Control | Permit fit | Notes |
|---|---|---|
| **Control 8** Audit Log Management | **Sufficient** | Strongest CIS fit — hash chain + signed exports + TSA satisfies safeguards 8.2, 8.3, 8.10, 8.11 |
| Control 3 Data Protection | Partial | AI-decision audit evidence at rest |
| Control 4 Secure Configuration of Enterprise Assets and Software | Partial | policy_id is config-as-code for AI |
| Control 6 Access Control Management | Partial | AI-action access control boundary |
| Control 15 Service Provider Management | Partial | Keel as service provider + resource_provider inventory |
| Control 16 Application Software Security | Partial | closure_v2 cryptographic binding |
| Control 17 Incident Response Management | Partial | Incident evidence export bundle |

**Out of scope (12 of 18):** Controls 1, 2, 5, 7, 9, 10, 11, 12, 13, 14, 18. Customer addresses these via standard security tooling — these are not procurement-blocking gaps in the Keel substrate, they are simply outside Permit scope.

CIS Controls are recognized in mid-market security questionnaires but rarely a hard procurement gate.

## Coverage scope for security/adversary frameworks

Three frameworks added in the 2026-05-10 pass have **narrower natural mappings** than the compliance/AI-governance frameworks. This is intentional — Permit is pre-execution governance plus tamper-evident evidence, not adversary detection or general application security. Honest scoping:

### MITRE ATLAS (~13 of ~50 techniques mapped)

In scope: AI Model Access (T0040, T0044, T0047), Execution (T0050, T0051, T0053), Defense Evasion / Privilege Escalation (T0054), Exfiltration (T0024, T0056), Impact (T0029, T0034, T0046), Initial Access (T0049 as partial).

Explicitly out of scope: Reconnaissance, Discovery, Persistence, Lateral Movement, Command and Control. These are SOC/EDR responsibilities, not Permit-primitive scope.

### OWASP API Security Top 10 (2023) — 8 of 10 items mapped

Mapped: API1 (BOLA), API2 (Broken Auth — necessary identity context), API3 (Property-level Authz), API4 (Resource Consumption — sufficient via budgets), API5 (Function-level Authz — sufficient), API6 (Sensitive Business Flows), API9 (Inventory), API10 (Unsafe Consumption of APIs).

Explicit non-mappings: **API7 Server Side Request Forgery** (network-layer concern), **API8 Security Misconfiguration** (deployment/config baseline concern). Both are listed in `explicit_non_mappings`.

### OWASP ASVS v5.0.0 — 6 of 17 chapters mapped

Mapped: V4 (API and Web Service), V8 (Authorization), V11 (Cryptography), V13 (Configuration), V14 (Data Protection), V16 (Security Logging and Error Handling).

Not load-bearing for Permit: V1, V3, V5, V7, V17. **V17 WebRTC** is in `explicit_non_mappings` because Permit has no WebRTC surface.

**Version qualifier matters:** ASVS v5 (2025) is NOT backwards-compatible with v4. Cite as "ASVS v5.0.0" in customer-facing artifacts to avoid the v4 vs v5 ambiguity (e.g., v5 V8 = Authorization; v4 V8 = Data Protection — different chapters entirely).

## Multi-source verification methodology (ISO 42001 lesson learned)

Initial verification of ISO/IEC 42001:2023 went through three sources with materially different signal:

1. **ChatGPT** — confident verbatim claim of 38/38 Annex A controls with multi-source citations. Independently useful for triangulating control IDs across publicly available summaries.
2. **Perplexity** — cautious paraphrase, recommended buying the standard. Useful as a calibration on confidence: when Perplexity refuses to verbatim-quote, treat ChatGPT verbatim claims as needing a third source.
3. **iTeh Standards** (`cdn.standards.iteh.ai`) — authorized ISO reseller; their public "samples" preview is the **authoritative ISO/IEC publication preview** (front matter + Clauses 1-3 verbatim + ToC). This is the closest free source to the canonical standard and is what we used to verbatim-verify clauses, subclauses, definitions, and annex structure.

**Pattern to repeat:** when an LLM offers verbatim text from a paywalled standard, the verifier should (a) check whether an authorized reseller publishes a preview/sample, (b) read that preview directly, and (c) downgrade any LLM-quoted text outside the preview window from "verbatim verified" to "single-source, medium confidence."

This is the same pattern that previously caught Perplexity hallucinating pre-CPRA CCPA text and ChatGPT misrouting bare `(d)(2)` shorthand to a different regulation. **Direct fetch of the authoritative source remains the only reliable verification path.**

## When to update this artifact

- A new framework is added to the priority list.
- An existing framework releases a new revision (e.g., NIST AI RMF 2.0).
- A regulation moves from proposed to adopted (or vice versa).
- The Permit Spec wire format changes such that field semantics shift.

When updating, re-verify EVERY citation against the canonical published source. Do not trust prior LLM outputs (Perplexity, ChatGPT, or otherwise) for verbatim statutory text.

## License

Apache License 2.0, same as the Permit Spec.
