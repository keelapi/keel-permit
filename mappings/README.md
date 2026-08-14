# Permit v1 Control Framework Mappings

`control-frameworks.schema-mapping.json` maps Permit v1 wire-format fields and
audit-export-bundle artifacts to selected evidence needs in AI governance,
security, privacy, and compliance frameworks.

The mapping is intended for evidence support only. It is not a compliance
certification, legal opinion, audit opinion, or statement that any customer
control is sufficient. Customers and their assessors remain responsible for
control design, control operation, framework applicability, and audit conclusions.

## Status

- Version: `0.2.0-draft`
- Artifact: `control-frameworks.schema-mapping.json`
- Scope: Permit v1 fields, signed export artifacts, checkpoint artifacts, and
  verifier-facing integrity evidence.

## Framework Coverage

The current draft includes mappings for:

- CCPA §1798.105 and CPPA ADMT regulations
- EU AI Act Article 26(6) and GDPR Article 17(3)(b)
- AICPA SOC 2 Trust Services Criteria
- NIST AI RMF 1.0
- ISO/IEC 42001:2023
- OWASP Top 10 for LLM Applications 2025
- MITRE ATLAS
- OWASP API Security Top 10 2023
- OWASP ASVS v5.0.0
- FedRAMP / NIST SP 800-53 Rev 5 evidence support
- CIS Controls v8.1
- PCI DSS v4.0.1 evidence support for in-scope CDE use cases
- AIUC-1 (Q3-2026 edition) evidence support for selected agent-security controls

FedRAMP and PCI DSS entries are evidence-support mappings only. Keel is not a
FedRAMP-authorized Cloud Service Offering and is not a PCI DSS validated service
provider. Those mappings describe where Permit evidence can support a customer's
own applicable control environment.

The AIUC-1 entry is likewise evidence support only. Keel is not AIUC-1 certified
and does not make an agent AIUC-1 compliant: certification is per-agent, scoped
through an auditor-signed Statement of Applicability, and granted by an
accredited auditor. AIUC-1 revises quarterly, so the entry is pinned to the
Q3-2026 edition and should be reverified each quarter. Verification is partial —
the A008.3, B006.3, D003, and D004 control titles were confirmed verbatim on
2026-08-13, while the E015 series is corroborated from secondary sources only and
is labelled as such on every mapping. Do not quote the E015 identifiers verbatim
or promote them to verified without checking the full evidence catalog.

## Schema Summary

The JSON contains:

- `verification_status` — high-level source verification status for mapped
  framework references.
- `frameworks` — framework metadata, source links, and concise scope notes.
- `mappings` — Permit field to framework-control mappings.
- `audit_export_bundle_mappings` — export/checkpoint artifact to
  framework-control mappings.
- `framework_overlays` — framework-specific grouping of mapped controls.
- `explicit_non_mappings` — controls or framework areas intentionally out of
  Permit scope.

Mapping entries use these evidence types:

- `necessary` — expected evidence input that requires additional customer-owned
  evidence or control operation.
- `direct_support` — evidence directly supports the named evidence need within
  Permit scope; sufficiency remains customer/assessor determined.
- `partial` — evidence contributes to the evidence need but is not sufficient
  alone.

## How To Use

1. Start with the framework and control ID relevant to the customer question.
2. Inspect the mapped Permit field or export artifact.
3. Pair the mapped Permit evidence with customer-owned policies, procedures,
   operational records, and assessor judgment.
4. Treat `explicit_non_mappings` as intentional scope boundaries, not product
   defects.

## License

Apache License 2.0, same as the Permit Spec.
