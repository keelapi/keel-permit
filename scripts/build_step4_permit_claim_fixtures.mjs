#!/usr/bin/env node
// Build deterministic Step 4 permit-claim baseline fixtures.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS_ROOT = path.join(ROOT, "test-vectors", "verifier_claims", "v0");
const FIXTURE_ROOT = path.join(CORPUS_ROOT, "fixtures");
const TRUST_ROOT = path.join(CORPUS_ROOT, "trust_roots", "step4-permit-claims-trust-root.json");

const PROJECT_ID = "00000000-0000-0000-0000-000000000041";
const CHAIN_SCOPE = `project:${PROJECT_ID}`;
const GENESIS_PREV_HASH = "0".repeat(64);
const SIGNED_AT = "2026-05-21T10:00:00.000000Z";
const REVOCATION_TIME = "2026-05-21T10:05:00.000000Z";
const CHECKPOINT_BOUNDARY = "2026-05-21T10:10:00.000000Z";
const CHECKPOINT_ID = "40000000-0000-4000-8000-000000000001";
const EMPTY_TREE_HASH = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const EXPORT_SEED = Buffer.alloc(32, 0x11);
const CHECKPOINT_SEED = Buffer.alloc(32, 0x22);
const PERMIT_BINDING_SEED = Buffer.alloc(32, 0x33);
const OTHER_PERMIT_BINDING_SEED = Buffer.alloc(32, 0x44);
const MISMATCHED_PROJECT_ID = "00000000-0000-0000-0000-000000000099";

const DECISION_FIXTURES = [
  {
    id: "permit-decision-allow-valid",
    permitId: "10000000-0000-4000-8000-000000000001",
    decision: "allow",
    title: "Valid signed permit allow decision"
  },
  {
    id: "permit-decision-deny-valid",
    permitId: "10000000-0000-4000-8000-000000000002",
    decision: "deny",
    title: "Valid signed permit deny decision"
  },
  {
    id: "permit-decision-challenge-valid",
    permitId: "10000000-0000-4000-8000-000000000003",
    decision: "challenge",
    title: "Valid signed permit challenge decision"
  }
];

const DECISION_NEGATIVE_FIXTURES = [
  {
    id: "permit-decision-neg-bad-signature",
    permitId: "10000000-0000-4000-8000-000000000101",
    decision: "allow",
    mutation: "bad_signature",
    title: "Permit decision with invalid signature",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_DECISION_SIGNATURE_INVALID",
    delta: "The binding signature is produced by an untrusted key while the canonical payload still names the trusted key."
  },
  {
    id: "permit-decision-neg-tampered-decision",
    permitId: "10000000-0000-4000-8000-000000000102",
    decision: "deny",
    mutation: "tampered_decision",
    title: "Permit decision with tampered canonical decision",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_DECISION_CANONICAL_HASH_MISMATCH",
    delta: "The signed canonical payload decision is changed after the canonical hash and signature are produced."
  },
  {
    id: "permit-decision-neg-untrusted-key",
    permitId: "10000000-0000-4000-8000-000000000103",
    decision: "allow",
    mutation: "untrusted_key",
    title: "Permit decision signed by untrusted key",
    expectedVerdict: "insufficient_evidence",
    expectedReason: "PERMIT_DECISION_UNTRUSTED_KEY",
    delta: "The binding is internally valid but names a permit-binding key absent from the public trust root."
  },
  {
    id: "permit-decision-neg-canonical-payload-mismatch",
    permitId: "10000000-0000-4000-8000-000000000104",
    decision: "allow",
    expectedDecision: "deny",
    mutation: "canonical_payload_mismatch",
    title: "Permit decision canonical payload mismatch",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH",
    delta: "The signed canonical payload is valid, but the requested decision evidence expects a different decision."
  }
];

const ABSENCE_PERMIT_ID = "20000000-0000-4000-8000-000000000001";
const ACTOR_ID = "30000000-0000-4000-8000-000000000001";

const REVOKED_NEGATIVE_FIXTURES = [
  {
    id: "permit-revoked-neg-bad-signature",
    mutation: "bad_signature",
    title: "Permit revocation with invalid signature",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_REVOKED_SIGNATURE_INVALID",
    delta: "The revocation event signature is produced by a key outside the public permit-binding trust root."
  },
  {
    id: "permit-revoked-neg-project-mismatch",
    mutation: "project_mismatch",
    title: "Permit revocation project mismatch",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_REVOKED_PROJECT_ID_MISMATCH",
    delta: "The export declares a different project scope than the signed revocation event."
  },
  {
    id: "permit-revoked-neg-effective-at-mismatch",
    mutation: "effective_at_mismatch",
    title: "Permit revocation effective_at mismatch",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_REVOKED_EFFECTIVE_AT_MISMATCH",
    delta: "The signed revocation event uses an effective_at timestamp different from revoked_at, which v1 reserves for future scheduling semantics."
  },
  {
    id: "permit-revoked-neg-missing-field",
    mutation: "missing_field",
    title: "Permit revocation missing required field",
    expectedVerdict: "insufficient_evidence",
    expectedReason: "PERMIT_REVOKED_EVIDENCE_MISSING",
    delta: "The required reason_code field is removed from the signed revocation event evidence."
  },
  {
    id: "permit-revoked-neg-actor-pii-detected",
    mutation: "actor_pii",
    title: "Permit revocation actor identity contains PII",
    expectedVerdict: "disproved",
    expectedReason: "PERMIT_REVOKED_ACTOR_PII_DETECTED",
    delta: "The signed actor_id uses an email-address shape instead of an opaque UUID."
  }
];

const SUPPORTED_PREDICATE_KINDS = [
  "project_id",
  "permit_id",
  "request_id",
  "event_type",
  "category",
  "severity",
  "decision_type",
  "policy_id",
  "provider",
  "sequence_number",
  "created_at",
  "occurred_at",
  "section",
  "export_type"
];

const ABSENCE_PROMOTED_FIXTURES = [
  {
    id: "dispatch-absence-after-revocation-neg-post-revocation-dispatch-present",
    title: "Post-revocation dispatch initiation disproves absence",
    postRevocationDisclosureAt: "2026-05-21T10:06:00.000000Z",
    expectedVerdict: "disproved",
    expectedReason: "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT",
    negative: {
      parent_fixture: "dispatch-absence-after-revocation-valid-empty-scope",
      delta: "Adds a disclosed dispatch.egress_bound record inside the post-revocation occurred_at range."
    }
  },
  {
    id: "dispatch-absence-after-revocation-neg-bridge-record-matches-predicate",
    title: "Bridge record matching dispatch predicate disproves absence",
    postRevocationBridgeAt: "2026-05-21T10:06:00.000000Z",
    expectedScopeVerdict: "disproved",
    expectedVerdict: "disproved",
    expectedReason: "EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE",
    negative: {
      parent_fixture: "dispatch-absence-after-revocation-valid-empty-scope",
      delta: "Places a post-revocation dispatch.egress_bound record in proof_bridge_records even though it satisfies the declared absence predicate."
    }
  },
  {
    id: "dispatch-absence-after-revocation-neg-predicate-out-of-grammar",
    title: "Absence predicate outside permit v1 grammar",
    predicateMutator: (predicate) => {
      predicate.equals.provider = "openai";
    },
    expectedVerdict: "unverifiable_scope",
    expectedReason: "EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR",
    negative: {
      parent_fixture: "dispatch-absence-after-revocation-valid-empty-scope",
      delta: "Adds a scope-predicate v1-valid provider equality that is outside the stricter permit absence predicate grammar."
    }
  },
  {
    id: "dispatch-absence-after-revocation-neg-missing-checkpoint",
    title: "Missing checkpoint prevents absence adjudication",
    writeCheckpoint: false,
    expectedCheckpointVerdict: "insufficient_evidence",
    expectedScopeVerdict: "insufficient_evidence",
    expectedVerdict: "insufficient_evidence",
    expectedReason: "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING",
    negative: {
      parent_fixture: "dispatch-absence-after-revocation-valid-empty-scope",
      delta: "Omits the checkpoint artifact referenced by the scope-faithful absence segment."
    }
  },
  {
    id: "dispatch-absence-after-revocation-neg-missing-sidecar",
    title: "Missing scope-state sidecar prevents absence adjudication",
    writeSidecar: false,
    expectedCheckpointVerdict: "insufficient_evidence",
    expectedScopeVerdict: "insufficient_evidence",
    expectedVerdict: "insufficient_evidence",
    expectedReason: "CHECKPOINT_SCOPE_STATE_MISSING",
    negative: {
      parent_fixture: "dispatch-absence-after-revocation-valid-empty-scope",
      delta: "Omits the checkpoint scope-state sidecar referenced by the scope-faithful absence segment."
    }
  },
  {
    id: "dispatch-absence-after-revocation-edge-pre-revocation-dispatch-supported",
    title: "Pre-revocation dispatch does not disprove post-revocation absence",
    includePreRevocationDispatch: true,
    expectedVerdict: "supported",
    expectedReason: "PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED"
  },
  {
    id: "dispatch-absence-after-revocation-edge-empty-scope-supported",
    title: "Empty post-revocation dispatch scope is supported",
    expectedVerdict: "supported",
    expectedReason: "PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED"
  },
  {
    id: "dispatch-absence-after-revocation-neg-occurred-at-equals-effective-at",
    title: "Dispatch at revocation effective_at disproves absence",
    postRevocationDisclosureAt: REVOCATION_TIME,
    expectedVerdict: "disproved",
    expectedReason: "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT",
    negative: {
      parent_fixture: "dispatch-absence-after-revocation-valid-empty-scope",
      delta: "Adds a disclosed dispatch.egress_bound record whose occurred_at equals the revocation effective_at lower bound."
    }
  }
];

function sortDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortDeep);
  }
  if (value && typeof value === "object" && value.constructor === Object) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortDeep(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortDeep(value));
}

function prettyJson(value) {
  return `${JSON.stringify(sortDeep(value), null, 2)}\n`;
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, prettyJson(value), "utf8");
}

function resetFixtureDir(fixtureId) {
  fs.rmSync(path.join(FIXTURE_ROOT, fixtureId), { recursive: true, force: true });
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, "utf8");
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function sha256Bytes(input) {
  return crypto.createHash("sha256").update(input).digest();
}

function sha256Prefixed(input) {
  return `sha256:${sha256Hex(input)}`;
}

function ed25519PrivateKey(seed) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

function rawPublicKey(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(-32);
}

function publicKeyB64(privateKey) {
  return `ed25519:${rawPublicKey(privateKey).toString("base64")}`;
}

function prefixedKeyId(privateKey) {
  return `sha256:${sha256Hex(rawPublicKey(privateKey)).slice(0, 32)}`;
}

function runtimeKeyId(privateKey) {
  return sha256Hex(rawPublicKey(privateKey)).slice(0, 16);
}

function signB64(privateKey, message) {
  const bytes = Buffer.isBuffer(message) ? message : Buffer.from(String(message), "utf8");
  return crypto.sign(null, bytes, privateKey).toString("base64");
}

function signEd25519(privateKey, message) {
  return `ed25519:${signB64(privateKey, message)}`;
}

function fileRef(relativePath, semanticId) {
  const bytes = fs.readFileSync(path.join(ROOT, relativePath));
  return {
    id: semanticId,
    hash: sha256Prefixed(bytes),
    path: relativePath
  };
}

function registryRef() {
  return fileRef("claim_registry/v0.json", "keel.verifier_claim_registry.v0");
}

function claimSet(claims) {
  return {
    version: "verifier-claims.v0",
    registry: registryRef(),
    claims: claims.map((name) => ({ name, required: true }))
  };
}

function semanticsPins(artifacts) {
  return {
    version: "keel-semantics-pins.v0",
    mode: "pinned",
    artifacts
  };
}

const SEMANTICS = {
  exportManifest: fileRef("semantics/export_manifest/integrity_v1.json", "keel.export_manifest.integrity.v1"),
  governanceChain: fileRef("semantics/governance_chain/record_hash_v1.json", "keel.governance_chain.record_hash.v1"),
  checkpointComposite: fileRef("semantics/checkpoint/composite_hash_v1.json", "keel.checkpoint.composite_hash.v1"),
  checkpointSignature: fileRef("semantics/checkpoint/signature_v1.json", "keel.checkpoint.signature.v1"),
  scopeMerkle: fileRef("semantics/scope_state/merkle_v1.json", "keel.scope_state.merkle.v1"),
  scopeSidecar: fileRef("semantics/scope_state/sidecar_format_v1.json", "keel.scope_state.sidecar_format.v1"),
  exportScopeFaithfulness: fileRef("semantics/export/scope_faithfulness_v1.json", "keel.export.scope_faithfulness.v1"),
  permitDecision: fileRef("semantics/permit/decision_v1.json", "keel.permit.decision.v1"),
  permitRevoked: fileRef("semantics/permit/revoked_event_v1.json", "keel.permit.revoked_event.v1"),
  permitDispatchAbsence: fileRef(
    "semantics/permit/dispatch_absence_after_revocation_v1.json",
    "keel.permit.dispatch_absence_after_revocation.v1"
  )
};

function buildTrustRoot() {
  const exportKey = ed25519PrivateKey(EXPORT_SEED);
  const checkpointKey = ed25519PrivateKey(CHECKPOINT_SEED);
  const permitKey = ed25519PrivateKey(PERMIT_BINDING_SEED);
  writeJson(TRUST_ROOT, {
    schema_version: 1,
    generated_at: SIGNED_AT,
    keys: [
      {
        algorithm: "ed25519",
        key_id: prefixedKeyId(exportKey),
        public_key: publicKeyB64(exportKey),
        purpose: "export_signing",
        status: "active",
        valid_from: "2026-01-01T00:00:00Z",
        valid_to: null
      },
      {
        algorithm: "ed25519",
        key_id: runtimeKeyId(permitKey),
        public_key: publicKeyB64(permitKey),
        purpose: "permit_binding_signing",
        status: "active",
        valid_from: "2026-01-01T00:00:00Z",
        valid_to: null
      },
      {
        algorithm: "ed25519",
        key_id: prefixedKeyId(checkpointKey),
        public_key: publicKeyB64(checkpointKey),
        purpose: "integrity_checkpoint",
        status: "active",
        valid_from: "2026-01-01T00:00:00Z",
        valid_to: null
      },
      {
        algorithm: "ed25519",
        key_id: prefixedKeyId(checkpointKey),
        public_key: publicKeyB64(checkpointKey),
        purpose: "scope_state",
        status: "active",
        valid_from: "2026-01-01T00:00:00Z",
        valid_to: null
      }
    ]
  });
}

function decisionCanonicalPayload(
  spec,
  { bindingKeyId = runtimeKeyId(ed25519PrivateKey(PERMIT_BINDING_SEED)) } = {}
) {
  return {
    binding_version: "v1",
    permit_id: spec.permitId,
    project_id: PROJECT_ID,
    parent_permit_id: null,
    decision: spec.decision,
    reason: `Fixture ${spec.decision} decision.`,
    provider: "openai",
    model: "gpt-4o-mini",
    operation: "responses.create",
    action_name: "chat.completion",
    request_fingerprint: sha256Hex(`${spec.id}:request`),
    constraints: {
      max_output_tokens: 512,
      temperature_max: 1
    },
    routing: {
      requested_provider: "openai",
      requested_model: "gpt-4o-mini",
      selected_provider: "openai",
      selected_model: "gpt-4o-mini",
      fallback_chain: [],
      fallback_occurred: false,
      reason_code: "fixture.primary",
      reason_metadata: {}
    },
    policy_id: "policy:step4-fixture",
    policy_version: "v2026-05-21",
    policy_snapshot_hash: sha256Hex(`${spec.id}:policy`),
    issued_at: SIGNED_AT,
    expires_at: "2026-05-21T11:00:00.000000Z",
    is_dry_run: false,
    binding_key_id: bindingKeyId,
    final_request_hash: null
  };
}

function decisionEvidence(
  spec,
  { privateKey = ed25519PrivateKey(PERMIT_BINDING_SEED) } = {}
) {
  const payload = decisionCanonicalPayload(spec, {
    bindingKeyId: runtimeKeyId(privateKey)
  });
  const hash = sha256Hex(canonicalJson(payload));
  return {
    artifact_type: "permit_decision_binding",
    artifact_version: "permit.decision.v1",
    canonical_payload: payload,
    binding_canonical_hash: hash,
    binding_signature: signEd25519(privateKey, hash),
    binding_key_id: runtimeKeyId(privateKey),
    binding_issued_at: SIGNED_AT,
    expected_decision: spec.decision
  };
}

function revokedEvent({
  permitId = ABSENCE_PERMIT_ID,
  projectId = PROJECT_ID,
  actorId = ACTOR_ID,
  actorKind = "user",
  reasonCode = "operator.requested",
  revokedAt = REVOCATION_TIME,
  effectiveAt = REVOCATION_TIME,
  privateKey = ed25519PrivateKey(PERMIT_BINDING_SEED)
} = {}) {
  const payload = {
    permit_id: permitId,
    project_id: projectId,
    actor_id: actorId,
    actor_kind: actorKind,
    reason_code: reasonCode,
    revoked_at: revokedAt,
    effective_at: effectiveAt
  };
  const hash = sha256Hex(canonicalJson(payload));
  return {
    event: {
      ...payload,
      signature: signB64(privateKey, hash)
    },
    canonical_hash: hash
  };
}

function buildManifest({ fixtureId, exportPayload, claims, artifacts, recordCount }) {
  const exportKey = ed25519PrivateKey(EXPORT_SEED);
  const exportBytes = Buffer.from(prettyJson(exportPayload), "utf8");
  const contentHash = sha256Prefixed(exportBytes);
  return {
    export_id: fixtureId,
    project_id: PROJECT_ID,
    export_type: "audit_export",
    format: "json",
    compressed: false,
    record_count: recordCount,
    content_hash: contentHash,
    key_id: prefixedKeyId(exportKey),
    public_key: publicKeyB64(exportKey),
    signed_at: SIGNED_AT,
    claim_set: claimSet(["export.integrity.v1", ...claims]),
    semantics_pins: semanticsPins([SEMANTICS.exportManifest, ...artifacts]),
    signature: signEd25519(exportKey, contentHash)
  };
}

function writeReadme(fixtureId, title, body) {
  writeText(
    path.join(FIXTURE_ROOT, fixtureId, "README.md"),
    `# ${fixtureId}\n\n${title}.\n\n${body}\n`
  );
}

function writeDecisionFixture(spec) {
  resetFixtureDir(spec.id);
  const fixtureDir = path.join(FIXTURE_ROOT, spec.id);
  const evidence = decisionEvidence(spec);
  const exportPayload = {
    schema: "keel.step4.permit_claim_fixture/v1",
    fixture_id: spec.id,
    project_id: PROJECT_ID,
    permit_decision: evidence
  };
  const manifest = buildManifest({
    fixtureId: spec.id,
    exportPayload,
    claims: ["permit.decision.v1"],
    artifacts: [SEMANTICS.permitDecision],
    recordCount: 1
  });
  writeJson(path.join(fixtureDir, "pack", "export.json"), exportPayload);
  writeJson(path.join(fixtureDir, "pack", "manifest.json"), manifest);
  writeReadme(
    spec.id,
    spec.title,
    `## What It Tests\n\nThe pack contains a signed issuance-time permit decision binding whose canonical payload decision is \`${spec.decision}\`.\n\n## Expected Verdict\n\n\`permit.decision.v1\` is expected to return \`supported\`.`
  );
  return corpusExportRecord({
    id: spec.id,
    title: spec.title,
    claims: ["export.integrity.v1", "permit.decision.v1"],
    features: ["step4_permit_claims"],
    extraPack: {}
  });
}

function writeDecisionNegativeFixture(spec) {
  resetFixtureDir(spec.id);
  const fixtureDir = path.join(FIXTURE_ROOT, spec.id);
  const otherPermitKey = ed25519PrivateKey(OTHER_PERMIT_BINDING_SEED);
  let evidence = decisionEvidence({
    id: spec.id,
    permitId: spec.permitId,
    decision: spec.decision
  });

  if (spec.mutation === "bad_signature") {
    evidence.binding_signature = signEd25519(otherPermitKey, evidence.binding_canonical_hash);
  } else if (spec.mutation === "tampered_decision") {
    evidence.canonical_payload.decision = "allow";
  } else if (spec.mutation === "untrusted_key") {
    evidence = decisionEvidence(
      {
        id: spec.id,
        permitId: spec.permitId,
        decision: spec.decision
      },
      { privateKey: otherPermitKey }
    );
  } else if (spec.mutation === "canonical_payload_mismatch") {
    evidence.expected_decision = spec.expectedDecision;
  } else {
    throw new Error(`unknown decision mutation: ${spec.mutation}`);
  }

  const exportPayload = {
    schema: "keel.step4.permit_claim_fixture/v1",
    fixture_id: spec.id,
    project_id: PROJECT_ID,
    permit_decision: evidence
  };
  const manifest = buildManifest({
    fixtureId: spec.id,
    exportPayload,
    claims: ["permit.decision.v1"],
    artifacts: [SEMANTICS.permitDecision],
    recordCount: 1
  });
  writeJson(path.join(fixtureDir, "pack", "export.json"), exportPayload);
  writeJson(path.join(fixtureDir, "pack", "manifest.json"), manifest);
  writeReadme(
    spec.id,
    spec.title,
    `## What It Tests\n\nThe pack mutates a signed issuance-time permit decision binding: ${spec.delta}\n\n## Expected Verdict\n\n\`permit.decision.v1\` is expected to return \`${spec.expectedVerdict}\` with \`${spec.expectedReason}\`.`
  );
  return corpusExportRecord({
    id: spec.id,
    title: spec.title,
    claims: [
      "export.integrity.v1",
      { name: "permit.decision.v1", expected_verdict: spec.expectedVerdict }
    ],
    features: ["step4_permit_claims"],
    extraPack: {},
    expectedOutcome: "FAIL",
    reasonClasses: [spec.expectedReason],
    negative: {
      parent_fixture: "permit-decision-allow-valid",
      delta: spec.delta
    }
  });
}

function recordHashV1(entry) {
  const timestamp = String(entry.created_at).replace(/Z$/, "");
  const parts = [
    entry.event_id,
    entry.event_type,
    entry.resource_type || "",
    entry.resource_id || "",
    entry.outcome || "",
    entry.severity,
    timestamp,
    entry.prev_hash,
    String(entry.sequence_number)
  ];
  return sha256Hex(parts.join("|"));
}

function chainEntry({ eventId, eventType, sequenceNumber, prevHash, occurredAt, payloadJson }) {
  const entry = {
    event_id: eventId,
    event_type: eventType,
    project_id: PROJECT_ID,
    permit_id: ABSENCE_PERMIT_ID,
    resource_type: "permit",
    resource_id: ABSENCE_PERMIT_ID,
    outcome: "success",
    severity: "info",
    occurred_at: occurredAt,
    created_at: occurredAt,
    payload_json: payloadJson,
    chain_scope: CHAIN_SCOPE,
    sequence_number: sequenceNumber,
    prev_hash: prevHash,
    chain_format_version: "v1"
  };
  entry.record_hash = recordHashV1(entry);
  return entry;
}

function buildAbsenceChain({
  includePreRevocationDispatch,
  postRevocationDisclosureAt = null,
  postRevocationBridgeAt = null
}) {
  const entries = [];
  let prev = GENESIS_PREV_HASH;
  let sequence = 1;
  if (includePreRevocationDispatch) {
    const dispatch = chainEntry({
      eventId: "evt_step4_pre_revocation_dispatch",
      eventType: "dispatch.egress_bound",
      sequenceNumber: sequence,
      prevHash: prev,
      occurredAt: "2026-05-21T10:04:00.000000Z",
      payloadJson: {
        project_id: PROJECT_ID,
        permit_id: ABSENCE_PERMIT_ID,
        event_type: "dispatch.egress_bound",
        occurred_at: "2026-05-21T10:04:00.000000Z",
        dispatch_request_digest_v1: sha256Hex("pre-revocation-dispatch")
      }
    });
    entries.push(dispatch);
    prev = dispatch.record_hash;
    sequence += 1;
  }
  const revocation = revokedEvent();
  const revoked = chainEntry({
    eventId: "evt_step4_permit_revoked",
    eventType: "permit.revoked",
    sequenceNumber: sequence,
    prevHash: prev,
    occurredAt: REVOCATION_TIME,
    payloadJson: {
      project_id: PROJECT_ID,
      permit_id: ABSENCE_PERMIT_ID,
      event_type: "permit.revoked",
      occurred_at: REVOCATION_TIME,
      revoked_at: REVOCATION_TIME,
      effective_at: REVOCATION_TIME,
      reason_code: "operator.requested"
    }
  });
  entries.push(revoked);
  prev = revoked.record_hash;
  sequence += 1;
  if (postRevocationDisclosureAt !== null || postRevocationBridgeAt !== null) {
    const occurredAt = postRevocationDisclosureAt || postRevocationBridgeAt;
    const dispatch = chainEntry({
      eventId: postRevocationDisclosureAt !== null
        ? "evt_step4_post_revocation_dispatch_disclosed"
        : "evt_step4_post_revocation_dispatch_bridge",
      eventType: "dispatch.egress_bound",
      sequenceNumber: sequence,
      prevHash: prev,
      occurredAt,
      payloadJson: {
        project_id: PROJECT_ID,
        permit_id: ABSENCE_PERMIT_ID,
        event_type: "dispatch.egress_bound",
        occurred_at: occurredAt,
        dispatch_request_digest_v1: sha256Hex(`${occurredAt}:post-revocation-dispatch`)
      }
    });
    entries.push(dispatch);
  }
  return { entries, revocation };
}

function compositeHash(chainHeads) {
  const lines = Object.keys(chainHeads)
    .sort()
    .map((scope) => `${scope}:${chainHeads[scope].sequence_number}:${chainHeads[scope].last_record_hash}`);
  return sha256Prefixed(Buffer.from(lines.join("\n"), "utf8"));
}

function buildCheckpoint(entries) {
  const checkpointKey = ed25519PrivateKey(CHECKPOINT_SEED);
  const last = entries.at(-1);
  const chainHeads = {
    [CHAIN_SCOPE]: {
      sequence_number: last.sequence_number,
      last_record_hash: last.record_hash
    }
  };
  const composite = compositeHash(chainHeads);
  return {
    checkpoint_id: CHECKPOINT_ID,
    computed_at: CHECKPOINT_BOUNDARY,
    keel_version: "step4-permit-claims-fixtures",
    chain_heads: chainHeads,
    composite_hash: composite,
    key_id: prefixedKeyId(checkpointKey),
    public_key: publicKeyB64(checkpointKey),
    claim_set: claimSet(["checkpoint.composite_hash.v1", "checkpoint.signature.v1"]),
    semantics_pins: semanticsPins([SEMANTICS.checkpointComposite, SEMANTICS.checkpointSignature]),
    signature: signEd25519(checkpointKey, composite)
  };
}

function chainScopeHash() {
  return sha256Hex(canonicalJson({ chain_scope: CHAIN_SCOPE }));
}

function absencePredicate() {
  return {
    version: "keel.scope_predicate.v1",
    operator: "and",
    equals: {
      project_id: PROJECT_ID,
      permit_id: ABSENCE_PERMIT_ID,
      event_type: "dispatch.egress_bound"
    },
    ranges: {
      occurred_at: {
        gte: REVOCATION_TIME,
        lt: CHECKPOINT_BOUNDARY
      }
    }
  };
}

function merkleRoot(disclosureRecords, predicateValueHash) {
  if (!disclosureRecords.length) {
    return EMPTY_TREE_HASH;
  }
  const leaves = [...disclosureRecords]
    .sort((a, b) => {
      const seq = a.sequence_number - b.sequence_number;
      if (seq !== 0) return seq;
      const eventCmp = String(a.event_id).localeCompare(String(b.event_id));
      if (eventCmp !== 0) return eventCmp;
      return String(a.record_hash).localeCompare(String(b.record_hash));
    })
    .map((record) => {
      const leafObject = {
        canonical_predicate_value_hash: predicateValueHash,
        event_id: record.event_id,
        record_hash: record.record_hash,
        sequence_number: record.sequence_number
      };
      return sha256Bytes(Buffer.concat([Buffer.from([0]), Buffer.from(canonicalJson(leafObject), "utf8")]));
    });

  function merkleHash(nodes) {
    if (nodes.length === 1) {
      return nodes[0];
    }
    const split = 1 << (Math.ceil(Math.log2(nodes.length)) - 1);
    const left = merkleHash(nodes.slice(0, split));
    const right = merkleHash(nodes.slice(split));
    return sha256Bytes(Buffer.concat([Buffer.from([1]), left, right]));
  }

  return `sha256:${merkleHash(leaves).toString("hex")}`;
}

function buildSidecar({ entries, predicate, disclosures }) {
  const checkpointKey = ed25519PrivateKey(CHECKPOINT_SEED);
  const predicateHash = sha256Prefixed(Buffer.from(canonicalJson(predicate), "utf8"));
  const sequences = disclosures.map((record) => record.sequence_number);
  const firstMatching = sequences.length ? Math.min(...sequences) : null;
  const lastMatching = sequences.length ? Math.max(...sequences) : null;
  const sidecar = {
    artifact_type: "checkpoint_scope_state",
    version: "checkpoint_scope_state.v1",
    scope_state_id: `keel.scope_state.v1:${chainScopeHash()}:${CHECKPOINT_ID}`,
    checkpoint_id: CHECKPOINT_ID,
    chain_scope: CHAIN_SCOPE,
    predicate_grammar_version: "keel.scope_predicate.v1",
    predicate_basis: {
      canonicalization_profile: "keel.canonical_json.payload.v1",
      supported_predicate_kinds: SUPPORTED_PREDICATE_KINDS,
      reserved_namespaces: ["keel.scope_predicate.reserved.v1", "non_membership_profile"]
    },
    commitment_profile: "keel.scope_state.merkle.v1",
    scope_commitments: [
      {
        predicate_value: predicate,
        predicate_value_hash: predicateHash,
        first_matching_sequence: firstMatching,
        last_matching_sequence: lastMatching,
        matching_count: disclosures.length,
        membership_root_hash: merkleRoot(disclosures, predicateHash)
      }
    ],
    tree_size: entries.at(-1).sequence_number,
    signed_at: SIGNED_AT,
    signature: {
      algorithm: "Ed25519",
      key_id: prefixedKeyId(checkpointKey),
      signature: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    },
    trust_root_reference: {
      manifest_version: "keel.public_key_manifest.v1",
      purpose: "scope_state",
      key_id: prefixedKeyId(checkpointKey)
    }
  };
  const signedPayload = structuredClone(sidecar);
  delete signedPayload.signature.signature;
  sidecar.signature.signature = signEd25519(checkpointKey, canonicalJson(signedPayload));
  return sidecar;
}

function buildAbsenceFixture({
  id,
  title,
  includePreRevocationDispatch,
  postRevocationDisclosureAt = null,
  postRevocationBridgeAt = null,
  predicateMutator = null,
  writeCheckpoint = true,
  writeSidecar = true,
  expectedCheckpointVerdict = "supported",
  expectedScopeVerdict = "supported",
  expectedVerdict = "supported",
  expectedReason = "PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED",
  negative = null
}) {
  resetFixtureDir(id);
  const { entries, revocation } = buildAbsenceChain({
    includePreRevocationDispatch,
    postRevocationDisclosureAt,
    postRevocationBridgeAt
  });
  const checkpoint = buildCheckpoint(entries);
  const predicate = absencePredicate();
  if (predicateMutator !== null) {
    predicateMutator(predicate);
  }
  const disclosures = entries.filter((entry) =>
    postRevocationDisclosureAt !== null && entry.event_type === "dispatch.egress_bound" && entry.occurred_at === postRevocationDisclosureAt
  );
  const sidecar = buildSidecar({ entries, predicate, disclosures });
  const sidecarBytes = Buffer.from(prettyJson(sidecar), "utf8");
  const sidecarHash = sha256Prefixed(sidecarBytes);
  const filtersHash = sha256Prefixed(Buffer.from(canonicalJson(predicate), "utf8"));
  const proofBridgeRecords = entries.filter((entry) => !disclosures.includes(entry));

  const segment = {
    segment_id: id,
    declared_scope: {
      version: "keel.scope_declaration.v1",
      scope_kind: "declared_sample",
      chain_scope: CHAIN_SCOPE,
      population_label: "Post-revocation dispatch.egress_bound events for one permit",
      predicate,
      presentation_policy: {
        version: "keel.presentation_policy.v1",
        policy_kind: "none",
        policy_parameters: {}
      }
    },
    declared_start: {
      kind: "genesis",
      chain_scope: CHAIN_SCOPE,
      sequence_number: 1,
      genesis_prev_hash: GENESIS_PREV_HASH
    },
    declared_end: {
      checkpoint_id: CHECKPOINT_ID,
      chain_scope: CHAIN_SCOPE,
      sequence_number: entries.at(-1).sequence_number,
      last_record_hash: entries.at(-1).record_hash,
      boundary_policy: "explicit_checkpoint",
      checkpoint_boundary: CHECKPOINT_BOUNDARY
    },
    scope_state_reference: {
      artifact_type: "checkpoint_scope_state",
      scope_state_id: sidecar.scope_state_id,
      checkpoint_id: CHECKPOINT_ID,
      chain_scope: CHAIN_SCOPE,
      artifact_hash: sidecarHash,
      storage_uri: `scope-state/v1/${chainScopeHash()}/${CHECKPOINT_ID}/checkpoint-scope-state-v1.json`
    },
    canonical_filters: {
      canonicalization_profile: "keel.canonical_json.payload.v1",
      raw_filters: predicate,
      filters_hash: filtersHash
    },
    chain_evidence: {
      disclosure_records: disclosures,
      proof_bridge_records: proofBridgeRecords
    }
  };

  const exportPayload = {
    schema: "keel.step4.permit_claim_fixture/v1",
    fixture_id: id,
    project_id: PROJECT_ID,
    permit_id: ABSENCE_PERMIT_ID,
    revocation_event: revocation,
    scope_faithfulness: {
      version: "keel.export_scope_faithfulness.v1",
      segments: [segment]
    }
  };
  const manifest = buildManifest({
    fixtureId: id,
    exportPayload,
    claims: [
      "permit.revoked.v1",
      "checkpoint.scope_state.v1",
      "export.scope_faithfulness.v1",
      "permit.dispatch_absence_after_revocation.v1"
    ],
    artifacts: [
      SEMANTICS.permitRevoked,
      SEMANTICS.checkpointComposite,
      SEMANTICS.checkpointSignature,
      SEMANTICS.governanceChain,
      SEMANTICS.scopeMerkle,
      SEMANTICS.scopeSidecar,
      SEMANTICS.exportScopeFaithfulness,
      SEMANTICS.permitDispatchAbsence
    ],
    recordCount: 0
  });

  const fixtureDir = path.join(FIXTURE_ROOT, id);
  writeJson(path.join(fixtureDir, "pack", "export.json"), exportPayload);
  writeJson(path.join(fixtureDir, "pack", "manifest.json"), manifest);
  if (writeCheckpoint) {
    writeJson(path.join(fixtureDir, "pack", "checkpoint.json"), checkpoint);
  }
  if (writeSidecar) {
    writeJson(path.join(fixtureDir, "sidecars", "checkpoint-scope-state-v1.json"), sidecar);
  }
  writeReadme(
    id,
    title,
    `## What It Tests\n\nThe pack contains supported revocation evidence and a scope-faithful absence adjudication segment for post-revocation \`dispatch.egress_bound\` events.${includePreRevocationDispatch ? " A pre-revocation `dispatch.egress_bound` record is supplied as bridge evidence and does not match the bounded `occurred_at` range." : ""}\n\n## Expected Verdict\n\n\`permit.dispatch_absence_after_revocation.v1\` is expected to return \`${expectedVerdict}\` with \`${expectedReason}\`.`
  );
  return corpusExportRecord({
    id,
    title,
    claims: [
      "export.integrity.v1",
      "permit.revoked.v1",
      {
        name: "checkpoint.scope_state.v1",
        expected_verdict: expectedCheckpointVerdict
      },
      {
        name: "export.scope_faithfulness.v1",
        expected_verdict: expectedScopeVerdict
      },
      {
        name: "permit.dispatch_absence_after_revocation.v1",
        expected_verdict: expectedVerdict
      }
    ],
    features: ["scope_faithfulness", "step4_permit_claims"],
    extraPack: {
      ...(writeCheckpoint ? { checkpoint_file: `fixtures/${id}/pack/checkpoint.json` } : {}),
      ...(writeSidecar ? { sidecar_file: `fixtures/${id}/sidecars/checkpoint-scope-state-v1.json` } : {})
    },
    expectedOutcome: expectedVerdict === "supported" ? "PASS" : "FAIL",
    reasonClasses: expectedVerdict === "supported" ? [] : [expectedReason],
    negative
  });
}

function writeRevokedFixture() {
  const id = "permit-revoked-valid";
  resetFixtureDir(id);
  const title = "Valid signed permit revocation event";
  const exportPayload = {
    schema: "keel.step4.permit_claim_fixture/v1",
    fixture_id: id,
    project_id: PROJECT_ID,
    permit_id: ABSENCE_PERMIT_ID,
    revocation_event: revokedEvent()
  };
  const manifest = buildManifest({
    fixtureId: id,
    exportPayload,
    claims: ["permit.revoked.v1"],
    artifacts: [SEMANTICS.permitRevoked],
    recordCount: 1
  });
  const fixtureDir = path.join(FIXTURE_ROOT, id);
  writeJson(path.join(fixtureDir, "pack", "export.json"), exportPayload);
  writeJson(path.join(fixtureDir, "pack", "manifest.json"), manifest);
  writeReadme(
    id,
    title,
    "## What It Tests\n\nThe pack contains a signed `permit.revoked` event with `permit_id`, `project_id`, opaque actor identity, taxonomy `reason_code`, and `effective_at == revoked_at`.\n\n## Expected Verdict\n\n`permit.revoked.v1` is expected to return `supported`."
  );
  return corpusExportRecord({
    id,
    title,
    claims: ["export.integrity.v1", "permit.revoked.v1"],
    features: ["step4_permit_claims"],
    extraPack: {}
  });
}

function writeRevokedNegativeFixture(spec) {
  resetFixtureDir(spec.id);
  const fixtureDir = path.join(FIXTURE_ROOT, spec.id);
  const otherPermitKey = ed25519PrivateKey(OTHER_PERMIT_BINDING_SEED);
  let revocation = revokedEvent();
  let projectId = PROJECT_ID;
  if (spec.mutation === "bad_signature") {
    revocation = revokedEvent({ privateKey: otherPermitKey });
  } else if (spec.mutation === "project_mismatch") {
    projectId = MISMATCHED_PROJECT_ID;
  } else if (spec.mutation === "effective_at_mismatch") {
    revocation = revokedEvent({ effectiveAt: "2026-05-21T10:06:00.000000Z" });
  } else if (spec.mutation === "missing_field") {
    delete revocation.event.reason_code;
  } else if (spec.mutation === "actor_pii") {
    revocation = revokedEvent({ actorId: "operator@example.com" });
  } else {
    throw new Error(`unknown revocation mutation: ${spec.mutation}`);
  }
  const exportPayload = {
    schema: "keel.step4.permit_claim_fixture/v1",
    fixture_id: spec.id,
    project_id: projectId,
    permit_id: ABSENCE_PERMIT_ID,
    revocation_event: revocation
  };
  const manifest = buildManifest({
    fixtureId: spec.id,
    exportPayload,
    claims: ["permit.revoked.v1"],
    artifacts: [SEMANTICS.permitRevoked],
    recordCount: 1
  });
  writeJson(path.join(fixtureDir, "pack", "export.json"), exportPayload);
  writeJson(path.join(fixtureDir, "pack", "manifest.json"), manifest);
  writeReadme(
    spec.id,
    spec.title,
    `## What It Tests\n\nThe pack mutates signed \`permit.revoked\` evidence: ${spec.delta}\n\n## Expected Verdict\n\n\`permit.revoked.v1\` is expected to return \`${spec.expectedVerdict}\` with \`${spec.expectedReason}\`.`
  );
  return corpusExportRecord({
    id: spec.id,
    title: spec.title,
    claims: [
      "export.integrity.v1",
      { name: "permit.revoked.v1", expected_verdict: spec.expectedVerdict }
    ],
    features: ["step4_permit_claims"],
    extraPack: {},
    expectedOutcome: "FAIL",
    reasonClasses: [spec.expectedReason],
    negative: {
      parent_fixture: "permit-revoked-valid",
      delta: spec.delta
    }
  });
}

function corpusExportRecord({
  id,
  title,
  claims,
  features,
  extraPack,
  expectedOutcome = "PASS",
  reasonClasses = [],
  negative = null
}) {
  const record = {
    claims: claims.map((claim) =>
      typeof claim === "string"
        ? { expected_verdict: "supported", name: claim }
        : claim
    ),
    expected_current: {
      outcome: expectedOutcome,
      reason_classes: reasonClasses
    },
    id,
    kind: "export",
    pack: {
      export_file: `fixtures/${id}/pack/export.json`,
      features,
      key_manifest: "trust_roots/step4-permit-claims-trust-root.json",
      manifest: `fixtures/${id}/pack/manifest.json`,
      ...extraPack
    },
    title
  };
  if (negative !== null) {
    record.negative = negative;
  }
  return {
    ...record
  };
}

function updateCorpus(records) {
  const corpusPath = path.join(CORPUS_ROOT, "corpus.json");
  const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
  const ids = new Set(records.map((record) => record.id));
  corpus.corpus_version = "verifier-claims-v0-golden-2026-05-21-step4";
  corpus.records = corpus.records.filter((record) => !ids.has(record.id)).concat(records);
  writeJson(corpusPath, corpus);
}

function main() {
  buildTrustRoot();
  const records = [
    ...DECISION_FIXTURES.map(writeDecisionFixture),
    ...DECISION_NEGATIVE_FIXTURES.map(writeDecisionNegativeFixture),
    writeRevokedFixture(),
    ...REVOKED_NEGATIVE_FIXTURES.map(writeRevokedNegativeFixture),
    buildAbsenceFixture({
      id: "dispatch-absence-after-revocation-valid-empty-scope",
      title: "Valid post-revocation dispatch absence with empty matching scope",
      includePreRevocationDispatch: false
    }),
    buildAbsenceFixture({
      id: "dispatch-absence-after-revocation-valid-with-pre-revocation-dispatch",
      title: "Valid post-revocation dispatch absence with pre-revocation dispatch evidence",
      includePreRevocationDispatch: true
    }),
    ...ABSENCE_PROMOTED_FIXTURES.map((fixture) =>
      buildAbsenceFixture({
        includePreRevocationDispatch: false,
        writeCheckpoint: true,
        writeSidecar: true,
        ...fixture
      })
    )
  ];
  updateCorpus(records);
  console.log(`Generated ${records.length} Step 4 permit-claim fixtures.`);
}

main();
