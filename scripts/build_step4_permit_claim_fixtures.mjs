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

const ABSENCE_PERMIT_ID = "20000000-0000-4000-8000-000000000001";
const ACTOR_ID = "30000000-0000-4000-8000-000000000001";

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

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, "utf8");
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
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

function decisionCanonicalPayload(spec) {
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
    binding_key_id: runtimeKeyId(ed25519PrivateKey(PERMIT_BINDING_SEED)),
    final_request_hash: null
  };
}

function decisionEvidence(spec) {
  const permitKey = ed25519PrivateKey(PERMIT_BINDING_SEED);
  const payload = decisionCanonicalPayload(spec);
  const hash = sha256Hex(canonicalJson(payload));
  return {
    artifact_type: "permit_decision_binding",
    artifact_version: "permit.decision.v1",
    canonical_payload: payload,
    binding_canonical_hash: hash,
    binding_signature: signEd25519(permitKey, hash),
    binding_key_id: runtimeKeyId(permitKey),
    binding_issued_at: SIGNED_AT,
    expected_decision: spec.decision
  };
}

function revokedEvent({ permitId = ABSENCE_PERMIT_ID, projectId = PROJECT_ID } = {}) {
  const permitKey = ed25519PrivateKey(PERMIT_BINDING_SEED);
  const payload = {
    permit_id: permitId,
    project_id: projectId,
    actor_id: ACTOR_ID,
    actor_kind: "user",
    reason_code: "operator.requested",
    revoked_at: REVOCATION_TIME,
    effective_at: REVOCATION_TIME
  };
  const hash = sha256Hex(canonicalJson(payload));
  return {
    event: {
      ...payload,
      signature: signB64(permitKey, hash)
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

function buildAbsenceChain({ includePreRevocationDispatch }) {
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

function buildSidecar({ entries, predicate }) {
  const checkpointKey = ed25519PrivateKey(CHECKPOINT_SEED);
  const predicateHash = sha256Prefixed(Buffer.from(canonicalJson(predicate), "utf8"));
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
        first_matching_sequence: null,
        last_matching_sequence: null,
        matching_count: 0,
        membership_root_hash: EMPTY_TREE_HASH
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

function buildAbsenceFixture({ id, title, includePreRevocationDispatch }) {
  const { entries, revocation } = buildAbsenceChain({ includePreRevocationDispatch });
  const checkpoint = buildCheckpoint(entries);
  const predicate = absencePredicate();
  const sidecar = buildSidecar({ entries, predicate });
  const sidecarBytes = Buffer.from(prettyJson(sidecar), "utf8");
  const sidecarHash = sha256Prefixed(sidecarBytes);
  const filtersHash = sha256Prefixed(Buffer.from(canonicalJson(predicate), "utf8"));

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
      disclosure_records: [],
      proof_bridge_records: entries
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
  writeJson(path.join(fixtureDir, "pack", "checkpoint.json"), checkpoint);
  writeJson(path.join(fixtureDir, "sidecars", "checkpoint-scope-state-v1.json"), sidecar);
  writeReadme(
    id,
    title,
    `## What It Tests\n\nThe pack contains supported revocation evidence and a scope-faithful absence adjudication segment whose post-revocation \`dispatch.egress_bound\` matching count is zero.${includePreRevocationDispatch ? " A pre-revocation `dispatch.egress_bound` record is supplied as bridge evidence and does not match the bounded `occurred_at` range." : ""}\n\n## Expected Verdict\n\n\`permit.dispatch_absence_after_revocation.v1\` is expected to return \`supported\`.`
  );
  return corpusExportRecord({
    id,
    title,
    claims: [
      "export.integrity.v1",
      "permit.revoked.v1",
      "checkpoint.scope_state.v1",
      "export.scope_faithfulness.v1",
      "permit.dispatch_absence_after_revocation.v1"
    ],
    features: ["scope_faithfulness", "step4_permit_claims"],
    extraPack: {
      checkpoint_file: `fixtures/${id}/pack/checkpoint.json`,
      sidecar_file: `fixtures/${id}/sidecars/checkpoint-scope-state-v1.json`
    }
  });
}

function writeRevokedFixture() {
  const id = "permit-revoked-valid";
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

function corpusExportRecord({ id, title, claims, features, extraPack }) {
  return {
    claims: claims.map((name) => ({ expected_verdict: "supported", name })),
    expected_current: {
      outcome: "PASS",
      reason_classes: []
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
    writeRevokedFixture(),
    buildAbsenceFixture({
      id: "dispatch-absence-after-revocation-valid-empty-scope",
      title: "Valid post-revocation dispatch absence with empty matching scope",
      includePreRevocationDispatch: false
    }),
    buildAbsenceFixture({
      id: "dispatch-absence-after-revocation-valid-with-pre-revocation-dispatch",
      title: "Valid post-revocation dispatch absence with pre-revocation dispatch evidence",
      includePreRevocationDispatch: true
    })
  ];
  updateCorpus(records);
  console.log(`Generated ${records.length} Step 4 permit-claim fixtures.`);
}

main();
