#!/usr/bin/env node
// Minimal executable verifier for the permit.co_signature.v1 golden corpus.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(HERE, "corpus.json");
const B64URL = /^[A-Za-z0-9_-]+$/;

function result(verdict, reason) {
  return { verdict, reason };
}

function decodeBase64url(value) {
  if (typeof value !== "string" || !B64URL.test(value) || value.includes("=")) {
    throw new Error("non-canonical base64url");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length === 0 || bytes.toString("base64url") !== value) {
    throw new Error("non-canonical base64url");
  }
  return bytes;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function equal(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function readCborUnsigned(bytes, cursor, additional) {
  if (additional < 24) return [additional, cursor];
  if (additional === 24) {
    if (cursor >= bytes.length) throw new Error("truncated CBOR");
    return [bytes[cursor], cursor + 1];
  }
  if (additional === 25) {
    if (cursor + 2 > bytes.length) throw new Error("truncated CBOR");
    return [bytes.readUInt16BE(cursor), cursor + 2];
  }
  throw new Error("unsupported CBOR length");
}

function readCbor(bytes, cursor = 0) {
  if (cursor >= bytes.length) throw new Error("truncated CBOR");
  const initial = bytes[cursor++];
  const major = initial >> 5;
  const additional = initial & 0x1f;
  const [argument, afterArgument] = readCborUnsigned(bytes, cursor, additional);
  cursor = afterArgument;

  if (major === 0) return [argument, cursor];
  if (major === 1) return [-1 - argument, cursor];
  if (major === 2) {
    if (cursor + argument > bytes.length) throw new Error("truncated CBOR bytes");
    return [bytes.subarray(cursor, cursor + argument), cursor + argument];
  }
  if (major === 5) {
    const map = new Map();
    for (let index = 0; index < argument; index += 1) {
      const [key, afterKey] = readCbor(bytes, cursor);
      const [value, afterValue] = readCbor(bytes, afterKey);
      if (map.has(key)) throw new Error("duplicate COSE key label");
      map.set(key, value);
      cursor = afterValue;
    }
    return [map, cursor];
  }
  throw new Error("unsupported CBOR type");
}

function decodeCosePublicKey(encoded, expectedAlgorithm) {
  const bytes = decodeBase64url(encoded);
  const [cose, cursor] = readCbor(bytes);
  if (!(cose instanceof Map) || cursor !== bytes.length || cose.get(3) !== expectedAlgorithm) {
    throw new Error("COSE algorithm mismatch");
  }

  if (expectedAlgorithm === -7) {
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (cose.get(1) !== 2 || cose.get(-1) !== 1 || !Buffer.isBuffer(x) || x.length !== 32 ||
        !Buffer.isBuffer(y) || y.length !== 32) {
      throw new Error("ES256 requires EC2 P-256 COSE key");
    }
    return crypto.createPublicKey({
      key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") },
      format: "jwk"
    });
  }

  if (expectedAlgorithm === -8) {
    const x = cose.get(-2);
    if (cose.get(1) !== 1 || cose.get(-1) !== 6 || !Buffer.isBuffer(x) || x.length !== 32) {
      throw new Error("EdDSA requires OKP Ed25519 COSE key");
    }
    return crypto.createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: x.toString("base64url") },
      format: "jwk"
    });
  }

  throw new Error("unsupported algorithm");
}

function readDerLength(bytes, cursor) {
  if (cursor >= bytes.length) throw new Error("truncated DER length");
  const first = bytes[cursor++];
  if (first < 0x80) return [first, cursor];
  const count = first & 0x7f;
  if (count === 0 || count > 2 || cursor + count > bytes.length || bytes[cursor] === 0x00) {
    throw new Error("non-minimal DER length");
  }
  let length = 0;
  for (let index = 0; index < count; index += 1) length = (length << 8) | bytes[cursor++];
  if (length < 0x80) throw new Error("non-minimal DER length");
  return [length, cursor];
}

function readDerInteger(bytes, cursor) {
  if (bytes[cursor++] !== 0x02) throw new Error("DER integer expected");
  const [length, bodyStart] = readDerLength(bytes, cursor);
  const bodyEnd = bodyStart + length;
  if (length === 0 || bodyEnd > bytes.length) throw new Error("invalid DER integer length");
  if ((bytes[bodyStart] & 0x80) !== 0) throw new Error("negative DER integer");
  if (length > 1 && bytes[bodyStart] === 0x00 && (bytes[bodyStart + 1] & 0x80) === 0) {
    throw new Error("non-minimal DER integer");
  }
  return bodyEnd;
}

function validEs256Der(signature) {
  try {
    if (signature[0] !== 0x30) return false;
    const [sequenceLength, bodyStart] = readDerLength(signature, 1);
    if (bodyStart + sequenceLength !== signature.length) return false;
    const afterR = readDerInteger(signature, bodyStart);
    const afterS = readDerInteger(signature, afterR);
    return afterS === signature.length;
  } catch {
    return false;
  }
}

function parseClientData(encoded) {
  const bytes = decodeBase64url(encoded);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const parsed = JSON.parse(text);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object" ||
      typeof parsed.type !== "string" || typeof parsed.challenge !== "string" ||
      typeof parsed.origin !== "string") {
    throw new Error("clientDataJSON object fields are invalid");
  }
  return { bytes, parsed };
}

export function referenceVerify(vector) {
  const claim = vector?.claim;
  const assertion = claim?.assertion;
  const key = vector?.registered_cose_key;
  const context = vector?.verification_context;
  if (!claim || !assertion || !key || !context) {
    return result("insufficient_evidence", "CO_SIGNATURE_EVIDENCE_MISSING");
  }

  for (const field of ["permit_id", "permit_canonical_hash", "action", "resource", "modality"]) {
    if (claim[field] !== context[field]) {
      return result("disproved", "CO_SIGNATURE_PERMIT_BINDING_MISMATCH");
    }
  }
  if (claim.payload_type !== "permit.co_signature.v1" || claim.key_id !== key.key_id ||
      claim.co_signer_id !== key.co_signer_id || claim.custody_tier !== "human_passkey") {
    return result("disproved", "CO_SIGNATURE_PERMIT_BINDING_MISMATCH");
  }
  if (assertion.credential_id !== key.credential_id) {
    return result("disproved", "CO_SIGNATURE_CREDENTIAL_MISMATCH");
  }
  if (assertion.cose_alg !== key.cose_alg) {
    return result("disproved", "CO_SIGNATURE_ALGORITHM_MISMATCH");
  }

  let clientData;
  try {
    clientData = parseClientData(assertion.client_data_json);
  } catch {
    return result("disproved", "CO_SIGNATURE_CLIENT_DATA_INVALID");
  }
  if (clientData.parsed.type !== "webauthn.get") {
    return result("disproved", "CO_SIGNATURE_TYPE_INVALID");
  }

  let challenge;
  try {
    challenge = decodeBase64url(clientData.parsed.challenge);
  } catch {
    return result("disproved", "CO_SIGNATURE_CHALLENGE_MISMATCH");
  }
  const expectedChallenge = Buffer.from(claim.permit_canonical_hash, "hex");
  if (expectedChallenge.length !== 32 || !equal(challenge, expectedChallenge)) {
    return result("disproved", "CO_SIGNATURE_CHALLENGE_MISMATCH");
  }
  if (!Array.isArray(context.allowed_origins) ||
      !context.allowed_origins.includes(clientData.parsed.origin)) {
    return result("disproved", "CO_SIGNATURE_ORIGIN_NOT_ALLOWED");
  }

  let authData;
  try {
    authData = decodeBase64url(assertion.authenticator_data);
  } catch {
    return result("disproved", "CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID");
  }
  if (authData.length < 37) {
    return result("disproved", "CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID");
  }
  const flags = authData[32];
  const backupEligible = (flags & 0x08) !== 0;
  const backupState = (flags & 0x10) !== 0;
  if (backupState && !backupEligible) {
    return result("disproved", "CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID");
  }

  if (key.rp_id !== context.rp_id) {
    return result("disproved", "CO_SIGNATURE_RP_ID_HASH_MISMATCH");
  }
  const expectedRpIdHash = sha256(Buffer.from(context.rp_id, "utf8"));
  if (!equal(authData.subarray(0, 32), expectedRpIdHash)) {
    return result("disproved", "CO_SIGNATURE_RP_ID_HASH_MISMATCH");
  }
  if ((flags & 0x01) === 0) {
    return result("disproved", "CO_SIGNATURE_USER_PRESENCE_REQUIRED");
  }
  if (context.require_user_verification !== false && (flags & 0x04) === 0) {
    return result("disproved", "CO_SIGNATURE_USER_VERIFICATION_REQUIRED");
  }

  let publicKey;
  try {
    publicKey = decodeCosePublicKey(key.public_key_cose, assertion.cose_alg);
  } catch {
    return result("disproved", "CO_SIGNATURE_ALGORITHM_MISMATCH");
  }

  let signature;
  try {
    signature = decodeBase64url(assertion.signature);
  } catch {
    return result("disproved", "CO_SIGNATURE_SIGNATURE_MALFORMED");
  }
  if ((assertion.cose_alg === -7 && !validEs256Der(signature)) ||
      (assertion.cose_alg === -8 && signature.length !== 64)) {
    return result("disproved", "CO_SIGNATURE_SIGNATURE_MALFORMED");
  }

  const signedData = Buffer.concat([authData, sha256(clientData.bytes)]);
  const verified = assertion.cose_alg === -7
    ? crypto.verify("sha256", signedData, publicKey, signature)
    : crypto.verify(null, signedData, publicKey, signature);
  return verified
    ? result("supported", "CO_SIGNATURE_VERIFIED")
    : result("disproved", "CO_SIGNATURE_INVALID_SIGNATURE");
}

export function verifyCorpus(corpusPath = CORPUS) {
  const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
  const failures = [];
  for (const vector of corpus.vectors) {
    const actual = referenceVerify(vector);
    if (actual.verdict !== vector.expected.verdict || actual.reason !== vector.expected.reason) {
      failures.push({ id: vector.id, expected: vector.expected, actual });
    }
  }
  return { count: corpus.vectors.length, failures };
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  const report = verifyCorpus(process.argv[2] ? path.resolve(process.argv[2]) : CORPUS);
  if (report.failures.length > 0) {
    console.error(JSON.stringify(report, null, 2));
    process.exitCode = 1;
  } else {
    console.log(`permit.co_signature.v1: ${report.count} vectors matched expected verdicts and reasons`);
  }
}
