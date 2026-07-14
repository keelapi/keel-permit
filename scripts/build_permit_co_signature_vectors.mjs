#!/usr/bin/env node
// Build deterministic WebAuthn permit co-signature golden vectors.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "test-vectors", "permit_co_signature", "v1", "corpus.json");

const P = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const A = P - 3n;
const N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const G = {
  x: BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
  y: BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
};

const RP_ID = "permit.example.test";
const ALLOWED_ORIGIN = "https://permit.example.test";
const PERMIT_ID = "10000000-0000-4000-8000-000000000001";
const CO_SIGNER_ID = "20000000-0000-4000-8000-000000000001";
const SIGNED_AT = "2026-07-13T12:00:00.000000Z";
const ACTION = "payments.transfer";
const RESOURCE = "payment:invoice:123";
const MODALITY = "payment";
const PERMIT_HASH = sha256(Buffer.from("keel-permit co-signature vector permit 1", "utf8")).toString("hex");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function fromBigInt(value, length = 32) {
  const hex = value.toString(16).padStart(length * 2, "0");
  return Buffer.from(hex, "hex");
}

function toBigInt(value) {
  return BigInt(`0x${Buffer.from(value).toString("hex") || "0"}`);
}

function mod(value, modulus) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function invert(value, modulus) {
  let a = mod(value, modulus);
  let b = modulus;
  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;
  while (a !== 0n) {
    const quotient = b / a;
    [x, u] = [u, x - quotient * u];
    [y, v] = [v, y - quotient * v];
    [b, a] = [a, b - quotient * a];
  }
  if (b !== 1n) throw new Error("value is not invertible");
  return mod(x, modulus);
}

function pointAdd(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x && mod(left.y + right.y, P) === 0n) return null;

  const slope = left.x === right.x && left.y === right.y
    ? mod((3n * left.x * left.x + A) * invert(2n * left.y, P), P)
    : mod((right.y - left.y) * invert(right.x - left.x, P), P);
  const x = mod(slope * slope - left.x - right.x, P);
  const y = mod(slope * (left.x - x) - left.y, P);
  return { x, y };
}

function scalarMultiply(scalar, point = G) {
  let n = mod(scalar, N);
  let result = null;
  let addend = point;
  while (n > 0n) {
    if (n & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    n >>= 1n;
  }
  return result;
}

function hmac(key, ...values) {
  const mac = crypto.createHmac("sha256", key);
  for (const value of values) mac.update(value);
  return mac.digest();
}

function deterministicK(privateScalar, digest) {
  const x = fromBigInt(privateScalar);
  const h = fromBigInt(toBigInt(digest) % N);
  let k = Buffer.alloc(32, 0x00);
  let v = Buffer.alloc(32, 0x01);
  k = hmac(k, v, Buffer.from([0x00]), x, h);
  v = hmac(k, v);
  k = hmac(k, v, Buffer.from([0x01]), x, h);
  v = hmac(k, v);
  for (;;) {
    v = hmac(k, v);
    const candidate = toBigInt(v);
    if (candidate > 0n && candidate < N) return candidate;
    k = hmac(k, v, Buffer.from([0x00]));
    v = hmac(k, v);
  }
}

function derInteger(value) {
  let bytes = fromBigInt(value);
  while (bytes.length > 1 && bytes[0] === 0x00 && (bytes[1] & 0x80) === 0) {
    bytes = bytes.subarray(1);
  }
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

function es256Sign(privateScalar, message) {
  const digest = sha256(message);
  const z = toBigInt(digest);
  let nonce = deterministicK(privateScalar, digest);
  for (;;) {
    const point = scalarMultiply(nonce);
    const r = mod(point.x, N);
    let s = mod(invert(nonce, N) * (z + r * privateScalar), N);
    if (r !== 0n && s !== 0n) {
      if (s > N / 2n) s = N - s;
      const rDer = derInteger(r);
      const sDer = derInteger(s);
      const body = Buffer.concat([rDer, sDer]);
      return Buffer.concat([Buffer.from([0x30, body.length]), body]);
    }
    nonce = mod(nonce + 1n, N);
  }
}

function coseEs256(x, y) {
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y
  ]);
}

function coseEd25519(x) {
  return Buffer.concat([
    Buffer.from([0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]),
    x
  ]);
}

function authenticatorData(rpId, flags, signCount = 1) {
  const count = Buffer.alloc(4);
  count.writeUInt32BE(signCount);
  return Buffer.concat([sha256(Buffer.from(rpId, "utf8")), Buffer.from([flags]), count]);
}

function clientData(challengeHash, origin = ALLOWED_ORIGIN) {
  return Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge: b64url(Buffer.from(challengeHash, "hex")),
    origin,
    crossOrigin: false
  }), "utf8");
}

function signedBytes(authData, clientJson) {
  return Buffer.concat([authData, sha256(clientJson)]);
}

const esPrivate = mod(toBigInt(sha256(Buffer.from("keel permit phase0 es256 private test key"))), N - 1n) + 1n;
const esPoint = scalarMultiply(esPrivate);
const esX = fromBigInt(esPoint.x);
const esY = fromBigInt(esPoint.y);
const esPrivateJwk = {
  kty: "EC",
  crv: "P-256",
  x: b64url(esX),
  y: b64url(esY),
  d: b64url(fromBigInt(esPrivate))
};
const esPublicKey = crypto.createPublicKey({ key: { ...esPrivateJwk, d: undefined }, format: "jwk" });
const esCose = coseEs256(esX, esY);

const edSeed = sha256(Buffer.from("keel permit phase0 ed25519 private test key"));
const edPkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  edSeed
]);
const edPrivateKey = crypto.createPrivateKey({ key: edPkcs8, format: "der", type: "pkcs8" });
const edPublicJwk = crypto.createPublicKey(edPrivateKey).export({ format: "jwk" });
const edX = Buffer.from(edPublicJwk.x, "base64url");
const edCose = coseEd25519(edX);

function keyRecord(label, credentialId, cose, alg) {
  return {
    record_type: "permit.co_signer_key.v1",
    key_id: `sha256:${sha256(cose).toString("hex")}`,
    co_signer_id: CO_SIGNER_ID,
    custody_tier: "human_passkey",
    credential_id: b64url(credentialId),
    public_key_cose: b64url(cose),
    cose_alg: alg,
    rp_id: RP_ID,
    aaguid: label === "es256"
      ? "00000000-0000-4000-8000-000000000007"
      : "00000000-0000-4000-8000-000000000008",
    attestation_format: "none",
    attestation_statement: null,
    backup_eligible: false,
    backup_state: false,
    sign_count: 0
  };
}

const esCredentialId = sha256(Buffer.from("keel permit es256 credential id"));
const edCredentialId = sha256(Buffer.from("keel permit eddsa credential id"));
const esKey = keyRecord("es256", esCredentialId, esCose, -7);
const edKey = keyRecord("eddsa", edCredentialId, edCose, -8);

function makeClaim(key, authData, clientJson, sign) {
  const signature = sign(signedBytes(authData, clientJson));
  return {
    payload_type: "permit.co_signature.v1",
    permit_id: PERMIT_ID,
    permit_canonical_hash: PERMIT_HASH,
    action: ACTION,
    resource: RESOURCE,
    modality: MODALITY,
    co_signer_id: CO_SIGNER_ID,
    role: "approver",
    key_id: key.key_id,
    custody_tier: "human_passkey",
    signed_at: SIGNED_AT,
    assertion: {
      credential_id: key.credential_id,
      authenticator_data: b64url(authData),
      client_data_json: b64url(clientJson),
      signature: b64url(signature),
      cose_alg: key.cose_alg
    }
  };
}

const esSign = (message) => es256Sign(esPrivate, message);
const edSign = (message) => crypto.sign(null, message, edPrivateKey);
const validAuthData = authenticatorData(RP_ID, 0x05, 1);
const validClientData = clientData(PERMIT_HASH);
const validEsClaim = makeClaim(esKey, validAuthData, validClientData, esSign);
const validEdClaim = makeClaim(edKey, validAuthData, validClientData, edSign);

if (!crypto.verify("sha256", signedBytes(validAuthData, validClientData), esPublicKey,
  Buffer.from(validEsClaim.assertion.signature, "base64url"))) {
  throw new Error("generated ES256 signature did not verify");
}
if (!crypto.verify(null, signedBytes(validAuthData, validClientData), crypto.createPublicKey(edPrivateKey),
  Buffer.from(validEdClaim.assertion.signature, "base64url"))) {
  throw new Error("generated EdDSA signature did not verify");
}

function context(overrides = {}) {
  return {
    permit_id: PERMIT_ID,
    permit_canonical_hash: PERMIT_HASH,
    action: ACTION,
    resource: RESOURCE,
    modality: MODALITY,
    rp_id: RP_ID,
    allowed_origins: [ALLOWED_ORIGIN],
    require_user_verification: true,
    ...overrides
  };
}

function vector(id, title, claim, registeredKey, expected, negative = undefined, verificationContext = context()) {
  const result = {
    id,
    title,
    claim,
    registered_cose_key: registeredKey,
    verification_context: verificationContext,
    expected
  };
  if (negative) result.negative = negative;
  return result;
}

const wrongChallengeHash = sha256(Buffer.from("not the target permit"));
const wrongChallengeClaim = makeClaim(esKey, validAuthData, clientData(wrongChallengeHash.toString("hex")), esSign);
const wrongOriginClaim = makeClaim(esKey, validAuthData, clientData(PERMIT_HASH, "https://evil.example.test"), esSign);
const wrongRpClaim = makeClaim(esKey, authenticatorData("other.example.test", 0x05, 1), validClientData, esSign);
const uvZeroClaim = makeClaim(esKey, authenticatorData(RP_ID, 0x01, 1), validClientData, esSign);

const tamperedAuthClaim = structuredClone(validEsClaim);
const tamperedAuthBytes = Buffer.from(tamperedAuthClaim.assertion.authenticator_data, "base64url");
tamperedAuthBytes[tamperedAuthBytes.length - 1] ^= 0x01;
tamperedAuthClaim.assertion.authenticator_data = b64url(tamperedAuthBytes);

const tamperedSignatureClaim = structuredClone(validEsClaim);
tamperedSignatureClaim.assertion.signature = b64url(Buffer.from([0x30, 0x00]));

function verifiesAsEs256(claim) {
  const authData = Buffer.from(claim.assertion.authenticator_data, "base64url");
  const clientJson = Buffer.from(claim.assertion.client_data_json, "base64url");
  const signature = Buffer.from(claim.assertion.signature, "base64url");
  return crypto.verify("sha256", signedBytes(authData, clientJson), esPublicKey, signature);
}

for (const [label, claim] of [
  ["wrong challenge", wrongChallengeClaim],
  ["wrong origin", wrongOriginClaim],
  ["wrong RP ID hash", wrongRpClaim],
  ["UV zero", uvZeroClaim]
]) {
  if (!verifiesAsEs256(claim)) throw new Error(`${label} vector has an unintended signature failure`);
}
if (verifiesAsEs256(tamperedAuthClaim)) {
  throw new Error("tampered authenticator-data vector unexpectedly verifies");
}
if (verifiesAsEs256(tamperedSignatureClaim)) {
  throw new Error("tampered signature vector unexpectedly verifies");
}

const replayHash = sha256(Buffer.from("keel-permit co-signature vector permit 2", "utf8")).toString("hex");
const vectors = [
  vector(
    "positive-es256",
    "Valid ES256 WebAuthn co-signature",
    validEsClaim,
    esKey,
    { verdict: "supported", reason: "CO_SIGNATURE_VERIFIED" }
  ),
  vector(
    "positive-eddsa",
    "Valid EdDSA WebAuthn co-signature",
    validEdClaim,
    edKey,
    { verdict: "supported", reason: "CO_SIGNATURE_VERIFIED" }
  ),
  vector(
    "negative-wrong-challenge",
    "Valid assertion for the wrong challenge",
    wrongChallengeClaim,
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_CHALLENGE_MISMATCH" },
    { mutation: "clientDataJSON.challenge is a different 32-byte value; the assertion remains cryptographically valid." }
  ),
  vector(
    "negative-wrong-origin",
    "Valid assertion from an origin outside the allowlist",
    wrongOriginClaim,
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_ORIGIN_NOT_ALLOWED" },
    { mutation: "clientDataJSON.origin is changed and the assertion is signed over the changed bytes." }
  ),
  vector(
    "negative-wrong-rp-id-hash",
    "Valid assertion carrying the wrong RP ID hash",
    wrongRpClaim,
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_RP_ID_HASH_MISMATCH" },
    { mutation: "authenticatorData.rpIdHash is computed for another RP ID and the assertion is validly signed." }
  ),
  vector(
    "negative-uv-zero",
    "UV is clear when user verification is required",
    uvZeroClaim,
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_USER_VERIFICATION_REQUIRED" },
    { mutation: "The authenticator flags have UP=1 and UV=0; the assertion is validly signed." }
  ),
  vector(
    "negative-tampered-authenticator-data",
    "Authenticator data changed after signing",
    tamperedAuthClaim,
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_INVALID_SIGNATURE" },
    { mutation: "The low byte of signCount is changed after signing, preserving a structurally valid authenticatorData value." }
  ),
  vector(
    "negative-tampered-signature",
    "Assertion signature has a malformed DER encoding",
    tamperedSignatureClaim,
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_SIGNATURE_MALFORMED" },
    { mutation: "The valid ES256 signature is replaced with an empty ASN.1 sequence." }
  ),
  vector(
    "negative-replay-different-permit",
    "Valid assertion replayed while adjudicating a different Permit",
    structuredClone(validEsClaim),
    esKey,
    { verdict: "disproved", reason: "CO_SIGNATURE_PERMIT_BINDING_MISMATCH" },
    { mutation: "The original claim and assertion are unchanged, but the independently verified target-Permit context is different." },
    context({
      permit_id: "10000000-0000-4000-8000-000000000002",
      permit_canonical_hash: replayHash,
      resource: "payment:invoice:999"
    })
  )
];

const corpus = {
  suite: "permit.co_signature.v1",
  version: "1.0.0",
  generated_at: "2026-07-13T12:00:00Z",
  description: "Deterministic, test-only WebAuthn assertion vectors. No private key material appears in this artifact.",
  vectors
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(corpus, null, 2)}\n`);
console.log(`wrote ${vectors.length} vectors to ${path.relative(ROOT, OUT)}`);
