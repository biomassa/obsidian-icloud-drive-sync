/**
 * Client-side prover for Apple's trusted-device ("bridge") 2FA flow.
 *
 * Port of icloudlite's hsa2_bridge_prover.py, which mirrors the prover worker in
 * Apple's browser client: SPAKE2 over P-256 keyed by scrypt(code, salt), then
 * HMAC confirmations, then AES-GCM decryption of the code Apple finally returns.
 * Affine arithmetic on BigInt — slow by crypto standards, but it runs a handful
 * of scalar multiplications once per sign-in.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
} from "node:crypto";
import {
  b64decode,
  bigIntToBytes,
  bigIntToFixedBytes,
  bytesToBigInt,
  bytesToHex,
  concatBytes,
  hexToBytes,
  mod,
  modInverse,
  modPow,
  utf8,
} from "../bytes.ts";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = mod(P - 3n, P);
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
export const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

const SPAKE2_M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const SPAKE2_N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
const CLIENT_IDENTITY = utf8("com.apple.security.webprover");
const SERVER_IDENTITY = utf8("com.apple.security.webverifier");
const SPAKE2_CONTEXT = utf8("SPAKE2Web");
const KEY_LENGTH = 32;

/** `null` is the point at infinity. */
export type Point = { x: bigint; y: bigint } | null;

export const GENERATOR: Point = { x: GX, y: GY };

export function encodePoint(point: Point): Uint8Array {
  if (!point) throw new Error("cannot encode the point at infinity");
  return concatBytes(
    new Uint8Array([4]),
    bigIntToFixedBytes(point.x, 32),
    bigIntToFixedBytes(point.y, 32),
  );
}

export function decodePoint(hex: string): Point {
  const raw = hexToBytes(hex);
  let point: Point;
  if (raw.length === 65 && raw[0] === 4) {
    point = { x: bytesToBigInt(raw.slice(1, 33)), y: bytesToBigInt(raw.slice(33)) };
  } else if (raw.length === 33 && (raw[0] === 2 || raw[0] === 3)) {
    const x = bytesToBigInt(raw.slice(1));
    const rhs = mod(modPow(x, 3n, P) + A * x + B, P);
    let y = modPow(rhs, (P + 1n) / 4n, P);
    if ((y & 1n) !== BigInt(raw[0]! & 1)) y = mod(-y, P);
    point = { x, y };
  } else {
    throw new Error("unsupported P-256 point encoding");
  }
  if (!isOnCurve(point)) throw new Error("invalid P-256 point");
  return point;
}

function isOnCurve(point: Point): boolean {
  if (!point) return false;
  return mod(point.y * point.y - (modPow(point.x, 3n, P) + A * point.x + B), P) === 0n;
}

function negate(point: Point): Point {
  return point && { x: point.x, y: mod(-point.y, P) };
}

export function addPoints(left: Point, right: Point): Point {
  if (!left) return right;
  if (!right) return left;
  if (left.x === right.x && mod(left.y + right.y, P) === 0n) return null;
  let slope: bigint;
  if (left.x === right.x && left.y === right.y) {
    if (left.y === 0n) return null;
    slope = mod((3n * left.x * left.x + A) * modInverse(2n * left.y, P), P);
  } else {
    slope = mod((right.y - left.y) * modInverse(right.x - left.x, P), P);
  }
  const x = mod(slope * slope - left.x - right.x, P);
  const y = mod(slope * (left.x - x) - left.y, P);
  return { x, y };
}

export function multiplyPoint(point: Point, scalar: bigint): Point {
  let k = mod(scalar, ORDER);
  let result: Point = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
    k >>= 1n;
  }
  return result;
}

function concatLengthPrefixed(...parts: Uint8Array[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const part of parts) {
    const len = new Uint8Array(8);
    new DataView(len.buffer).setBigUint64(0, BigInt(part.length), true);
    chunks.push(len, part);
  }
  return concatBytes(...chunks);
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(data).digest());
}

/** HKDF-SHA256 with the bridge worker's quirk: "ConfirmationKeys" always yields 64 bytes. */
function deriveKey(ikm: Uint8Array, info: Uint8Array, length = 64): Uint8Array {
  const infoText = Buffer.from(info).toString("latin1");
  const outLength = infoText.includes("ConfirmationKeys") ? 64 : length;
  const prk = hmacSha256(new Uint8Array(32), ikm);
  const blocks: Uint8Array[] = [];
  let previous: Uint8Array = new Uint8Array(0);
  let total = 0;
  for (let counter = 1; total < outLength; counter++) {
    previous = hmacSha256(prk, concatBytes(previous, info, new Uint8Array([counter])));
    blocks.push(previous);
    total += previous.length;
  }
  return concatBytes(...blocks).slice(0, outLength);
}

export function computeW0W1(code: string, saltB64: string): [bigint, bigint] {
  const derived = new Uint8Array(
    scryptSync(utf8(code), b64decode(saltB64), 64, { N: 16384, r: 8, p: 1 }),
  );
  return [bytesToBigInt(derived.slice(0, 32)), bytesToBigInt(derived.slice(32))];
}

export function deriveProverAndVerifierKeys(rawKeyHex: string): [string, string] {
  const raw = hexToBytes(rawKeyHex);
  return [
    bytesToHex(deriveKey(raw, utf8("webVerifier"), KEY_LENGTH)),
    bytesToHex(deriveKey(raw, utf8("webProver"), KEY_LENGTH)),
  ];
}

function randomNonzeroScalar(): bigint {
  for (;;) {
    // 16 extra bytes make the modulo bias negligible.
    const scalar = mod(bytesToBigInt(new Uint8Array(randomBytes(48))), ORDER);
    if (scalar !== 0n) return scalar;
  }
}

/** Keys and confirmations derived from one SPAKE2 transcript. */
class SharedSecret {
  readonly confirmClient: Uint8Array;
  readonly confirmServer: Uint8Array;
  readonly sharedKey: Uint8Array;
  readonly shareP: string;

  constructor(transcript: Uint8Array, shareP: string) {
    this.shareP = shareP;
    const digest = new Uint8Array(createHash("sha256").update(transcript).digest());
    const confirmations = deriveKey(digest, utf8("ConfirmationKeys"), 64);
    this.confirmClient = confirmations.slice(0, 32);
    this.confirmServer = confirmations.slice(32);
    this.sharedKey = deriveKey(digest, utf8("SharedKey"), KEY_LENGTH);
  }
}

function transcriptFor(
  clientPoint: Point,
  serverPoint: Point,
  z: Point,
  v: Point,
  w0: bigint,
): Uint8Array {
  return concatLengthPrefixed(
    SPAKE2_CONTEXT,
    CLIENT_IDENTITY,
    SERVER_IDENTITY,
    encodePoint(decodePoint(SPAKE2_M)),
    encodePoint(decodePoint(SPAKE2_N)),
    encodePoint(clientPoint),
    encodePoint(serverPoint),
    encodePoint(z),
    encodePoint(v),
    bigIntToBytes(w0),
  );
}

export class TrustedDeviceProver {
  private x = 0n;
  private w0 = 0n;
  private w1 = 0n;
  private message1: Point = null;
  private shareP = "";
  private secret: SharedSecret | null = null;
  private verifierKey: string | null = null;

  /** `xScalar` is for tests; production draws a fresh random scalar. */
  initWithSalt(saltB64: string, code: string, xScalar?: bigint): void {
    [this.w0, this.w1] = computeW0W1(code, saltB64);
    this.x = xScalar ?? randomNonzeroScalar();
    this.message1 = null;
    this.secret = null;
    this.verifierKey = null;
  }

  /** Hex of the prover's first SPAKE2 message: x·G + w0·M. */
  getMessage1(): string {
    if (!this.w0) throw new Error("initWithSalt must be called first");
    this.message1 = addPoints(
      multiplyPoint(GENERATOR, this.x),
      multiplyPoint(decodePoint(SPAKE2_M), this.w0),
    );
    this.shareP = bytesToHex(encodePoint(this.message1));
    return this.shareP;
  }

  /** Consume the verifier's first message; return the prover confirmation (hex). */
  processMessage1(serverMessageHex: string): string {
    if (!this.message1) throw new Error("getMessage1 must be called first");
    const serverPoint = decodePoint(serverMessageHex);
    const adjusted = addPoints(
      serverPoint,
      negate(multiplyPoint(decodePoint(SPAKE2_N), this.w0)),
    );
    const z = multiplyPoint(adjusted, this.x);
    const v = multiplyPoint(adjusted, this.w1);
    this.secret = new SharedSecret(
      transcriptFor(this.message1, serverPoint, z, v, this.w0),
      this.shareP,
    );
    return bytesToHex(hmacSha256(this.secret.confirmClient, hexToBytes(serverMessageHex)));
  }

  /** Check the verifier's confirmation; throws when it does not match. */
  processMessage2(messageHex: string): string {
    if (!this.secret) throw new Error("processMessage1 must be called first");
    const expected = bytesToHex(
      hmacSha256(this.secret.confirmServer, hexToBytes(this.secret.shareP)),
    );
    if (expected !== messageHex.toLowerCase()) {
      throw new Error("invalid confirmation from server");
    }
    const rawKey = bytesToHex(this.secret.sharedKey);
    [this.verifierKey] = deriveProverAndVerifierKeys(rawKey);
    return rawKey;
  }

  /** Decrypt Apple's final `encryptedCode`: version(1) | iv(12) | tag(16) | ciphertext. */
  decryptMessage(ciphertextB64: string): string {
    if (!this.verifierKey) throw new Error("bridge verifier key is not available");
    return decryptBridgeCode(this.verifierKey, ciphertextB64);
  }
}

export function decryptBridgeCode(verifierKeyHex: string, ciphertextB64: string): string {
  const payload = b64decode(ciphertextB64);
  if (payload[0] !== 0 || payload.length < 1 + 12 + 16) {
    throw new Error("malformed bridge payload");
  }
  const iv = payload.slice(1, 13);
  const tag = payload.slice(13, 29);
  const ciphertext = payload.slice(29);
  const decipher = createDecipheriv("aes-256-gcm", hexToBytes(verifierKeyHex), iv);
  decipher.setAAD(new Uint8Array([0]));
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString("utf8");
}

/** Test helper: the verifier side, as Apple's server runs it. */
export function encryptBridgeCode(verifierKeyHex: string, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", hexToBytes(verifierKeyHex), iv);
  cipher.setAAD(new Uint8Array([0]));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([Buffer.from([0]), iv, cipher.getAuthTag(), ct]).toString("base64");
}

/**
 * The verifier side of the exchange, as Apple's server runs it. Used only by
 * tests, to drive the prover and the bridge flow end to end without Apple —
 * the same role `_TrustedDeviceBridgeServerProver` plays in icloudlite.
 */
export class TestVerifier {
  private readonly w0: bigint;
  private readonly y: bigint;
  private readonly L: Point;
  private readonly message1: Point;
  private secret: SharedSecret | null = null;
  private clientShare = "";
  private verifierKey: string | null = null;

  constructor(code: string, saltB64: string) {
    const [w0, w1] = computeW0W1(code, saltB64);
    this.w0 = w0;
    this.L = multiplyPoint(GENERATOR, w1);
    this.y = randomNonzeroScalar();
    this.message1 = addPoints(multiplyPoint(GENERATOR, this.y), multiplyPoint(decodePoint(SPAKE2_N), w0));
  }

  getMessage1(): string {
    return bytesToHex(encodePoint(this.message1));
  }

  /** Consume the prover's message; return the verifier's confirmation (hex). */
  processMessage1(clientMessageHex: string): string {
    const clientPoint = decodePoint(clientMessageHex);
    const adjusted = addPoints(clientPoint, negate(multiplyPoint(decodePoint(SPAKE2_M), this.w0)));
    const z = multiplyPoint(adjusted, this.y);
    const v = multiplyPoint(this.L, this.y);
    this.clientShare = clientMessageHex;
    this.secret = new SharedSecret(transcriptFor(clientPoint, this.message1, z, v, this.w0), clientMessageHex);
    return bytesToHex(hmacSha256(this.secret.confirmServer, hexToBytes(clientMessageHex)));
  }

  /** Check the prover's confirmation; returns false when it does not match. */
  verifyClient(confirmationHex: string): boolean {
    if (!this.secret) throw new Error("processMessage1 must be called first");
    const expected = bytesToHex(hmacSha256(this.secret.confirmClient, hexToBytes(this.getMessage1())));
    if (expected !== confirmationHex.toLowerCase()) return false;
    [this.verifierKey] = deriveProverAndVerifierKeys(bytesToHex(this.secret.sharedKey));
    return true;
  }

  encryptCode(plaintext: string): string {
    if (!this.verifierKey) throw new Error("verifyClient must succeed first");
    return encryptBridgeCode(this.verifierKey, plaintext);
  }
}
