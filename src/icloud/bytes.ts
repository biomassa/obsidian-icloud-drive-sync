/** Byte and big-integer helpers shared by the SRP and SPAKE2 code. */

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/**
 * Minimal big-endian encoding, exactly as pysrp's `long_to_bytes`: no leading
 * zero bytes, and zero encodes as an empty array. Apple's SRP messages are
 * computed over this form, so padding here would change every hash.
 */
export function bigIntToBytes(n: bigint): Uint8Array {
  if (n < 0n) throw new RangeError("negative integers are not encodable");
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return hexToBytes(hex);
}

/** Fixed-width big-endian encoding, left-padded with zeros. */
export function bigIntToFixedBytes(n: bigint, length: number): Uint8Array {
  const raw = bigIntToBytes(n);
  if (raw.length > length) throw new RangeError("integer too large for width");
  const out = new Uint8Array(length);
  out.set(raw, length - raw.length);
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("malformed hex");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function b64encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/** Strict standard-alphabet base64 decode; rejects anything Buffer would silently skip. */
export function b64decode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) {
    throw new Error("malformed base64");
  }
  return Uint8Array.from(Buffer.from(text, "base64"));
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Non-negative remainder; JavaScript's % keeps the sign of the dividend. */
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

export function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new RangeError("not invertible");
  return mod(oldS, m);
}
