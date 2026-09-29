/**
 * Apple's SRP-6a variant for idmsa sign-in.
 *
 * This mirrors what icloudlite gets from pysrp with `rfc5054_enable()` and
 * `no_username_in_x()`, SHA-256 and the RFC 5054 2048-bit group. Each detail
 * below changes the result, and the server only says "wrong password":
 *
 * - k and u hash their inputs left-padded to the width of N (RFC 5054).
 * - x omits the username: x = H(salt | H(":" | P)), where P is not the password
 *   but PBKDF2 of its SHA-256 digest (see `derivePassword`).
 * - M1 and M2 hash A and B *unpadded*, and M1 includes H(username) even though
 *   x does not.
 *
 * `test/srp.test.ts` checks every intermediate against vectors produced by the
 * Python implementation that works against Apple today.
 *
 * One known divergence: obsisync runs pysrp's OpenSSL backend, which hashes the
 * salt as a minimal bignum and so drops a leading 0x00 byte. This port hashes
 * the raw salt bytes, as RFC 5054 and pysrp's pure-Python backend do. The salt
 * is fixed per account, so the two only differ for roughly 1 account in 256; if
 * such an account fails to sign in, this is the first thing to check.
 */
import { createHash, pbkdf2Sync, randomBytes } from "node:crypto";
import {
  bigIntToBytes,
  bigIntToFixedBytes,
  bytesToBigInt,
  concatBytes,
  hexToBytes,
  mod,
  modPow,
  utf8,
} from "./bytes.ts";

const N = bytesToBigInt(
  hexToBytes(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
  ),
);
const g = 2n;
const N_BYTES = bigIntToBytes(N);
const WIDTH = N_BYTES.length;

export type SrpProtocol = "s2k" | "s2k_fo";
export const SRP_PROTOCOLS: SrpProtocol[] = ["s2k", "s2k_fo"];

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function padded(n: bigint): Uint8Array {
  return bigIntToFixedBytes(n, WIDTH);
}

const k = bytesToBigInt(sha256(N_BYTES, padded(g)));

/**
 * The value Apple treats as "the password" in SRP.
 *
 * s2k hashes the raw SHA-256 digest; s2k_fo hashes its lowercase hex text.
 */
export function derivePassword(
  password: string,
  salt: Uint8Array,
  iterations: number,
  protocol: SrpProtocol,
): Uint8Array {
  const digest = sha256(utf8(password));
  const input =
    protocol === "s2k_fo" ? utf8(Buffer.from(digest).toString("hex")) : digest;
  return new Uint8Array(pbkdf2Sync(input, salt, iterations, 32, "sha256"));
}

export interface SrpChallenge {
  salt: Uint8Array;
  B: Uint8Array;
  iterations: number;
  protocol: SrpProtocol;
}

export interface SrpProof {
  M1: Uint8Array;
  M2: Uint8Array;
  /** Intermediates, exposed for the parity test only. */
  debug: { u: bigint; x: bigint; S: bigint; K: Uint8Array };
}

export class SrpClient {
  readonly accountName: string;
  private readonly a: bigint;
  readonly A: bigint;
  /** The secret ephemeral, exposed so a proof can be cross-checked before it is sent. */
  readonly ephemeral: Uint8Array;

  /**
   * By default a 32-byte ephemeral with the top bit set — what pysrp's OpenSSL
   * backend (`BN_rand(a, 256, 0, 0)`) draws, and so what Apple sees from
   * obsisync today. Tests may pass a fixed one.
   */
  constructor(accountName: string, ephemeral?: Uint8Array) {
    this.accountName = accountName;
    let aBytes = ephemeral;
    if (!aBytes) {
      aBytes = new Uint8Array(randomBytes(32));
      aBytes[0]! |= 0x80;
    }
    this.ephemeral = aBytes;
    this.a = bytesToBigInt(aBytes);
    this.A = modPow(g, this.a, N);
  }

  /** A, in the unpadded form Apple expects in `signin/init`. */
  get publicKey(): Uint8Array {
    return bigIntToBytes(this.A);
  }

  processChallenge(password: string, challenge: SrpChallenge): SrpProof {
    const B = bytesToBigInt(challenge.B);
    if (mod(B, N) === 0n) throw new Error("SRP safety check failed: B mod N is zero");

    const u = bytesToBigInt(sha256(padded(this.A), padded(B)));
    if (u === 0n) throw new Error("SRP safety check failed: u is zero");

    const p = derivePassword(
      password,
      challenge.salt,
      challenge.iterations,
      challenge.protocol,
    );
    const x = bytesToBigInt(sha256(challenge.salt, sha256(utf8(":"), p)));
    const v = modPow(g, x, N);
    const S = modPow(mod(B - k * v, N), this.a + u * x, N);
    const K = sha256(bigIntToBytes(S));

    const hN = sha256(N_BYTES);
    const hg = sha256(padded(g));
    const hNxorg = hN.map((byte, i) => byte ^ hg[i]!);

    const M1 = sha256(
      hNxorg,
      sha256(utf8(this.accountName)),
      challenge.salt,
      bigIntToBytes(this.A),
      bigIntToBytes(B),
      K,
    );
    const M2 = sha256(concatBytes(bigIntToBytes(this.A), M1, K));
    return { M1, M2, debug: { u, x, S, K } };
  }
}
