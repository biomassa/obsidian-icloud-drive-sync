/**
 * A minimal WebSocket client for Apple's push courier.
 *
 * Hand-rolled over TLS for the same reason as http.ts: inside Obsidian the
 * global WebSocket is Chromium's, which sends Obsidian's own Origin and cannot
 * be given the one Apple expects. Only what the bridge needs is implemented:
 * binary messages, fragmentation, ping/pong and close.
 */
import { connect, type TLSSocket } from "node:tls";
import { createHash, randomBytes } from "node:crypto";

import { TrustedDevicePromptError } from "../errors.ts";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OP_CONT = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

export interface BridgeSocket {
  sendBinary(payload: Uint8Array): void;
  /** One complete message. Rejects on timeout, close or a protocol error. */
  readMessage(timeoutMs: number): Promise<Uint8Array>;
  close(): void;
}

export interface WebSocketOptions {
  origin: string;
  userAgent: string;
  timeoutMs: number;
  family?: 0 | 4;
}

export type WebSocketFactory = (url: string, options: WebSocketOptions) => Promise<BridgeSocket>;

export const openWebSocket: WebSocketFactory = async (url, options) => {
  const parsed = new URL(url);
  if (parsed.protocol !== "wss:" || !parsed.hostname) {
    throw new TrustedDevicePromptError(`unsupported websocket URL: ${url}`);
  }
  const socket = await new Promise<TLSSocket>((resolve, reject) => {
    const s = connect({
      host: parsed.hostname,
      port: Number(parsed.port) || 443,
      servername: parsed.hostname,
      ...(options.family ? { family: options.family } : {}),
    });
    const timer = setTimeout(() => {
      s.destroy();
      reject(new TrustedDevicePromptError("timed out connecting to Apple's push service"));
    }, options.timeoutMs);
    s.once("secureConnect", () => {
      clearTimeout(timer);
      resolve(s);
    });
    s.once("error", (e) => {
      clearTimeout(timer);
      reject(new TrustedDevicePromptError(`push service connection failed: ${e.message}`));
    });
  });
  const ws = new RawWebSocket(socket);
  await ws.handshake(parsed, options);
  return ws;
};

class RawWebSocket implements BridgeSocket {
  private buffer = Buffer.alloc(0);
  private waiter: (() => void) | null = null;
  private failure: Error | null = null;
  private readonly socket: TLSSocket;

  constructor(socket: TLSSocket) {
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.wake();
    });
    socket.on("close", () => this.fail(new TrustedDevicePromptError("push service connection closed")));
    socket.on("error", (e) => this.fail(new TrustedDevicePromptError(`push service error: ${e.message}`)));
  }

  private wake(): void {
    const w = this.waiter;
    this.waiter = null;
    w?.();
  }

  private fail(error: Error): void {
    this.failure ??= error;
    this.wake();
  }

  /** Wait until `predicate` is satisfied by the buffer, or the deadline passes. */
  private async waitUntil(predicate: () => boolean, deadline: number): Promise<void> {
    while (!predicate()) {
      if (this.failure) throw this.failure;
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new TrustedDevicePromptError("timed out waiting for Apple's push service");
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, remaining);
        this.waiter = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  }

  private async readExact(n: number, deadline: number): Promise<Buffer> {
    await this.waitUntil(() => this.buffer.length >= n, deadline);
    const out = this.buffer.subarray(0, n);
    this.buffer = this.buffer.subarray(n);
    return Buffer.from(out);
  }

  async handshake(url: URL, options: WebSocketOptions): Promise<void> {
    const key = randomBytes(16).toString("base64");
    const resource = url.pathname + url.search;
    this.socket.write(
      [
        `GET ${resource || "/"} HTTP/1.1`,
        `Host: ${url.hostname}`,
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Origin: ${options.origin}`,
        `User-Agent: ${options.userAgent}`,
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Key: ${key}`,
        "",
        "",
      ].join("\r\n"),
    );
    const deadline = Date.now() + options.timeoutMs;
    await this.waitUntil(() => this.buffer.includes("\r\n\r\n"), deadline);
    const end = this.buffer.indexOf("\r\n\r\n") + 4;
    const head = this.buffer.subarray(0, end).toString("latin1");
    this.buffer = this.buffer.subarray(end);

    const [statusLine = "", ...lines] = head.split("\r\n");
    if (!/ 101 /.test(statusLine)) {
      this.close();
      throw new TrustedDevicePromptError(`websocket upgrade failed: ${statusLine}`);
    }
    const headers = new Map<string, string>();
    for (const line of lines) {
      const i = line.indexOf(":");
      if (i > 0) headers.set(line.slice(0, i).trim().toLowerCase(), line.slice(i + 1).trim());
    }
    const expected = createHash("sha1").update(key + GUID).digest("base64");
    if (headers.get("sec-websocket-accept") !== expected) {
      this.close();
      throw new TrustedDevicePromptError("invalid websocket accept header from Apple's push service");
    }
  }

  private sendFrame(opcode: number, payload: Uint8Array): void {
    const mask = randomBytes(4);
    const len = payload.length;
    let header: Buffer;
    if (len < 126) {
      header = Buffer.from([0x80 | opcode, 0x80 | len]);
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i]! ^ mask[i % 4]!;
    this.socket.write(Buffer.concat([header, mask, masked]));
  }

  sendBinary(payload: Uint8Array): void {
    this.sendFrame(OP_BINARY, payload);
  }

  async readMessage(timeoutMs: number): Promise<Uint8Array> {
    const deadline = Date.now() + timeoutMs;
    const fragments: Buffer[] = [];
    let opcode: number | null = null;
    for (;;) {
      const [b0, b1] = await this.readExact(2, deadline);
      const frameOp = b0! & 0x0f;
      const fin = Boolean(b0! & 0x80);
      const masked = Boolean(b1! & 0x80);
      let length = b1! & 0x7f;
      if (length === 126) length = (await this.readExact(2, deadline)).readUInt16BE(0);
      else if (length === 127) length = Number((await this.readExact(8, deadline)).readBigUInt64BE(0));
      const mask = masked ? await this.readExact(4, deadline) : null;
      const payload = await this.readExact(length, deadline);
      if (mask) for (let i = 0; i < payload.length; i++) payload[i]! ^= mask[i % 4]!;

      if (frameOp === OP_CLOSE) {
        throw new TrustedDevicePromptError("Apple's push service closed the connection");
      }
      if (frameOp === OP_PING) {
        this.sendFrame(OP_PONG, payload);
        continue;
      }
      if (frameOp === OP_PONG) continue;
      if (frameOp !== OP_CONT) opcode = frameOp;
      fragments.push(payload);
      if (fin) {
        if (opcode !== OP_TEXT && opcode !== OP_BINARY) {
          throw new TrustedDevicePromptError(`unsupported websocket opcode: ${opcode}`);
        }
        return new Uint8Array(Buffer.concat(fragments));
      }
    }
  }

  close(): void {
    if (this.socket.destroyed) return;
    try {
      this.sendFrame(OP_CLOSE, new Uint8Array(0));
    } catch {
      // closing anyway
    }
    this.socket.end();
    setTimeout(() => this.socket.destroy(), 1000).unref?.();
  }
}
