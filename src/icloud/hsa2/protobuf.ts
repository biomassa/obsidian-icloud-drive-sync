/**
 * The small slice of protobuf wire format Apple's push websocket speaks.
 *
 * Only varints (wire type 0) and length-delimited fields (wire type 2) appear;
 * anything else is treated as a malformed frame rather than skipped, because
 * this is a private protocol and a surprise means we no longer understand it.
 */
import { concatBytes, utf8 } from "../bytes.ts";

export class ProtocolError extends Error {}

export function encodeVarint(value: number | bigint): Uint8Array {
  let v = BigInt(value);
  if (v < 0n) throw new RangeError("negative varints are not supported");
  const out: number[] = [];
  for (;;) {
    const byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v) out.push(byte | 0x80);
    else {
      out.push(byte);
      return new Uint8Array(out);
    }
  }
}

export function readVarint(data: Uint8Array, offset: number): [bigint, number] {
  let value = 0n;
  let shift = 0n;
  const start = offset;
  for (;;) {
    if (offset >= data.length) throw new ProtocolError("truncated protobuf varint");
    const byte = data[offset++]!;
    value |= BigInt(byte & 0x7f) << shift;
    if (!(byte & 0x80)) return [value, offset];
    shift += 7n;
    if (shift > 63n || offset - start >= 10) throw new ProtocolError("malformed protobuf varint");
  }
}

export function bytesField(field: number, value: Uint8Array): Uint8Array {
  return concatBytes(encodeVarint((field << 3) | 2), encodeVarint(value.length), value);
}

export function stringField(field: number, value: string): Uint8Array {
  return bytesField(field, utf8(value));
}

export function uintField(field: number, value: number | bigint): Uint8Array {
  return concatBytes(encodeVarint(field << 3), encodeVarint(value));
}

export type FieldValue = bigint | Uint8Array;

export function decodeFields(data: Uint8Array): Map<number, FieldValue[]> {
  const fields = new Map<number, FieldValue[]>();
  let offset = 0;
  while (offset < data.length) {
    const [key, afterKey] = readVarint(data, offset);
    offset = afterKey;
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    let value: FieldValue;
    if (wire === 0) {
      [value, offset] = readVarint(data, offset);
    } else if (wire === 2) {
      const [length, afterLength] = readVarint(data, offset);
      const end = afterLength + Number(length);
      if (end > data.length) throw new ProtocolError("truncated protobuf field");
      value = data.slice(afterLength, end);
      offset = end;
    } else {
      throw new ProtocolError(`unsupported protobuf wire type: ${wire}`);
    }
    const list = fields.get(field);
    if (list) list.push(value);
    else fields.set(field, [value]);
  }
  return fields;
}

export function firstBytes(fields: Map<number, FieldValue[]>, field: number): Uint8Array | undefined {
  const v = fields.get(field)?.[0];
  if (v === undefined) return undefined;
  if (!(v instanceof Uint8Array)) throw new ProtocolError(`field ${field} is not bytes`);
  return v;
}

export function firstInt(fields: Map<number, FieldValue[]>, field: number): number | undefined {
  const v = fields.get(field)?.[0];
  if (v === undefined) return undefined;
  if (typeof v !== "bigint") throw new ProtocolError(`field ${field} is not an integer`);
  return Number(v);
}

// ── Apple push-websocket messages ────────────────────────────────────────────

const SIGNATURE_PREFIX = new Uint8Array([0x01, 0x03]);
const CONNECTION_EXPIRATION_SECONDS = 86400;

/** The bootstrap message; its hex form becomes the websocket URL path. */
export function encodeConnectionMessage(
  publicKey: Uint8Array,
  nonce: Uint8Array,
  derSignature: Uint8Array,
): Uint8Array {
  const signature =
    derSignature[0] === 0x01 && derSignature[1] === 0x03
      ? derSignature
      : concatBytes(SIGNATURE_PREFIX, derSignature);
  const inner = concatBytes(
    bytesField(1, publicKey),
    bytesField(2, nonce),
    bytesField(3, signature),
    bytesField(5, uintField(1, CONNECTION_EXPIRATION_SECONDS)),
  );
  return bytesField(1, inner);
}

export function encodeWebFilterMessage(topics: string[]): Uint8Array {
  return bytesField(3, concatBytes(...topics.map((t) => stringField(1, t))));
}

export function encodeAckMessage(topic: Uint8Array, messageId: number): Uint8Array {
  return bytesField(2, concatBytes(bytesField(1, topic), uintField(2, messageId)));
}

export interface ServerMessage {
  connection?: { pushTokenB64: string; status: number; serverTimestampSeconds?: number };
  push?: { topic: Uint8Array; messageId: number; payload: Uint8Array };
  subscription?: { messageId: number; status: number; retryIntervalSeconds: number; topics: string[] };
  ack?: { topic: Uint8Array; messageId: number; deliveryStatus: number };
  fieldNumbers: number[];
}

export function decodeServerMessage(message: Uint8Array): ServerMessage {
  const fields = decodeFields(message);
  const out: ServerMessage = { fieldNumbers: [...fields.keys()].sort((a, b) => a - b) };

  const conn = firstBytes(fields, 1);
  if (conn) {
    const f = decodeFields(conn);
    out.connection = {
      pushTokenB64: Buffer.from(firstBytes(f, 1) ?? new Uint8Array()).toString("ascii"),
      status: firstInt(f, 2) ?? 0,
      serverTimestampSeconds: firstInt(f, 3),
    };
  }

  const push = firstBytes(fields, 2);
  if (push) {
    const f = decodeFields(push);
    out.push = {
      topic: firstBytes(f, 1) ?? new Uint8Array(),
      messageId: firstInt(f, 2) ?? 0,
      payload: firstBytes(f, 4) ?? new Uint8Array(),
    };
  }

  const sub = firstBytes(fields, 3);
  if (sub) {
    const f = decodeFields(sub);
    const topics: string[] = [];
    const payload = firstBytes(f, 1);
    if (payload) {
      for (const appResponse of decodeFields(payload).get(1) ?? []) {
        if (!(appResponse instanceof Uint8Array)) continue;
        const topic = firstBytes(decodeFields(appResponse), 1);
        if (topic?.length) topics.push(Buffer.from(topic).toString("utf8"));
      }
    }
    out.subscription = {
      messageId: firstInt(f, 2) ?? 0,
      status: firstInt(f, 3) ?? 0,
      retryIntervalSeconds: firstInt(f, 4) ?? 0,
      topics,
    };
  }

  const ack = firstBytes(fields, 7);
  if (ack) {
    const f = decodeFields(ack);
    out.ack = {
      topic: firstBytes(f, 1) ?? new Uint8Array(),
      messageId: firstInt(f, 2) ?? 0,
      deliveryStatus: firstInt(f, 3) ?? 0,
    };
  }
  return out;
}
