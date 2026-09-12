// Private lossless reader for the existing Evidence Braid canonical JSON wire.
// Numeric lexemes and byte offsets survive admission; this is not I-JSON/JCS.
import { TextDecoder } from "node:util";
import { verifyFloatToken } from "./receipt-numbers.mjs";

const TYPED_ARRAY = Object.getPrototypeOf(Uint8Array.prototype);
const GET_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "byteLength").get;
const GET_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "byteOffset").get;
const GET_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "buffer").get;
const GET_KIND = Object.getOwnPropertyDescriptor(TYPED_ARRAY, Symbol.toStringTag).get;
const COPY = Uint8Array.prototype.set;
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const MAX_BYTES = 20 * 1024 * 1024;

export class ReceiptWireError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReceiptWireError";
  }
}

export function requireWire(condition, message) {
  if (!condition) throw new ReceiptWireError(message);
}

function copyBytes(raw, maximum) {
  try {
    requireWire(GET_KIND.call(raw) === "Uint8Array", "wire must be a native byte view");
    const length = GET_LENGTH.call(raw);
    requireWire(length > 0 && length <= maximum, "wire exceeds byte budget or is empty");
    const source = new Uint8Array(GET_BUFFER.call(raw), GET_OFFSET.call(raw), length);
    const result = Buffer.allocUnsafe(length);
    COPY.call(result, source);
    return result;
  } catch (error) {
    if (error instanceof ReceiptWireError) throw error;
    throw new ReceiptWireError("invalid or detached native byte view");
  }
}

// Python's sorted(str) compares Unicode scalars, not UTF-16 code units.
function precedes(left, right) {
  let a = 0;
  let b = 0;
  while (a < left.length && b < right.length) {
    const x = left.codePointAt(a);
    const y = right.codePointAt(b);
    if (x !== y) return x < y;
    a += x > 0xffff ? 2 : 1;
    b += y > 0xffff ? 2 : 1;
  }
  return a === left.length && b !== right.length;
}

function xmlText(value) {
  for (const character of value) {
    const point = character.codePointAt(0);
    requireWire(point === 9 || point === 10 || point === 13 ||
      (point >= 0x20 && point <= 0xd7ff) ||
      (point >= 0xe000 && point <= 0xfffd) ||
      (point >= 0x10000 && point <= 0x10ffff), "string is not XML 1.0 scalar text");
  }
  return value;
}

/** Owns a native snapshot. Nodes retain exact UTF-8 [start,end) byte spans.
 * Integers are BigInt; floats retain their canonical lexemes. The height field
 * lets the event verifier enforce its additional full-event nesting bound.
 */
export function readCanonicalWire(raw, maximumBytes = MAX_BYTES) {
  requireWire(Number.isSafeInteger(maximumBytes) && maximumBytes > 0 && maximumBytes <= MAX_BYTES,
    "invalid byte budget");
  const bytes = copyBytes(raw, maximumBytes);
  let offset = 0;
  let nodes = 0;

  function count(depth) {
    requireWire(depth <= 72, "wire exceeds nesting budget");
    requireWire(++nodes <= 1_000_000, "wire exceeds node budget");
  }

  function string() {
    const start = offset++;
    while (offset < bytes.length) {
      const byte = bytes[offset++];
      if (byte === 34) {
        let value;
        try { value = DECODER.decode(bytes.subarray(start + 1, offset - 1)); }
        catch { throw new ReceiptWireError("string is not strict UTF-8"); }
        // No \u escape is canonical for XML-admitted text with ensure_ascii=False.
        value = value.replace(/\\(["\\tnr])/g, (_, escaped) =>
          ({ t: "\t", n: "\n", r: "\r", '"': '"', "\\": "\\" })[escaped]);
        return { kind: "string", value: xmlText(value), start, end: offset, height: 0 };
      }
      requireWire(byte >= 32, "unescaped control byte in string");
      if (byte === 92) {
        const escaped = bytes[offset++];
        requireWire(escaped === 34 || escaped === 92 || escaped === 116 ||
          escaped === 110 || escaped === 114, "noncanonical string escape");
      }
    }
    throw new ReceiptWireError("unterminated string");
  }

  function value(depth) {
    count(depth);
    const start = offset;
    const first = bytes[offset];
    if (first === 34) return string();
    if (first === 123 || first === 91) {
      requireWire(depth < 72, "wire exceeds container nesting budget");
      const object = first === 123;
      const result = object ? new Map() : [];
      const close = object ? 125 : 93;
      let previous;
      let height = 0;
      offset++;
      if (bytes[offset] !== close) {
        for (;;) {
          let key;
          if (object) {
            count(depth + 1); // The envelope budget includes map keys.
            requireWire(bytes[offset] === 34, "object key must be a string");
            key = string().value;
            requireWire(previous === undefined || precedes(previous, key),
              "object keys are duplicated or not in scalar order");
            previous = key;
            requireWire(bytes[offset++] === 58, "missing object colon");
          }
          const child = value(depth + 1);
          height = Math.max(height, child.height + 1);
          if (object) result.set(key, child);
          else result.push(child);
          if (bytes[offset] === close) break;
          requireWire(bytes[offset++] === 44, "missing container separator");
        }
      }
      offset++;
      return { kind: object ? "object" : "array", value: result, start, end: offset, height };
    }
    for (const [literal, primitive] of [["true", true], ["false", false], ["null", null]]) {
      if (first === literal.charCodeAt(0)) {
        requireWire(bytes.subarray(offset, offset + literal.length).equals(Buffer.from(literal, "ascii")),
          "invalid JSON literal");
        offset += literal.length;
        return { kind: primitive === null ? "null" : "boolean", value: primitive,
          start, end: offset, height: 0 };
      }
    }
    requireWire(first === 45 || (first >= 48 && first <= 57), "invalid canonical JSON value");
    while (offset < bytes.length && bytes[offset] !== 44 && bytes[offset] !== 93 && bytes[offset] !== 125) {
      requireWire(offset - start < 641 && bytes[offset] < 128, "number exceeds lexical budget");
      offset++;
    }
    const token = bytes.subarray(start, offset).toString("ascii");
    if (/^-?(?:0|[1-9][0-9]*)$/.test(token)) {
      requireWire(token !== "-0" && token.length - (token[0] === "-" ? 1 : 0) <= 640,
        "noncanonical or oversized integer");
      return { kind: "integer", value: BigInt(token), token, start, end: offset, height: 0 };
    }
    try { verifyFloatToken(token); }
    catch { throw new ReceiptWireError("noncanonical or invalid finite float"); }
    return { kind: "float", value: Number(token), token, start, end: offset, height: 0 };
  }

  const root = value(0);
  requireWire(offset === bytes.length, "trailing wire bytes");
  return { bytes, root };
}
