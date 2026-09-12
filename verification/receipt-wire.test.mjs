import assert from "node:assert/strict";
import test from "node:test";
import { readCanonicalWire, ReceiptWireError } from "./receipt-wire.mjs";

const read = (text) => readCanonicalWire(Buffer.from(text));
const reject = (text) => assert.throws(() => read(text), ReceiptWireError);

test("lossless integer/float types, scalar key ordering and original byte spans", () => {
  const text = '{"a":9007199254740993,"b":1.0,"c":true,"z":[-0.0,null],"\ue000":"é","𐀀":"é"}';
  const { bytes, root } = read(text);
  assert.equal(root.value.get("a").value, 9007199254740993n);
  assert.equal(root.value.get("b").kind, "float");
  assert.equal(root.value.get("c").kind, "boolean");
  assert.equal(root.value.get("z").value[0].token, "-0.0");
  for (const [key, expected] of [["\ue000", '"é"'], ["𐀀", '"é"']]) {
    const node = root.value.get(key);
    assert.equal(bytes.subarray(node.start, node.end).toString("utf8"), expected);
  }
  assert.equal(root.height, 2);
  reject('{"𐀀":1,"\ue000":2}');
});

test("complete admitted string alphabet and canonical escapes", () => {
  const strings = ["", "\t\n\r", '"\\/', "é", "é", "\u0085\u00a0\u2028\u2029\ufeff", "\ue000𐀀\u{10ffff}"];
  for (const value of strings) assert.equal(read(JSON.stringify(value)).root.value, value);
  for (const text of ['"\\u0061"', '"\\/"', '"\\u0009"', '"\\b"', '"\\f"',
    '"\\x20"', '"\\ud800"', '"\\ud800\\udc00"', '"\ufffe"', '"\uffff"', '"\u0000"', '"\u001f"',
    '"unterminated', '"\\', '\ufeff{}']) reject(text);
});

test("strict UTF-8 and canonical syntax with no duplicate keys", () => {
  for (const bytes of [[34, 0xc0, 0xaf, 34], [34, 0xed, 0xa0, 0x80, 34],
    [34, 0xf4, 0x90, 0x80, 0x80, 34], [34, 0xc3, 34], [0xef, 0xbb, 0xbf, 123, 125],
    [0x74, 0xf2, 0x75, 0x65], [0x6e, 0xf5, 0x6c, 0x6c]]) {
    assert.throws(() => readCanonicalWire(Uint8Array.from(bytes)), ReceiptWireError);
  }
  for (const text of ["", " ", "{}\n", " {}", "[1,]", "{\"a\":1,}", "{\"a\" 1}",
    "{\"b\":1,\"a\":2}", "{\"a\":1,\"a\":2}", "[1 2]", "[", "{", "truefalse", "nul", "False",
    "[true false]", "{1:2}", "[null,", "[]x"]) reject(text);
  assert.equal(read('{"__proto__":1,"constructor":2}').root.value.get("__proto__").value, 1n);
  for (const text of ["{}", "[]", "true", "false", "null", "[{},[],true,false,null]"]) read(text);
});

test("integer budget and canonical binary64 text without Number coercion", () => {
  for (const sign of ["", "-"]) {
    const token = sign + "9".repeat(640);
    assert.equal(read(token).root.value, BigInt(token));
    reject(sign + "9".repeat(641));
  }
  for (const token of ["0", "1", "-1", "0.0", "-0.0", "0.1", "0.0001", "1e-05", "1e+16",
    "5e-324", "2.2250738585072014e-308", "1.7976931348623157e+308"]) read(token);
  for (const token of ["-0", "01", "+1", ".1", "1.", "1e0", "1e+00", "1E+16", "1e-5", "0.10",
    "NaN", "Infinity", "-Infinity", "1e309", "1e-325", "1 2", "1é", "1e" + "9".repeat(640)]) reject(token);
});

test("nesting and byte bounds apply before broad allocation", () => {
  read("[".repeat(72) + "0" + "]".repeat(72));
  reject("[".repeat(73) + "0" + "]".repeat(73));
  reject("[".repeat(73) + "]".repeat(73));
  assert.equal(readCanonicalWire(Buffer.from("0"), 1).root.value, 0n);
  assert.throws(() => readCanonicalWire(Buffer.from("00"), 1), ReceiptWireError);
  for (const maximum of [0, -1, 1.1, Infinity, 20 * 1024 * 1024 + 1]) {
    assert.throws(() => readCanonicalWire(Buffer.from("0"), maximum), ReceiptWireError);
  }
});

test("native snapshot bypasses instance hooks and rejects non-byte or detached views", () => {
  const backing = Buffer.from("xx{\"a\":1}yy");
  const view = new Uint8Array(backing.buffer, backing.byteOffset + 2, 7);
  for (const key of ["byteLength", "byteOffset", "buffer", Symbol.iterator, Symbol.toStringTag]) {
    Object.defineProperty(view, key, { get() { throw new Error("hook must not run"); } });
  }
  const result = readCanonicalWire(view);
  backing.fill(0);
  assert.equal(result.bytes.toString(), '{"a":1}');
  for (const input of [null, undefined, "0", [48], new Uint16Array([48]), new DataView(new ArrayBuffer(1)),
    new Proxy(new Uint8Array([48]), {})]) {
    assert.throws(() => readCanonicalWire(input), ReceiptWireError);
  }
  const detached = new Uint8Array([48]);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  assert.throws(() => readCanonicalWire(detached), ReceiptWireError);
});

test("million-node boundary counts object keys as well as values", () => {
  // Root object + key + array + 999997 primitive elements = exactly 1000000.
  const prefix = '{"a":[' + '0,'.repeat(999996) + '0';
  assert.equal(read(prefix + ']}').root.value.get("a").value.length, 999997);
  reject(prefix + ',0]}');
  // A map key is not itself a nested container, but is still one graph node.
  const nested = '{"a":'.repeat(64) + '0' + '}'.repeat(64);
  assert.equal(read(nested).root.height, 64);
});

test("exact 20 MiB envelope is admitted; a further byte is rejected before parsing", () => {
  const limit = 20 * 1024 * 1024;
  const raw = Buffer.alloc(limit, 0x61);
  raw[0] = 34;
  raw[limit - 1] = 34;
  assert.equal(readCanonicalWire(raw).root.value.length, limit - 2);
  assert.throws(() => readCanonicalWire(Buffer.alloc(limit + 1, 0x20)), ReceiptWireError);
});
