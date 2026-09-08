import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { ConsistencyVerificationError, verifyLedgerConsistency } from "./ledger-consistency.mjs";

// Synthetic trees test the proof protocol, not the receipt model/chain. Actual
// Python receipt ledgers are exercised separately by test_node_consistency.py.
const D = Buffer.from("evidence-braid:ledger-membership:v1\0");
const hash = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest("hex");
const node = (left, right) => hash(D, Buffer.from("N"), Buffer.from(left, "hex"), Buffer.from(right, "hex"));
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  }
  return value;
}
const encode = value => Buffer.from(JSON.stringify(sorted(value)));
const empty = hash(D, Buffer.from("E"));
const leaves = Array.from({ length: 65 }, (_, i) => hash(Buffer.from(`synthetic-${i}`)));
function root(values) {
  if (!values.length) return empty;
  const frontier = [];
  for (let value of values) {
    let width = 1;
    while (frontier.length && frontier.at(-1).width === width) {
      value = node(frontier.pop().value, value);
      width *= 2;
    }
    frontier.push({ width, value });
  }
  let value = frontier.pop().value;
  while (frontier.length) value = node(frontier.pop().value, value);
  return value;
}
function seal(body) {
  const { commitment_digest, ...unsigned } = body;
  return { ...unsigned, commitment_digest: hash(D, Buffer.from("C"), encode(unsigned)) };
}
function commitment(count, values = leaves, version = "2.0") {
  const genesis = hash(Buffer.from(`evidence-braid-ledger:v${version[0]}`));
  return seal({ kind: "evidence-braid-ledger-commitment", schema_version: "1.0",
    ledger_version: version, genesis, head_digest: count ? values[count - 1] : genesis,
    entry_count: count, root_hash: root(values.slice(0, count)) });
}
function pathFor(values, count, known = true) {
  if (count === values.length) return known ? [] : [root(values)];
  let split = 1;
  while (split * 2 < values.length) split *= 2;
  if (count <= split) return [...pathFor(values.slice(0, split), count, known), root(values.slice(split))];
  return [...pathFor(values.slice(split), count - split, false), root(values.slice(0, split))];
}
function proof(before = 3, after = 7, version = "2.0") {
  return { kind: "evidence-braid-ledger-consistency", schema_version: "1.0",
    old_commitment: commitment(before, leaves, version),
    new_commitment: commitment(after, leaves, version),
    path: before === 0 || before === after ? [] : pathFor(leaves.slice(0, after), before) };
}
const anchors = value => ({ expectedOldCommitmentDigest: value.old_commitment?.commitment_digest ?? "0".repeat(64),
  expectedNewCommitmentDigest: value.new_commitment?.commitment_digest ?? "0".repeat(64) });
const verify = value => verifyLedgerConsistency(encode(value), anchors(value));
function reject(value) { assert.throws(() => verify(value), ConsistencyVerificationError); }

test("all prefix sizes through 65 match independently built frontier roots", () => {
  let count = 0;
  for (let next = 0; next <= 65; next++) {
    for (let before = 0; before <= next; before++) {
      const result = verify(proof(before, next));
      assert.equal(result.oldEntryCount, before);
      assert.equal(result.newEntryCount, next);
      assert(Object.isFrozen(result));
      count++;
    }
  }
  assert.equal(count, 2211);
  assert.equal(verify(proof(3, 7, "1.0")).newEntryCount, 7);
});

test("requires two external anchors, not a self-selected incoming header", () => {
  const value = proof();
  for (const options of [undefined, null, [], {}, { expectedOldCommitmentDigest: "0".repeat(64) },
    { ...anchors(value), extra: true }]) {
    assert.throws(() => verifyLedgerConsistency(encode(value), options), ConsistencyVerificationError);
  }
  for (const name of Object.keys(anchors(value))) {
    for (const digest of [null, 1, "A".repeat(64), "0".repeat(63), "0".repeat(64) + "\n", "0".repeat(64)]) {
      assert.throws(() => verifyLedgerConsistency(encode(value), { ...anchors(value), [name]: digest }),
        ConsistencyVerificationError);
    }
  }
});

test("wrong roots, missing, extra, reordered and modified path nodes fail", () => {
  const value = proof();
  for (const path of [[], value.path.slice(1), value.path.slice(0, -1), [...value.path, value.path[0]],
    [...value.path].reverse(), value.path.map(() => "0".repeat(64))]) reject({ ...value, path });
  for (let i = 0; i < value.path.length; i++) {
    for (let bit = 0n; bit < 256n; bit++) {
      const path = [...value.path];
      path[i] = (BigInt(`0x${path[i]}`) ^ (1n << bit)).toString(16).padStart(64, "0");
      reject({ ...value, path });
    }
  }
  const old_commitment = seal({ ...value.old_commitment, root_hash: "0".repeat(64) });
  reject({ ...value, old_commitment });
});

test("equal/empty/rollback/version and genesis boundaries", () => {
  const equal = proof(7, 7);
  reject({ ...equal, path: ["0".repeat(64)] });
  reject({ ...equal, new_commitment: seal({ ...equal.new_commitment, head_digest: "0".repeat(64) }) });
  reject({ ...proof(0, 7), path: ["0".repeat(64)] });
  reject({ ...proof(), old_commitment: commitment(8) });
  reject({ ...proof(), old_commitment: commitment(3, leaves, "1.0") });
  for (const field of ["head_digest", "root_hash"]) {
    reject({ ...proof(0, 7), old_commitment: seal({ ...commitment(0), [field]: "0".repeat(64) }) });
  }
  reject({ ...proof(), old_commitment: seal({ ...commitment(3), genesis: "0".repeat(64) }) });
  // The documented hidden-chain limitation: anchored tree consistency alone
  // cannot establish a new header's relationship to an undisclosed tail leaf.
  const dishonest = proof();
  dishonest.new_commitment = seal({ ...dishonest.new_commitment, head_digest: "0".repeat(64) });
  assert.equal(verify(dishonest).newEntryCount, 7);
});

test("closed shapes, strict scalar types and header commitments", () => {
  for (const malformed of [null, [], 2, {}, { ...proof(), extra: 1 },
    { ...proof(), kind: "wrong" }, { ...proof(), schema_version: 1 },
    { ...proof(), path: null }, { ...proof(), path: Array(19).fill("0".repeat(64)) },
    { ...proof(), path: ["A".repeat(64)] }]) {
    assert.throws(() => verifyLedgerConsistency(encode(malformed), anchors(proof())), ConsistencyVerificationError);
  }
  for (const header of [null, [], {}, { ...commitment(3), extra: 1 }]) {
    reject({ ...proof(), old_commitment: header });
  }
  for (const [key, bad] of [
    ["kind", "wrong"], ["schema_version", 1], ["ledger_version", "3.0"],
    ["genesis", "bad"], ["head_digest", "bad"], ["root_hash", "bad"],
    ["commitment_digest", "0".repeat(64)], ["entry_count", true],
    ["entry_count", -1], ["entry_count", 100001],
  ]) reject({ ...proof(), old_commitment: { ...commitment(3), [key]: bad } });
});

test("raw byte/UTF8/depth/number admission and canonical-only spelling", () => {
  const value = proof();
  const valid = encode(value);
  const invalid = [undefined, "{}", new Uint16Array(4), Buffer.alloc(0), Buffer.alloc(4097),
    Buffer.from([0xff]), Buffer.from('{"x":{"y":[]}}'), Buffer.from("[")];
  for (const raw of invalid) {
    assert.throws(() => verifyLedgerConsistency(raw, anchors(value)), ConsistencyVerificationError);
  }
  for (const token of ["1234567", "-1234567", "-", "0.1", "1e2", "1E2", "-0"]) {
    const raw = Buffer.from(valid.toString().replace('"entry_count":3', `"entry_count":${token}`));
    assert.throws(() => verifyLedgerConsistency(raw, anchors(value)), ConsistencyVerificationError);
  }
  for (const raw of [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), valid]),
    Buffer.concat([valid, Buffer.from("\n")]), Buffer.from(JSON.stringify(value)),
    Buffer.from(valid.toString().replace('{"kind":', '{"kind":"duplicate","kind":')),
    Buffer.from(valid.toString().replace("evidence-braid-ledger-consistency", "evidence-braid-ledger-\\u0063onsistency")),
    Buffer.from(valid.toString().replace("evidence-braid-ledger-consistency", 'string[\\"\\\\]'))]) {
    assert.throws(() => verifyLedgerConsistency(raw, anchors(value)), ConsistencyVerificationError);
  }
  const padded = Buffer.concat([Buffer.from("x"), valid, Buffer.from("y")]);
  assert.equal(verifyLedgerConsistency(new Uint8Array(padded.buffer, padded.byteOffset + 1, valid.length),
    anchors(value)).newEntryCount, 7);
});

test("native byte-view bounds ignore shadowed properties and caller hooks", () => {
  const value = proof();
  const tooLarge = new Uint8Array(5000);
  Object.defineProperty(tooLarge, "byteLength", { value: 1 });
  assert.throws(() => verifyLedgerConsistency(tooLarge, anchors(value)), /1\.\.4096/);
  const bytes = new Uint8Array(encode(value));
  const forbidden = () => { assert.fail("caller property hook was invoked"); };
  for (const key of ["byteLength", "byteOffset", "buffer", "length", "valueOf", Symbol.iterator]) {
    Object.defineProperty(bytes, key, { get: forbidden });
  }
  assert.equal(verifyLedgerConsistency(bytes, anchors(value)).newEntryCount, 7);
  const proxy = new Proxy(new Uint8Array(encode(value)), { get: forbidden });
  assert.throws(() => verifyLedgerConsistency(proxy, anchors(value)), ConsistencyVerificationError);
  const detached = new Uint8Array(20);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  assert.throws(() => verifyLedgerConsistency(detached, anchors(value)), ConsistencyVerificationError);
  const fake = Object.create(Uint8Array.prototype);
  assert.throws(() => verifyLedgerConsistency(fake, anchors(value)), ConsistencyVerificationError);
});

test("sparse subtree fixtures exercise the maximum count and high index bits", () => {
  // O(log n) synthetic fixture construction. Opaque disjoint subtrees stand in
  // for their undisclosed leaves; only ancestors on the prefix boundary are
  // expanded. This constructs two consistent roots, not actual receipt data.
  function boundary(before, after, start = 0, seeded = true) {
    if (before === after) {
      const value = hash(Buffer.from(`opaque-subtree:${start}:${after}`));
      return { before: value, after: value, path: seeded ? [] : [value] };
    }
    let split = 1;
    while (split * 2 < after) split *= 2;
    if (before <= split) {
      const left = boundary(before, split, start, seeded);
      const right = hash(Buffer.from(`opaque-subtree:${start + split}:${after - split}`));
      return { before: left.before, after: node(left.after, right), path: [...left.path, right] };
    }
    const left = hash(Buffer.from(`opaque-subtree:${start}:${split}`));
    const right = boundary(before - split, after - split, start + split, false);
    return { before: node(left, right.before), after: node(left, right.after), path: [...right.path, left] };
  }
  for (const before of [1, 32767, 32768, 65535, 65536, 99999, 100000]) {
    const trees = boundary(before, 100000);
    const value = proof();
    value.old_commitment = seal({ ...value.old_commitment, entry_count: before, root_hash: trees.before });
    value.new_commitment = seal({ ...value.new_commitment, entry_count: 100000, root_hash: trees.after });
    if (before === 100000) value.new_commitment = value.old_commitment;
    value.path = trees.path;
    assert(value.path.length <= 18);
    assert.equal(verify(value).oldEntryCount, before);
    assert.equal(verify(value).newEntryCount, 100000);
    if (value.path.length > 1) reject({ ...value, path: [...value.path].reverse() });
  }
});
