import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { LedgerVerificationError, verifyLedgerMembership, verifyLedgerReceipt } from "./ledger-membership.mjs";

// Test-only builder: fixed ASCII object schema, and explicitly supplied raw
// event text. Never imports the numeric reader or the verification algorithms.
const hash = (...parts) => {
  const result = createHash("sha256");
  for (const part of parts) result.update(part);
  return result.digest("hex");
};
const tag = (letter, ...parts) => hash("evidence-braid:ledger-membership:v1\0", letter, ...parts);
const parent = (a, b) => tag("N", Buffer.from(a, "hex"), Buffer.from(b, "hex"));
const encode = (object) => "{" + Object.keys(object).sort().map((key) =>
  JSON.stringify(key) + ":" + JSON.stringify(object[key])).join(",") + "}";
const event = (id = "one", date = "2026-09-01T00:00:00Z") =>
  `{"claim":"claim","confidence":1.0,"event_id":"${id}","ingested_at":"${date}",` +
  `"modality":"sensor","observed_at":"${date}","signal":"contradict","source":"source"}`;

function makeReceipt(sequence, previous, ledgerVersion, rawEvent = event()) {
  const id = JSON.parse(rawEvent).event_id;
  const receiptDigest = ledgerVersion === "1.0" ? hash(previous, "\n", rawEvent) : hash(
    `{"event":${rawEvent},"previous_digest":"${previous}","schema_version":"2.0","sequence":${sequence}}`,
  );
  const raw = `{"digest":"${receiptDigest}","event":${rawEvent},"event_id":${JSON.stringify(id)},` +
    `"previous_digest":"${previous}","sequence":${sequence}}`;
  return { raw, receiptDigest, previousDigest: previous, sequence, eventId: id };
}

function fixture(receipts, rootHash, selections, ledgerVersion = "2.0", count = receipts.length, overrides = {}) {
  const header = { entry_count: count, genesis: hash(`evidence-braid-ledger:v${ledgerVersion[0]}`),
    head_digest: receipts.at(-1).receiptDigest, kind: "evidence-braid-ledger-commitment", ledger_version: ledgerVersion,
    root_hash: rootHash, schema_version: "1.0", ...overrides };
  const commitmentDigest = tag("C", encode(header));
  const rawHeader = encode({ commitment_digest: commitmentDigest, ...header });
  const members = selections.map(([receipt, path]) => `{"entry":${receipt.raw},"siblings":${JSON.stringify(path)}}`);
  const raw = `{"commitment":${rawHeader},"kind":"evidence-braid-ledger-membership",` +
    `"members":[${members.join(",")}],"schema_version":"1.0"}`;
  return { raw, options: { expectedCommitmentDigest: commitmentDigest } };
}

const verify = (case_) => verifyLedgerMembership(Buffer.from(case_.raw), case_.options);
const reject = (case_) => assert.throws(() => verify(case_), LedgerVerificationError);
const leaf = (receipt, version) => tag("L", `{"ledger_version":"${version}","receipt":${receipt.raw}}`);

function chain(count, version) {
  let previous = hash(`evidence-braid-ledger:v${version[0]}`);
  return Array.from({ length: count }, (_, i) => {
    const receipt = makeReceipt(i, previous, version, event(`id${i}`));
    previous = receipt.receiptDigest;
    return receipt;
  });
}

test("independent hand-built unpadded one, three and five-leaf trees in both ledger versions", () => {
  for (const version of ["1.0", "2.0"]) {
    const receipts = chain(5, version);
    const [a, b, c, d, e] = receipts.map((item) => leaf(item, version));
    const ab = parent(a, b);
    const cd = parent(c, d);
    const abcd = parent(ab, cd);
    const cases = [
      fixture(receipts.slice(0, 1), a, [[receipts[0], []]], version),
      fixture(receipts.slice(0, 3), parent(ab, c), [
        [receipts[0], [b, c]], [receipts[1], [a, c]], [receipts[2], [ab]],
      ], version),
      fixture(receipts, parent(abcd, e), [
        [receipts[0], [b, cd, e]], [receipts[1], [a, cd, e]], [receipts[2], [d, ab, e]],
        [receipts[3], [c, ab, e]], [receipts[4], [abcd]],
      ], version),
    ];
    for (const item of cases) {
      const result = verify(item);
      assert.equal(result.members.length, result.entryCount);
      assert.ok(Object.isFrozen(result) && Object.isFrozen(result.members));
      assert.ok(result.members.every(Object.isFrozen));
      reject({ ...item, options: { expectedCommitmentDigest: "0".repeat(64) } });
    }
  }
});

test("sparse 100000-count paths verify exact bit-boundary shapes without inventing hidden links", () => {
  // 100000 = 65536 + 32768 + 1024 + 512 + 128 + 32. These exact
  // bottom-up paths are independent fixed vectors, not production route calls.
  const cases = [[0, Array(17).fill(false)], [65535, [...Array(16).fill(true), false]],
    [65536, [...Array(16).fill(false), true]], [99999, Array(10).fill(true)]];
  for (const [position, directions] of cases) {
    const receipt = makeReceipt(position, hash("evidence-braid-ledger:v2"), "2.0");
    const path = directions.map((_, i) => hash(`opaque subtree ${i}`));
    let root = leaf(receipt, "2.0");
    for (let i = 0; i < path.length; i++) root = directions[i] ? parent(path[i], root) : parent(root, path[i]);
    const item = fixture([receipt], root, [[receipt, path]], "2.0", 100000);
    assert.equal(verify(item).members[0].sequence, position);
    reject(fixture([receipt], root, [[receipt, [...path, hash("extra")]]], "2.0", 100000));
    reject(fixture([receipt], root, [[receipt, path.slice(1)]], "2.0", 100000));
  }
});

test("canonical Gregorian calendar independently checks leap centuries and normalized microseconds", () => {
  const dates = ["0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999Z",
    "2000-02-29T00:00:00.000001Z", "2024-02-29T01:02:03.100000Z"];
  for (const date of dates) {
    const receipt = makeReceipt(0, hash("evidence-braid-ledger:v2"), "2.0", event("id", date));
    assert.equal(verify(fixture([receipt], leaf(receipt, "2.0"), [[receipt, []]])).members[0].eventId, "id");
  }
});

test("optional attributes are lossless, nonempty and distinct from canonical identifiers", () => {
  const previous = hash("evidence-braid-ledger:v2");
  const suffix = event().slice(1);
  const valid = makeReceipt(0, previous, "2.0",
    '{"attributes":{"":true,"big":9007199254740993,"float":-0.0,"𐀀":[]},' +
    suffix.replace('"event_id":', '"correlation_group":"﻿é﻿","event_id":'));
  assert.equal(verify(fixture([valid], leaf(valid, "2.0"), [[valid, []]])).members.length, 1);
  for (const attributes of ["{}", "[]", "null"]) {
    const invalid = makeReceipt(0, previous, "2.0", `{"attributes":${attributes},${suffix}`);
    reject(fixture([invalid], leaf(invalid, "2.0"), [[invalid, []]]));
  }
});

test("application-owned option getter failures are not disguised as invalid wire", () => {
  const original = new Error("application failure");
  const options = { get expectedCommitmentDigest() { throw original; } };
  assert.throws(() => verifyLedgerMembership(Buffer.from("{}"), options), (error) => error === original);
});

test("receipt sequence context is captured once before admission", () => {
  const receipts = chain(2, "2.0");
  const receipt = receipts[1];
  let reads = 0;
  const options = { ledgerVersion: "2.0", expectedReceiptDigest: receipt.receiptDigest,
    expectedPreviousDigest: receipt.previousDigest,
    get expectedSequence() { return ++reads <= 4 ? 0 : 1; } };
  assert.throws(() => verifyLedgerReceipt(Buffer.from(receipt.raw), options), LedgerVerificationError);
  assert.equal(reads, 1);
});

test("recomputed anchor cannot hide first/last receipt bindings or bad genesis", () => {
  const [receipt] = chain(1, "2.0");
  const root = leaf(receipt, "2.0");
  reject(fixture([receipt], root, [[receipt, []]], "2.0", 1, { head_digest: hash("other") }));
  reject(fixture([receipt], root, [[receipt, []]], "2.0", 1, { genesis: hash("other") }));
  const wrongPrevious = makeReceipt(0, hash("not genesis"), "2.0");
  reject(fixture([wrongPrevious], leaf(wrongPrevious, "2.0"), [[wrongPrevious, []]]));
  reject(fixture([receipt], tag("E"), [[receipt, []]], "2.0", 0,
    { head_digest: hash("evidence-braid-ledger:v2") }));
  reject(fixture([receipt], root, [[receipt, []]], "2.0", 100001));
  reject(fixture([receipt], root, [[receipt, []]], "3.0"));
});

test("both public APIs require independently supplied closed option objects", () => {
  const [receipt] = chain(1, "2.0");
  const item = fixture([receipt], leaf(receipt, "2.0"), [[receipt, []]]);
  for (const options of [undefined, null, [], {}, { expectedCommitmentDigest: 1 },
    { expectedCommitmentDigest: item.options.expectedCommitmentDigest, extra: true }]) reject({ ...item, options });
  const options = { ledgerVersion: "2.0", expectedReceiptDigest: receipt.receiptDigest,
    expectedPreviousDigest: receipt.previousDigest, expectedSequence: 0 };
  assert.equal(verifyLedgerReceipt(Buffer.from(receipt.raw), options).eventId, "id0");
  for (const updates of [{ expectedSequence: -0 }, { expectedSequence: 1 }, { expectedSequence: 100000 },
    { expectedSequence: true }, { expectedSequence: 0.5 }, { expectedPreviousDigest: hash("different") },
    { expectedReceiptDigest: hash("different") }, { ledgerVersion: "3.0" }, { extra: 1 }]) {
    assert.throws(() => verifyLedgerReceipt(Buffer.from(receipt.raw), { ...options, ...updates }), LedgerVerificationError);
  }
});

test("membership field, ordering, cardinality and path errors fail as public verification errors", () => {
  const receipts = chain(3, "2.0");
  const [a, b, c] = receipts.map((item) => leaf(item, "2.0"));
  const root = parent(parent(a, b), c);
  const item = fixture(receipts, root, [[receipts[0], [b, c]], [receipts[2], [parent(a, b)]]]);
  for (const mutate of [
    (data) => { data.members.reverse(); }, (data) => { data.members.push(data.members[1]); },
    (data) => { data.members = []; }, (data) => { data.members = Array(1001).fill(data.members[0]); },
    (data) => { data.members[0].siblings = Array(18).fill(a); },
    (data) => { data.members[0].siblings = [123]; }, (data) => { data.members[0].siblings = {}; },
    (data) => { data.members[0].entry = null; }, (data) => { data.members[0].extra = true; },
    (data) => { data.kind = "wrong"; }, (data) => { data.schema_version = "2.0"; },
  ]) {
    // Mutation reserialization deliberately preserves the canonical float.
    const data = JSON.parse(item.raw);
    mutate(data);
    const wire = JSON.stringify(data).replaceAll('"confidence":1,', '"confidence":1.0,');
    reject({ ...item, raw: wire });
  }
});

test("selected receipt byte limits include canonical syntax and aggregate across members", () => {
  function sizedReceipt(size, sequence, previous) {
    const initial = makeReceipt(sequence, previous, "2.0");
    const added = size - Buffer.byteLength(initial.raw);
    const rawEvent = event().replace('"claim":"claim"', `"claim":"claim${"a".repeat(added)}"`);
    const result = makeReceipt(sequence, previous, "2.0", rawEvent);
    assert.equal(Buffer.byteLength(result.raw), size);
    return result;
  }
  const limit = 16 * 1024 * 1024;
  const previous = hash("evidence-braid-ledger:v2");
  let receipt = sizedReceipt(limit, 0, previous);
  let item = fixture([receipt], leaf(receipt, "2.0"), [[receipt, []]]);
  assert.equal(verify(item).entryCount, 1);
  assert.equal(verifyLedgerReceipt(Buffer.from(receipt.raw), {
    ledgerVersion: "2.0", expectedReceiptDigest: receipt.receiptDigest,
    expectedPreviousDigest: previous, expectedSequence: 0,
  }).sequence, 0);
  receipt = sizedReceipt(limit + 1, 0, previous);
  item = fixture([receipt], leaf(receipt, "2.0"), [[receipt, []]]);
  reject(item);
  assert.throws(() => verifyLedgerReceipt(Buffer.from(receipt.raw), {
    ledgerVersion: "2.0", expectedReceiptDigest: receipt.receiptDigest,
    expectedPreviousDigest: previous, expectedSequence: 0,
  }), LedgerVerificationError);
  const first = sizedReceipt(limit / 2, 0, previous);
  for (const extra of [0, 1]) {
    const second = sizedReceipt(limit / 2 + extra, 1, first.receiptDigest);
    const a = leaf(first, "2.0");
    const b = leaf(second, "2.0");
    const pair = fixture([first, second], parent(a, b), [[first, [b]], [second, [a]]]);
    if (extra) reject(pair);
    else assert.equal(verify(pair).members.length, 2);
  }
});
