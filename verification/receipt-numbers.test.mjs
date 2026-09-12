import assert from "node:assert/strict";
import test from "node:test";
import { canonicalFloat, verifyFloatToken, NumberWireError } from "./receipt-numbers.mjs";

function fromBits(hex) {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
}

test("independent fixed IEEE-754 bit vectors retain Python receipt float spelling", () => {
  const vectors = [
    ["0000000000000000", "0.0"],
    ["8000000000000000", "-0.0"],
    ["3ff0000000000000", "1.0"],
    ["3fe0000000000000", "0.5"],
    ["3fb999999999999a", "0.1"],
    ["0000000000000001", "5e-324"],
    ["0000000000000002", "1e-323"],
    ["0000000000000003", "1.5e-323"],
    ["0010000000000000", "2.2250738585072014e-308"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["3ff0000000000001", "1.0000000000000002"],
    ["3fefffffffffffff", "0.9999999999999999"],
  ];
  for (const [bits, expected] of vectors) {
    assert.equal(canonicalFloat(fromBits(bits)), expected, bits);
    assert.equal(verifyFloatToken(expected), expected);
  }
});

test("canonical notation thresholds and decimal carries are not JS stringify", () => {
  for (const expected of [
    "0.0001", "1e-05", "1000000000000000.0", "1e+16", "1e-07", "1e+23",
    "1.2345678901234567", "-1.7976931348623157e+308", "-5e-324",
  ]) {
    assert.equal(canonicalFloat(Number(expected)), expected);
    assert.equal(verifyFloatToken(expected), expected);
  }
});

test("integer tokens, alternate floats and overflowing spellings fail closed", () => {
  for (const value of [
    "1", "-0", "0", "1.00", "0.10", "1E+16", "1e16", "1e+016", "0.00001",
    "1.0e+16", "1e-5", "1e+309", "1e-99999999999999999999999", "NaN", "Infinity",
    " 1.0", "1.0\n", "+1.0", ".5", "01.0", "-0.00", "4e-324", "1e-324",
    null, true, 1, {}, [],
  ]) {
    assert.throws(() => verifyFloatToken(value), NumberWireError);
  }
  for (const value of [NaN, Infinity, -Infinity, 1n, "1.0", null]) {
    assert.throws(() => canonicalFloat(value), NumberWireError);
  }
});

test("binary exponent neighbors and seeded mantissas retain exact bit identity", () => {
  const patterns = new Set();
  for (let exponent = 1n; exponent < 2047n; exponent++) {
    const power = exponent << 52n;
    patterns.add(power - 1n); patterns.add(power); patterns.add(power + 1n);
  }
  let state = 821964n;
  for (let i = 0; i < 512; i++) {
    state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 63n) - 1n);
    patterns.add(state);
  }
  for (const bits of patterns) {
    const value = fromBits(bits.toString(16));
    if (!Number.isFinite(value)) continue;
    for (const signed of [value, -value]) {
      const token = canonicalFloat(signed);
      assert.ok(Object.is(Number(token), signed));
      assert.equal(verifyFloatToken(token), token);
    }
  }
  // Roundtrip is an independent invariant, not an oracle for Python spelling.
  // The separate Python test supplies repr() expectations for >19000 vectors.
});
