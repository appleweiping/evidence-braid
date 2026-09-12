// Private canonical-wire numeric support. This is not RFC 8785 or a general
// JavaScript serializer. No Python process or floating-point formatter is used.

export class NumberWireError extends Error {
  constructor() {
    super("invalid canonical receipt number");
    this.name = "NumberWireError";
  }
}

const UNIT = 1n << 1075n;
const FRACTION_MASK = (1n << 52n) - 1n;
const POW10 = [1n];
for (let index = 1; index <= 340; index++) POW10.push(POW10[index - 1] * 10n);
Object.freeze(POW10);

// All finite nonnegative binary64 values and their half-way boundaries are
// integers in units of 2**-1075. The bit pattern immediately after maximum
// finite is treated as the virtual next value 2**1024, not as a JS Infinity.
function scaled(bits) {
  const exponent = Number(bits >> 52n);
  const fraction = bits & FRACTION_MASK;
  return exponent === 0 ? fraction << 1n : ((1n << 52n) + fraction) << BigInt(exponent);
}

function decimalFactors(exponent) {
  return exponent >= 0 ? [UNIT * POW10[exponent], 1n] : [UNIT, POW10[-exponent]];
}

function comparePower(value, exponent) {
  const [numerator, denominator] = decimalFactors(exponent);
  const difference = value * denominator - numerator;
  return difference < 0n ? -1 : difference === 0n ? 0 : 1;
}

function nearestInteger(numerator, denominator) {
  const quotient = numerator / denominator;
  const twiceRemainder = 2n * (numerator % denominator);
  return quotient + (twiceRemainder > denominator ||
    (twiceRemainder === denominator && (quotient & 1n) === 1n) ? 1n : 0n);
}

function candidate(value, lower, upper, inclusive, digits, exponent) {
  const [numerator, denominator] = decimalFactors(exponent);
  const low = lower * denominator;
  const high = upper * denominator;
  let minimum = (low + numerator - 1n) / numerator;
  if (!inclusive && low % numerator === 0n) minimum++;
  let maximum = (high - (inclusive ? 0n : 1n)) / numerator;
  if (minimum < POW10[digits - 1]) minimum = POW10[digits - 1];
  if (maximum >= POW10[digits]) maximum = POW10[digits] - 1n;
  if (minimum > maximum) return null;
  let significand = nearestInteger(value * denominator, numerator);
  if (significand < minimum) significand = minimum;
  if (significand > maximum) significand = maximum;
  const difference = significand * numerator - value * denominator;
  return {
    significand,
    exponent,
    distance: difference < 0n ? -difference : difference,
    denominator,
  };
}

function closer(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  const difference = left.distance * right.denominator - right.distance * left.denominator;
  if (difference < 0n) return left;
  if (difference > 0n) return right;
  return (left.significand & 1n) === 0n ? left : right;
}

function spelling({ significand, exponent }) {
  const digits = significand.toString();
  const magnitude = digits.length + exponent - 1;
  if (magnitude < -4 || magnitude >= 16) {
    const fraction = digits.length === 1 ? "" : `.${digits.slice(1)}`;
    const power = String(Math.abs(magnitude)).padStart(2, "0");
    return `${digits[0]}${fraction}e${magnitude < 0 ? "-" : "+"}${power}`;
  }
  if (exponent >= 0) return `${digits}${"0".repeat(exponent)}.0`;
  const point = digits.length + exponent;
  if (point > 0) return `${digits.slice(0, point)}.${digits.slice(point)}`;
  return `0.${"0".repeat(-point)}${digits}`;
}

export function canonicalFloat(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new NumberWireError();
  const negative = value < 0 || Object.is(value, -0);
  if (value === 0) return negative ? "-0.0" : "0.0";
  const absolute = Math.abs(value);
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, absolute);
  const bits = view.getBigUint64(0);
  const exact = scaled(bits);
  const lower = (exact + scaled(bits - 1n)) / 2n;
  const upper = (exact + scaled(bits + 1n)) / 2n;
  const inclusive = (bits & 1n) === 0n;
  // The logarithm is only an initial estimate. Exact integer comparisons fix
  // either side of a decimal-power boundary before choosing any candidate.
  let magnitude = Math.floor(Math.log10(absolute));
  while (comparePower(exact, magnitude) < 0) magnitude--;
  while (comparePower(exact, magnitude + 1) >= 0) magnitude++;
  for (let digits = 1; digits <= 17; digits++) {
    const exponent = magnitude - digits + 1;
    // A shortest decimal can carry across a power of ten even when the exact
    // binary value lies just below that decimal boundary (for example 1e-7).
    const chosen = closer(
      candidate(exact, lower, upper, inclusive, digits, exponent),
      candidate(exact, lower, upper, inclusive, digits, exponent + 1),
    );
    if (chosen !== null) return (negative ? "-" : "") + spelling(chosen);
  }
  throw new NumberWireError();
}

export function verifyFloatToken(token) {
  if (typeof token !== "string" || token.length > 24 ||
      !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)$/.test(token)) {
    throw new NumberWireError();
  }
  if (canonicalFloat(Number(token)) !== token) throw new NumberWireError();
  return token;
}
