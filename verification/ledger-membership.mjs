/** Original offline verifier of canonical receipts and selected Merkle members.
 * No Python process, network, filesystem, dependency or lossy event serialization.
 * Callers must separately establish their anchors; hashes do not authenticate.
 */
import { createHash } from "node:crypto";
import { readCanonicalWire, ReceiptWireError, requireWire } from "./receipt-wire.mjs";

const DOMAIN = Buffer.from("evidence-braid:ledger-membership:v1\0", "ascii");
const RECEIPT_LIMIT = 16 * 1024 * 1024;
const HEX = /^[0-9a-f]{64}$/;
// Deliberately not JS trim(): Python strips U+0085, but does not strip U+FEFF.
const EDGE_SPACE = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/u;

export class LedgerVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "LedgerVerificationError";
  }
}

function verified(operation) {
  try { return operation(); }
  catch (error) {
    if (error instanceof ReceiptWireError) throw new LedgerVerificationError(error.message);
    throw error;
  }
}

function sha(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function tagged(tag, ...parts) { return sha(DOMAIN, tag, ...parts); }
function join(left, right) { return tagged("N", Buffer.from(left, "hex"), Buffer.from(right, "hex")); }
function span(bytes, node) { return bytes.subarray(node.start, node.end); }

function fields(node, required, optional = []) {
  requireWire(node?.kind === "object", "expected closed wire object");
  requireWire(required.every((key) => node.value.has(key)) &&
    [...node.value.keys()].every((key) => required.includes(key) || optional.includes(key)),
  "invalid wire object fields");
  return node.value;
}

function text(node) {
  requireWire(node?.kind === "string", "expected wire string");
  return node.value;
}

function identifier(node) {
  const value = text(node);
  requireWire(value.length > 0 && !EDGE_SPACE.test(value), "identifier is empty or not canonically trimmed");
  return value;
}

function digest(value) {
  requireWire(typeof value === "string" && value.length === 64 && HEX.test(value),
    "expected lowercase SHA-256 digest");
  return value;
}

function integer(node, maximum) {
  requireWire(node?.kind === "integer" && node.value >= 0n && node.value <= BigInt(maximum),
    "integer field is outside protocol bounds");
  return Number(node.value);
}

function version(value) {
  requireWire(value === "1.0" || value === "2.0", "unsupported ledger version");
  return value;
}

function timestamp(node) {
  const value = text(node);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{6}))?Z$/.exec(value);
  requireWire(match !== null, "timestamp must use canonical UTC spelling");
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  requireWire(year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] &&
    hour < 24 && minute < 60 && second < 60 && match[7] !== "000000",
  "invalid calendar value or redundant zero microseconds");
}

function event(node) {
  const data = fields(node, ["claim", "confidence", "event_id", "ingested_at", "modality",
    "observed_at", "signal", "source"], ["attributes", "correlation_group"]);
  requireWire(node.height <= 64, "event exceeds full-event nesting bound");
  for (const name of ["claim", "event_id", "source"]) identifier(data.get(name));
  requireWire(["vision", "audio", "text", "sensor"].includes(text(data.get("modality"))), "invalid modality");
  requireWire(["support", "contradict"].includes(text(data.get("signal"))), "invalid signal");
  const confidence = data.get("confidence");
  requireWire(confidence.kind === "float" && confidence.value >= 0 && confidence.value <= 1 &&
    confidence.token !== "-0.0", "confidence must be a canonical normalized float in [0,1]");
  timestamp(data.get("observed_at"));
  timestamp(data.get("ingested_at"));
  if (data.has("correlation_group")) identifier(data.get("correlation_group"));
  if (data.has("attributes")) {
    const attributes = data.get("attributes");
    requireWire(attributes.kind === "object" && attributes.value.size > 0,
      "attributes must be a nonempty object or omitted");
  }
  return text(data.get("event_id"));
}

function receipt(bytes, node, ledgerVersion) {
  requireWire(node.end - node.start <= RECEIPT_LIMIT, "receipt exceeds 16 MiB");
  const data = fields(node, ["digest", "event", "event_id", "previous_digest", "sequence"]);
  const sequence = integer(data.get("sequence"), 99_999);
  const eventId = event(data.get("event"));
  requireWire(text(data.get("event_id")) === eventId, "receipt and event identifiers differ");
  const previous = digest(text(data.get("previous_digest")));
  const supplied = digest(text(data.get("digest")));
  const rawEvent = span(bytes, data.get("event"));
  const expected = ledgerVersion === "1.0" ? sha(previous, "\n", rawEvent) : sha(
    '{"event":', rawEvent, `,"previous_digest":"${previous}","schema_version":"2.0","sequence":${sequence}}`,
  );
  requireWire(expected === supplied, "receipt chain digest mismatch");
  return Object.freeze({ sequence, eventId, receiptDigest: supplied, previousDigest: previous });
}

function header(bytes, node) {
  const data = fields(node, ["commitment_digest", "entry_count", "genesis", "head_digest", "kind",
    "ledger_version", "root_hash", "schema_version"]);
  requireWire(text(data.get("kind")) === "evidence-braid-ledger-commitment" &&
    text(data.get("schema_version")) === "1.0", "unsupported commitment profile");
  const ledgerVersion = version(text(data.get("ledger_version")));
  const entryCount = integer(data.get("entry_count"), 100_000);
  const genesis = digest(text(data.get("genesis")));
  const headDigest = digest(text(data.get("head_digest")));
  const rootHash = digest(text(data.get("root_hash")));
  const commitmentDigest = digest(text(data.get("commitment_digest")));
  requireWire(genesis === sha(`evidence-braid-ledger:v${ledgerVersion[0]}`), "genesis/version mismatch");
  if (entryCount === 0) {
    requireWire(headDigest === genesis && rootHash === tagged("E"), "inconsistent empty commitment");
  }
  // The closed ASCII field set has already been validated. Remove only the
  // first canonical commitment_digest field; all remaining bytes stay exact.
  const body = bytes.subarray(data.get("commitment_digest").end + 1, node.end);
  requireWire(tagged("C", "{", body) === commitmentDigest, "commitment digest mismatch");
  return { ledgerVersion, entryCount, genesis, headDigest, rootHash, commitmentDigest };
}

function optionsFields(options, names) {
  requireWire(options !== null && typeof options === "object" && !Array.isArray(options),
    "explicit verification options are required");
  const keys = Object.keys(options);
  requireWire(keys.length === names.length && names.every((key) => keys.includes(key)),
    "explicit verification option fields are required");
}

/** Verify one full canonical receipt against caller-established context.
 * Version 1's hash does not bind sequence: expectedSequence is a separate check,
 * not proof that the sequence was authenticated by that legacy receipt hash.
 */
export function verifyLedgerReceipt(raw, options) {
  return verified(() => {
    optionsFields(options, ["ledgerVersion", "expectedReceiptDigest", "expectedPreviousDigest", "expectedSequence"]);
    const ledgerVersion = version(options.ledgerVersion);
    const expected = digest(options.expectedReceiptDigest);
    const previous = digest(options.expectedPreviousDigest);
    const expectedSequence = options.expectedSequence;
    requireWire(Number.isSafeInteger(expectedSequence) && expectedSequence >= 0 &&
      expectedSequence < 100_000 && !Object.is(expectedSequence, -0), "invalid expected sequence");
    const { bytes, root } = readCanonicalWire(raw, RECEIPT_LIMIT);
    const result = receipt(bytes, root, ledgerVersion);
    requireWire(result.sequence === expectedSequence && result.receiptDigest === expected &&
      result.previousDigest === previous, "receipt differs from expected context");
    return result;
  });
}

/** Verify selected full receipts under a separately retained commitment digest.
 * Does not establish hidden chain links, query completeness, source identity,
 * signatures or durable storage. Returns frozen metadata, never a lossy graph.
 */
export function verifyLedgerMembership(raw, options) {
  return verified(() => {
    optionsFields(options, ["expectedCommitmentDigest"]);
    const expected = digest(options.expectedCommitmentDigest);
    const { bytes, root } = readCanonicalWire(raw);
    const data = fields(root, ["commitment", "kind", "members", "schema_version"]);
    requireWire(text(data.get("kind")) === "evidence-braid-ledger-membership" &&
      text(data.get("schema_version")) === "1.0", "unsupported membership profile");
    const commitment = header(bytes, data.get("commitment"));
    requireWire(commitment.commitmentDigest === expected, "commitment differs from external anchor");
    const members = data.get("members");
    requireWire(members.kind === "array" && members.value.length >= 1 && members.value.length <= 1000,
      "membership requires 1..1000 members");
    let previous = -1;
    let receiptBytes = 0;
    const results = [];
    for (const member of members.value) {
      const proof = fields(member, ["entry", "siblings"]);
      const entry = proof.get("entry");
      receiptBytes += entry.end - entry.start;
      requireWire(receiptBytes <= RECEIPT_LIMIT, "selected receipts exceed 16 MiB");
      const siblings = proof.get("siblings");
      requireWire(siblings.kind === "array" && siblings.value.length <= 17, "invalid sibling array bound");
      const hashes = siblings.value.map((item) => digest(text(item)));
      const result = receipt(bytes, entry, commitment.ledgerVersion);
      requireWire(result.sequence > previous && result.sequence < commitment.entryCount,
        "member positions must strictly increase within the commitment");
      previous = result.sequence;
      if (result.sequence === 0) requireWire(result.previousDigest === commitment.genesis,
        "first receipt does not follow genesis");
      if (result.sequence === commitment.entryCount - 1) requireWire(result.receiptDigest === commitment.headDigest,
        "last receipt differs from committed head");
      // Build intervals top-down, then consume exact sibling hashes bottom-up.
      // Largest power of two strictly below width defines the unpadded tree.
      let width = commitment.entryCount;
      let position = result.sequence;
      const leftSibling = [];
      while (width > 1) {
        let split = 1;
        while (split * 2 < width) split *= 2;
        const right = position >= split;
        leftSibling.push(right);
        if (right) { position -= split; width -= split; }
        else width = split;
      }
      requireWire(hashes.length === leftSibling.length, "sibling count differs from exact tree route");
      let rootHash = tagged("L", `{"ledger_version":"${commitment.ledgerVersion}","receipt":`, span(bytes, entry), "}");
      for (let index = 0; index < hashes.length; index++) {
        rootHash = leftSibling[leftSibling.length - index - 1] ?
          join(hashes[index], rootHash) : join(rootHash, hashes[index]);
      }
      requireWire(rootHash === commitment.rootHash, "membership path does not reproduce committed root");
      results.push(result);
    }
    return Object.freeze({ ledgerVersion: commitment.ledgerVersion, entryCount: commitment.entryCount,
      commitmentDigest: expected, members: Object.freeze(results) });
  });
}
