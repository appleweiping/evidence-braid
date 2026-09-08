/** Independently implemented, offline two-anchor receipt-tree verification.
 * No Python process, receipt parser, filesystem access, network or dependencies.
 * This profile is not an authentication or witnessed-checkpoint protocol.
 */
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

const DOMAIN = Buffer.from("evidence-braid:ledger-membership:v1\0", "ascii");
const HEADER_KEYS = ["commitment_digest", "entry_count", "genesis", "head_digest",
  "kind", "ledger_version", "root_hash", "schema_version"];
const PROOF_KEYS = ["kind", "new_commitment", "old_commitment", "path", "schema_version"];
const HEX = /^[0-9a-f]{64}$/;
const TYPED_ARRAY = Object.getPrototypeOf(Uint8Array.prototype);
const BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "byteLength").get;
const BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "byteOffset").get;
const ARRAY_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "buffer").get;
const ARRAY_KIND = Object.getOwnPropertyDescriptor(TYPED_ARRAY, Symbol.toStringTag).get;
const COPY_VIEW = Uint8Array.prototype.set;

export class ConsistencyVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConsistencyVerificationError";
  }
}

function requireValue(condition, message) {
  if (!condition) throw new ConsistencyVerificationError(message);
}

function sha(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function tagged(tag, ...parts) {
  return sha(DOMAIN, Buffer.from(tag, "ascii"), ...parts);
}

function join(left, right) {
  return tagged("N", Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function shape(value, keys, message) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value), message);
  const actual = Object.keys(value).sort();
  requireValue(actual.length === keys.length && actual.every((key, i) => key === keys[i]), message);
}

function digest(value) {
  requireValue(typeof value === "string" && value.length === 64 && HEX.test(value),
    "expected lowercase SHA-256 digest");
  return value;
}

// Only closed, admitted ASCII headers/proof objects reach this serializer.
// It deliberately does not claim Python/RFC8785 canonicalization of arbitrary
// receipt JSON, floating-point numbers, Unicode maps or rich event attributes.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonical(value[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function header(value) {
  shape(value, HEADER_KEYS, "invalid commitment fields");
  requireValue(value.kind === "evidence-braid-ledger-commitment" && value.schema_version === "1.0",
    "unsupported commitment profile");
  requireValue(value.ledger_version === "1.0" || value.ledger_version === "2.0",
    "unsupported ledger version");
  for (const key of ["genesis", "head_digest", "root_hash", "commitment_digest"]) digest(value[key]);
  requireValue(Number.isSafeInteger(value.entry_count) && value.entry_count >= 0 &&
    value.entry_count <= 100_000 && !Object.is(value.entry_count, -0), "invalid entry count");
  const genesis = sha(Buffer.from(`evidence-braid-ledger:v${value.ledger_version[0]}`, "ascii"));
  requireValue(value.genesis === genesis, "genesis differs from ledger version");
  if (value.entry_count === 0) {
    requireValue(value.head_digest === genesis && value.root_hash === tagged("E"),
      "empty commitment is inconsistent");
  }
  const { commitment_digest: supplied, ...body } = value;
  requireValue(tagged("C", Buffer.from(canonical(body), "ascii")) === supplied,
    "commitment digest mismatch");
}

function admission(raw) {
  let bytes;
  try {
    // Native getters bypass shadowed byteLength/buffer/valueOf/iterator hooks.
    // Proxy wrappers and detached or non-byte views fail before allocation.
    requireValue(ARRAY_KIND.call(raw) === "Uint8Array", "proof must be a native byte view");
    const length = BYTE_LENGTH.call(raw);
    requireValue(length > 0 && length <= 4096, "proof must be 1..4096 bytes");
    const view = new Uint8Array(ARRAY_BUFFER.call(raw), BYTE_OFFSET.call(raw), length);
    bytes = Buffer.allocUnsafe(length);
    COPY_VIEW.call(bytes, view);
  } catch (error) {
    if (error instanceof ConsistencyVerificationError) throw error;
    throw new ConsistencyVerificationError("proof has an invalid or detached byte view");
  }
  let text;
  try {
    // ignoreBOM=true retains a BOM, allowing canonical comparison to reject it.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new ConsistencyVerificationError("proof is not strict UTF-8");
  }
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "{" || char === "[") {
      requireValue(++depth <= 2, "proof exceeds two container levels");
    } else if (char === "}" || char === "]") depth--;
    else if (char === "-" || (char >= "0" && char <= "9")) {
      if (char === "-") i++;
      const digits = i;
      while (text[i] >= "0" && text[i] <= "9") i++;
      requireValue(i - digits <= 6 && i > digits, "proof integer exceeds six digits");
      requireValue(text[i] !== "." && text[i] !== "e" && text[i] !== "E",
        "proof numbers must be plain integers");
      i--;
    }
  }
  let value;
  try { value = JSON.parse(text); }
  catch { throw new ConsistencyVerificationError("proof is not JSON"); }
  shape(value, PROOF_KEYS, "invalid consistency proof fields");
  requireValue(value.kind === "evidence-braid-ledger-consistency" && value.schema_version === "1.0",
    "unsupported consistency profile");
  requireValue(Array.isArray(value.path) && value.path.length <= 18, "invalid proof path size");
  for (const item of value.path) digest(item);
  header(value.old_commitment);
  header(value.new_commitment);
  // Also rejects duplicate keys, escapes, key order, whitespace, trailing bytes,
  // BOM, alternate number spellings and negative zero without a lossy rewrite.
  requireValue(canonical(value) === text, "proof is not canonical profile JSON");
  return value;
}

/** Verify canonical proof bytes against two separately established anchors.
 * Returns only frozen verified counts/digests; never chooses its own anchors.
 * The caller is responsible for authenticating the anchors and their meaning.
 */
export function verifyLedgerConsistency(raw, options) {
  shape(options, ["expectedNewCommitmentDigest", "expectedOldCommitmentDigest"],
    "two explicit expected commitment digests are required");
  const expectedOld = digest(options.expectedOldCommitmentDigest);
  const expectedNew = digest(options.expectedNewCommitmentDigest);
  const proof = admission(raw);
  const old = proof.old_commitment;
  const next = proof.new_commitment;
  requireValue(old.commitment_digest === expectedOld && next.commitment_digest === expectedNew,
    "proof commitments differ from expected anchors");
  requireValue(old.ledger_version === next.ledger_version && old.genesis === next.genesis,
    "ledger version/genesis mismatch");
  requireValue(old.entry_count <= next.entry_count, "entry-count rollback");
  if (old.entry_count === next.entry_count) {
    requireValue(proof.path.length === 0 && canonical(old) === canonical(next),
      "equal-size commitments must be identical with an empty path");
  } else if (old.entry_count === 0) {
    requireValue(proof.path.length === 0, "empty-prefix consistency needs an empty path");
  } else {
    // An iterative bit/index verifier, structurally distinct from the Python
    // producer/verifier's recursive paired-root reconstruction.
    let oldIndex = old.entry_count - 1;
    let newIndex = next.entry_count - 1;
    while ((oldIndex & 1) === 1) { oldIndex >>= 1; newIndex >>= 1; }
    let index = 0;
    let before = old.root_hash;
    if (oldIndex !== 0) {
      requireValue(proof.path.length > 0, "missing initial consistency subtree");
      before = proof.path[index++];
    }
    let after = before;
    for (; index < proof.path.length; index++) {
      requireValue(newIndex !== 0, "extra consistency path node");
      const sibling = proof.path[index];
      if ((oldIndex & 1) === 1 || oldIndex === newIndex) {
        before = join(sibling, before);
        after = join(sibling, after);
        while (oldIndex !== 0 && (oldIndex & 1) === 0) { oldIndex >>= 1; newIndex >>= 1; }
      } else after = join(after, sibling);
      oldIndex >>= 1;
      newIndex >>= 1;
    }
    requireValue(newIndex === 0 && before === old.root_hash && after === next.root_hash,
      "consistency path does not reproduce both committed roots");
  }
  return Object.freeze({ oldEntryCount: old.entry_count, newEntryCount: next.entry_count,
    oldCommitmentDigest: expectedOld, newCommitmentDigest: expectedNew });
}
