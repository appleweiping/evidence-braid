"""Independent Python binary64 oracle; the JavaScript formatter never calls Python."""

from __future__ import annotations

import json
import math
import os
import random
import shutil
import struct
import subprocess
from pathlib import Path

import pytest


def test_exact_receipt_float_formatter_against_binary64_neighbors_and_seeded_bits():
    node = shutil.which("node")
    if node is None and os.environ.get("EVIDENCE_REQUIRE_NODE") == "1":
        pytest.fail("Node is required by the independent-verifier CI gate")
    if node is None:
        pytest.skip("Node.js is optional for Python-only installations")
    values = {0, 1, (1 << 52) - 1, 1 << 52, 0x7FEFFFFFFFFFFFFF}
    for exponent in range(1, 2047):
        bits = exponent << 52
        values.update((bits - 1, bits, bits + 1))
    for exponent in range(-323, 309):
        value = float(f"1e{exponent}")
        bits = struct.unpack(">Q", struct.pack(">d", value))[0]
        values.update((bits - 1, bits, bits + 1))
    rng = random.Random(821964)
    values.update(rng.getrandbits(63) for _ in range(2048))
    cases = []
    for bits in sorted(values):
        for encoded in (bits, bits | (1 << 63)):
            value = struct.unpack(">d", struct.pack(">Q", encoded))[0]
            if math.isfinite(value):
                cases.append([f"{encoded:016x}", repr(value)])
    module = (Path(__file__).resolve().parents[1] / "verification/receipt-numbers.mjs").as_uri()
    script = f"""
import {{ canonicalFloat, verifyFloatToken }} from {json.dumps(module)};
let input = '';
for await (const chunk of process.stdin) input += chunk;
const cases = JSON.parse(input);
const failures = [];
for (const [bits, expected] of cases) {{
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt('0x' + bits));
  const actual = canonicalFloat(view.getFloat64(0));
  if (actual !== expected) failures.push({{bits, actual, expected}});
  else if (verifyFloatToken(expected) !== expected) failures.push({{bits, token:true}});
}}
process.stdout.write(JSON.stringify({{count:cases.length, failures}}));
"""
    completed = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(cases),
        encoding="utf-8",
        capture_output=True,
        timeout=180,
        check=True,
    )
    assert completed.stderr == ""
    result = json.loads(completed.stdout)
    assert result["count"] == len(cases) and len(cases) > 19000
    assert result["failures"] == []
