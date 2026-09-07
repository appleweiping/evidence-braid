# Closed content-addressed artifact bundles

A workflow's `ArtifactReference` commits to bytes but does not make those bytes
available. `build_artifact_bundle` closes that gap: one independently verifiable
archive includes the evidence/workflow receipts, the recomputed claim state and
every committed artifact's actual contents. Verification needs neither the
original source paths nor the builder's process.

This is an original, restrictive ZIP profile, not an implementation of another
project's directory layout or wire protocol. It adds no runtime dependency.

## Offline example

```sh
python examples/closed_artifacts.py
```

The example creates a real attachment and a claim reviewed by a distinct actor,
builds the archive, deletes the source attachment, moves the archive, and checks
every byte and the replayed state. Its temporary files are removed afterward.
There are no downloaded inputs or network calls.

```python
from evidence_braid import build_artifact_bundle, verify_artifact_bundle

# workflow and authority are your existing typed workflow and trusted policy.
built = build_artifact_bundle(
    "new-archive.zip",
    workflow,
    {"bench-result": "reviewed-notes.txt"},
    authority=authority,
)
verified = verify_artifact_bundle(
    "new-archive.zip",
    authority=authority,
    expected_head=workflow.head_digest,
    expected_evidence_head=workflow.evidence.head_digest,
    expected_bundle_digest=built.bundle_digest,
)
assert verified.state == built.state
```

In a real exchange the recipient must obtain the authority policy and expected
heads from a **separately trusted channel**, not copy them out of the unverified
archive. The two head arguments are mandatory; the closed-bundle digest is an
optional additional anchor. `VerifiedArtifactBundle` is detached immutable
metadata, not an open handle. Directly constructing a result object checks its
derived field consistency, not file contents or actor authorization; only the
verification operation performs those checks.

## On-disk contract

An archive contains these entries in exactly this order:

```text
manifest.json
workflow.json
state.json
objects/<lowercase SHA-256>
objects/<lowercase SHA-256> ...  # lexicographic digest order
```

There are no directory entries. Artifact IDs are identifiers only, never paths.
Every workflow artifact ID has one source mapping supplied to the builder and
one manifest binding to its content-addressed object. Multiple references can
share one object when both digest and size agree. Even a deduplicated source is
read and verified independently: a correct first source does not excuse an
incorrect second mapping. Unreferenced sources/objects, missing references,
conflicting sizes and additional archive entries fail closed. An empty artifact
inventory has just the three metadata entries.

`workflow.json` embeds the existing workflow envelope, including evidence,
authority digest, artifact commitments, transition receipts and heads. Its
schema is not weakened. `state.json` is the complete deterministic procedural
state from [authorized replay](authority-workflows.md), not a cached state that
the reader trusts. The manifest inventories exact metadata/object sizes and
SHA-256 digests, repeats artifact scope/claim/media bindings, and includes a
content-derived `bundle_digest` computed over the manifest without that field.
The manifest does not inventory its own bytes recursively.

All metadata must be exact compact UTF-8 canonical JSON using the project's
sorted-key Python encoding (not a claim of RFC 8785 or cross-language numeric
conformance). Duplicate keys, non-finite/overflowed numeric values, unknown or
modified fields, and noncanonical whitespace/number spellings are rejected.
Boolean spellings cannot substitute for numerically equal integer fields.

## Deliberately restricted ZIP32 profile

This format uses the standard ZIP structures described by the primary
[PKWARE application note](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
and Python's [ZIP API](https://docs.python.org/3/library/zipfile.html), with a
small supported subset:

- Single-disk ZIP32, version 2.0, STORED members only; no compression, encryption,
  ZIP64, streaming data descriptors, extra fields, comments or trailing bytes.
- Fixed ASCII names above, no duplicates or aliases, contiguous local entries
  beginning at offset zero and a contiguous central directory at the end.
- Local and central names, sizes, CRCs and headers must agree. Entries have
  canonical Unix regular-file mode `0600`, internal attributes zero and fixed
  1980-01-01 timestamps. Those timestamps are format determinism, not source
  creation times. Symlink, directory and special-file entries are forbidden.

Before constructing Python `ZipFile` objects, the reader bounds the actual
archive length, reads only the fixed 22-byte end record, checks entry count,
central-directory length and offsets, and then reads the bounded directory.
Every central/local header and bounded name is checked before `ZipFile` can
materialize its entry objects. A cached immutable copy of the validated central
directory/end record is served to `ZipFile`; a changed end record cannot make
the later metadata read unbounded. Artifact payloads remain streamed from the
same opened file. CRC checks and independent SHA-256 checks both run.

No archive entry is extracted, executed, rendered or treated as an external path.
The reader is not a general-purpose ZIP compatibility layer. A generic tool that
recompresses the archive, changes member times/permissions, or appends a comment
can produce a valid general ZIP that this profile intentionally refuses.

## Resource and performance bounds

`ArtifactBundleLimits` can tighten these defaults but cannot exceed their
compiled ceilings. Each setting is a positive integer; booleans are rejected.

| Boundary | Default/ceiling |
| --- | ---: |
| Artifact references | 1,024 |
| One object/source | 64 MiB |
| Unique object bytes | 512 MiB |
| Source bytes including duplicate mappings | 512 MiB |
| Manifest | 4 MiB |
| Workflow metadata | 64 MiB |
| Replayed state metadata | 64 MiB |
| Central directory | 256 KiB |
| Entire archive | 1 GiB |

The entry ceiling is artifact-reference limit plus three. Artifact source files
must match their declared size before copying and their digest afterward; they
are copied/read in chunks of at most 1 MiB. The builder calculates the exact
canonical output size before staging, so archive and directory limits also
apply before writing. Source paths and mapping membership are snapshotted before
I/O; later caller mapping changes or working-directory changes do not retarget
the inputs. Final-component symbolic links and nonregular files are refused.

Verification is linear in unique object bytes plus workflow replay and metadata
processing. Construction reads every supplied source (including duplicates),
then reads each unique stored object again during independent prepublication
verification. Workflows and JSON metadata are materialized; their object graphs,
canonical serialization copies and replay state can require substantially more
memory than serialized byte counts. Python API metadata size checks occur after
serialization; file metadata lengths are bounded before reading/parsing.
**These are input/output/work limits, not a process-RSS or hard runtime sandbox.**

File size, modification time, device and inode are compared around copying and
verification. Observed source/archive changes fail. Digest checks enforce the
committed contents even when size alone agrees. These checks do not make mutable
filesystems immutable, authenticate a producer, or defend against every hostile
ancestor-link/filesystem race. Do not modify inputs concurrently. Keep the
archive and separately trusted anchors after verification if later use matters.

## Publication and failure behavior

The destination's parent must exist. A same-directory staging file is fully
written, independently reopened and verified before publication. The private
publication helper flushes, fsyncs and closes it, then atomically creates a hard
link at the destination. Existing destinations, including a concurrent winner,
are never overwritten. Filesystems without the required hard-link capability
fail closed; there is no unsafe check-then-rename fallback. No administrator
privilege is required on a supporting filesystem.

Failure before publication leaves the destination absent or unchanged and
attempts to remove staging. Ordinary cleanup errors do not replace an active
validation error or genuine interrupt; they add diagnostic context. Genuine
interrupts during cleanup are not silently ignored. If final staging unlink
fails after the hard link succeeded, the error explicitly says the output was
published: inspect that result instead of blindly retrying. This is atomic
visibility with file-content fsync, **not** directory-metadata power-loss
durability or a distributed transaction.

## CLI

```sh
evidence-braid artifact-bundle create trusted-authority.json new.zip \
  --workflow workflow.json --artifact bench-result=reviewed-notes.txt \
  --expected-head WORKFLOW_SHA256 --expected-evidence-head EVIDENCE_SHA256

evidence-braid artifact-bundle verify trusted-authority.json new.zip \
  --expected-head WORKFLOW_SHA256 --expected-evidence-head EVIDENCE_SHA256 \
  --expected-bundle-digest BUNDLE_SHA256
```

Replace the placeholder anchors with your independently retained values. Creation
requires exactly one `--artifact ID=FILE` per reference; duplicate mappings fail.
Both commands print verified summary/state JSON to stdout. There is no report
file option that could accidentally overwrite the archive or authority file.

## Assurance, privacy and open work

A passing archive agrees internally with the supplied authority and anchors.
It does not prove the observations true, the actors authenticated, or the policy
correct. Procedural approval is not a truth label. There is no signature,
encryption, secret scanning or redaction. Every explicitly mapped file becomes
available to anyone with the archive; inspect attachments before sharing. Only
declared mappings are copied, and original source paths are not inventoried.

Remaining work includes signatures/witnesses, authenticated custody, external
artifact stores, independent non-Python verification, richer epistemic receipt
formats and service workflows. This feature closes a bounded local artifact
availability/integrity gap, not the whole repository's parity objective.
