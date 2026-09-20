# Portable supported-case verification

`verify_supported_case_bundle` is a read-only assurance gate for one case inside
an existing [closed artifact ZIP](closed-artifacts.md). It checks the archived
case journal, exact assertion/input/output bytes, independent case authority,
current procedural approval and three externally retained heads. It does not
need the source case database or original attachment paths.

Run the installed offline example in normal or optimized mode:

```sh
python -m evidence_braid.examples.portable_case_bundle
python -O -m evidence_braid.examples.portable_case_bundle
```

The example creates a local durable case with a trusted fixture callback,
commits a checked `SUPPORTED` verdict, builds a **new** workflow context that
binds the case artifacts, obtains a separately authorized procedural approval,
moves the ZIP, deletes the DB/source files and verifies the archive. It performs
no provider call or download.

## Contract

```python
from evidence_braid import verify_supported_case_bundle

verified = verify_supported_case_bundle(
    "moved.zip",
    workflow_authority=trusted_workflow_policy,
    case_authority=trusted_case_policy,
    case_journal_artifact_id="journal-1",
    expected_workflow_head=retained_workflow_head,
    expected_evidence_head=retained_evidence_head,
    expected_case_head=retained_case_head,
    expected_bundle_digest=retained_bundle_digest,  # optional additional anchor
)
```

All policy and head values, plus the chosen journal artifact ID, must be
obtained independently of the archive. The journal reference uses media type
`application/vnd.evidence-braid.case-journal+json`. The supported profile is
exactly three receipts (plan, observed output, checked supported verdict), plus
four distinct bound objects: canonical journal, assertion, test input and
measured output. Every object is a regular content-addressed ZIP member under
the existing strict archive profile. The case plan's workflow, claim and scope
must match the replayed workflow; all four references must have been bound to
that claim before submission, and its **current** status must be `APPROVED`.
Revoked approval, refuted/inconclusive/missing observation or verdict, mismatched
bytes and stale anchors fail rather than returning a soft support label.

The verifier applies every existing ZIP, workflow, evidence and manifest
check while capturing the bounded case journal and payloads from the same open
archive. It recomputes the exact `sha256-equality-v1` comparison from retained
bytes, under the Stage B UTF-8/text and 64 KiB assertion / 256 KiB input /
4096-byte output / 512 KiB combined limits. The journal is capped at 2 MiB.
It extracts nothing, calls no adapter and writes nothing. The existing archive
wire, builder and `verify_artifact_bundle` API are unchanged.

## Trust limits

This checks a portable declared history and its actual archived bytes, not
that the callback truly ran, that a real-world assertion is true, or that actor
names identify real people. A separately retained case head pins the exported
case, not the latest SQLite operation head. `VerifiedSupportedCaseBundle` is
detached metadata; direct construction of the result type does not verify a
file. The archive discloses its full workflow and all bound object bytes, not
a redacted receipt. Case-store claim provenance, authorized case decisions,
cross-store/file atomicity, external signatures/witnesses, rollback protection,
live providers and whole-reference parity remain open.
