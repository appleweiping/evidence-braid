# Atomic offline schema directories

`export_schema_directory(path)` publishes the **same ten resources and `wire-1` bytes** as
the [existing canonical ZIP](offline-schemas.md). It does not replace the ZIP API, change the
catalog digest or create a new publication line. `verify_schema_directory` compares the complete
closed directory with that installed publication and requires an explicitly supplied catalog digest.
This is not an arbitrary schema-directory import or an authorization verdict.

```python
from evidence_braid import export_schema_directory, verify_schema_directory

exported = export_schema_directory("schemas")  # Parent must already exist; target must not exist.
checked = verify_schema_directory(
    exported.destination,
    expected_catalog_digest=exported.catalog_digest,
)
assert checked == exported
```

In a real exchange, select the expected catalog digest from a separately trusted source; copying
the export's own digest is only an API demonstration. SHA-256 identifies the bytes, not an
authenticated publisher. Directory metadata objects are immutable output descriptions, not proof
certificates when manually constructed.

```text
schemas/
└── wire-1/
    ├── catalog.json
    ├── SHA256SUMS
    ├── common.schema.json
    └── seven public *.schema.json resources
```

The published files total 26,961 bytes. `SchemaDirectoryExport.to_dict()` reports the absolute
destination, publication line, catalog digest, `resource_count=10` and total resource `size_bytes`.
There is no invented directory/archive hash: the catalog and exact checksum inventory already
bind the closed set, and directory placement is separate from those identities.

## Atomic visibility and no replacement

The destination's immediate parent must be an existing ordinary directory. No ancestors are
created. The operation binds its path to an absolute path before any work that could change the
process working directory. It reserves explicit tracking records before creating an unpredictable
same-parent staging directory, creates only its `wire-1` child and fixed files, and opens each file
exclusively. POSIX directory/file mode requests are `0700`/`0600`; actual access policy also depends
on the platform, inherited Windows ACLs and the caller's trusted parent directory.

Each write is unbuffered, checked for short writes and followed by `fsync` before its descriptor is
closed. Thus no Python buffered data remains to flush. The independent complete-directory verifier
then checks the staged tree. The destination becomes visible through one native operation:

- Windows: `os.rename`, whose Windows contract rejects every existing destination, including an
  empty directory. See [Python's rename contract](https://docs.python.org/3/library/os.html#os.rename).
- Linux: the native C-library `renameat2` entry point with `RENAME_NOREPLACE`. The flag requires
  underlying filesystem support; see [the Linux interface](https://man7.org/linux/man-pages/man2/rename.2.html).

Missing native symbols, unsupported operating systems or filesystems, cross-device errors and
existing targets fail closed. There is no plain Unix rename, delete-first, merge, recursive-copy
or overwrite fallback. Concurrent cooperating publishers compete at the native operation; one can
win a previously absent destination. A successful export never removes that published destination.

This guarantees atomic namespace visibility where the selected native operation succeeds, not
directory-metadata durability across power loss. Files are fsynced; parent directory metadata is
not promised durable. A crash before publication can leave a staging directory. There is no
background sweeper, recovery daemon or implicit removal of old directories.

## Cleanup and acknowledgement

Prepublication cleanup attempts only the explicitly tracked paths whose observed device/inode,
ordinary-file/directory type and complete tracked parent chain still match. It uses individual
`unlink` and empty-directory `rmdir`, never recursive deletion. New unknown files, replaced entries,
changed staging parents, or creation whose identity could not be captured are retained and reported
instead of guessed to be safe. An unknown file prevents removal of its containing directory.
Earlier control exceptions retain precedence over ordinary cleanup failures, and remaining owned
resources still receive cleanup attempts. An ordinary failure followed by a new control exception
propagates the control exception. Descriptor-close failures prevent successful verification or
publication acknowledgement; no hard guarantee is made about a native close that itself fails.

`SchemaDirectoryPublicationError` exposes `destination`, `staging_path` and `publication_state`:

| State | Meaning |
|---|---|
| `unpublished` | Publication was not attempted, or the original staging inode was still observed at its old name after the failed attempt. |
| `published` | Native rename acknowledged success, or the staged inode was observed only at the destination after an interrupted acknowledgement. |
| `unknown` | The native operation or subsequent observation failed and neither state could be established safely. |

Controls such as `KeyboardInterrupt` and `SystemExit` propagate as the same exception object with
an acknowledgement note, rather than being converted into ordinary errors. A `published` or
`unknown` error is not permission to retry destructively. Inspect the destination with the separately
retained digest and examine the reported staging path. Failure to print the CLI report after a
successful export explicitly reports that publication already occurred. None of these outcomes
authorizes automatic deletion of the destination or unknown residue.

## Strict bounded verification

The verifier demands exactly one root entry named `wire-1`, then exactly the ten fixed file names.
Both enumerations are incremental: at most one extra entry is consumed before rejection, not an
unbounded `listdir`. Root, version directory and files must be ordinary, non-symlink, non-reparse
objects with usable file identity. A directory masquerading as a file is refused. On systems that
provide them, `O_NOFOLLOW` and `O_NONBLOCK` supplement observed-path checks during file opening.

Each source size must exactly match the known resource before reading. One descriptor is used to
bind the observed device/inode, size and timestamps, read at most `expected_size + 1` bytes, compare
every byte with the pinned publication, and recheck the opened object and named path. Previously
checked files and both inventories are rechecked at the end. Per-file reads stay within 64 KiB
plus one byte, and the complete resource total within 256 KiB. The catalog and checksum inventory
also have their tighter installed-publication bounds (8 KiB and 4 KiB).

Windows `lstat` and `fstat` can expose different meanings for `ctime`. Cross-API binding therefore
uses compatible device/inode, size, modification time and available Windows birth time; before/after
checks within each API retain its own `ctime`. Unix also compares compatible cross-API `ctime`.
This prevents ordinary newly written Windows files from being mistaken for changed files without
discarding each observer's change checks.

These bounds concern enumerated entries, resource bytes and retained metadata, not process RSS or
hard real-time native I/O. The implementation materializes the bounded installed publication. The
immediate parent and named tree are checked, but arbitrary ancestors and the filesystem itself are
trusted. Check/open/unlink/rename observations do not constitute a hostile same-user filesystem
sandbox or an atomic immutable read snapshot. Concurrent adversarial mutation, filesystem-specific
cache behavior and modification after return are outside that guarantee. Returned directories
remain owner-writable; verification does not install access controls or freeze them forever.

## CLI and offline example

```bash
evidence-braid schema export-directory schemas
evidence-braid schema verify-directory schemas --expected-catalog-digest <trusted-digest>
python examples/offline_schema_directory.py
```

The example publishes and relocates a real directory, then verifies it in a fresh isolated Python
process outside the checkout. It requires no network or runtime dependency. The existing ZIP,
JSON Schema registry, golden resource bytes and semantic-verification exclusions remain unchanged.
Native replay/proof checks are still required; broader schema lines, migration, signed publication
and whole-reference repository parity remain open.
