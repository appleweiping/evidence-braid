"""Export, relocate and independently reopen the packaged schema publication."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from evidence_braid import export_schemas, load_schema_catalog, schema_registry


def main() -> None:
    # In an exchange, choose this digest from a separately trusted publication.
    # Reading it here demonstrates the API, not an independent trust channel.
    catalog = load_schema_catalog()
    retained_digest = catalog.digest
    registry = schema_registry()
    assert len(registry) == 8
    with TemporaryDirectory(prefix="evidence-schemas-") as directory:
        root = Path(directory)
        exported = export_schemas(root / "original.zip")
        moved = root / "relocated.zip"
        exported.destination.rename(moved)
        code = """
import json, sys
from evidence_braid import verify_schema_archive
checked = verify_schema_archive(sys.argv[1], expected_catalog_digest=sys.argv[2])
print(json.dumps(checked.to_dict()))
"""
        process = subprocess.run(
            [sys.executable, "-I", "-c", code, str(moved), retained_digest],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        checked = json.loads(process.stdout)
        assert checked["archive_sha256"] == exported.archive_sha256
        print(
            json.dumps(
                {
                    "publication_line": catalog.to_dict()["publication_line"],
                    "public_schemas": sum(item.to_dict()["public"] for item in catalog.schemas),
                    "schema_resources": len(registry),
                    "catalog_digest": retained_digest,
                    "archive_sha256": exported.archive_sha256,
                    "archive_bytes": exported.size_bytes,
                    "relocated_process_verified": True,
                    "semantic_authorization_provided": False,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
