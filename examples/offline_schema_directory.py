"""Publish a closed directory, relocate it and verify in another offline process."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from evidence_braid import export_schema_directory, load_schema_catalog


def main() -> None:
    # A receiver must select this digest independently. Loading our installed
    # catalog here demonstrates the API, not an independent trust channel.
    expected = load_schema_catalog().digest
    with TemporaryDirectory(prefix="evidence-schema-directory-example-") as directory:
        root = Path(directory)
        exported = export_schema_directory(root / "publication")
        moved = root / "relocated"
        exported.destination.rename(moved)
        code = """
import json, sys
from evidence_braid import verify_schema_directory
result = verify_schema_directory(sys.argv[1], expected_catalog_digest=sys.argv[2])
print(json.dumps(result.to_dict()))
"""
        process = subprocess.run(
            [sys.executable, "-I", "-c", code, str(moved), expected],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        checked = json.loads(process.stdout)
        assert checked == {**exported.to_dict(), "destination": str(moved)}
        print(
            json.dumps(
                {
                    **checked,
                    "relocated_process_verified": True,
                    "semantic_authorization_provided": False,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
