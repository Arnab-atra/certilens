"""Quick sanity test for the Rust bridge.

Run with: python -m certilens.tests_bridge
"""

import tempfile
from pathlib import Path

import certilens


def main() -> int:
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    doc = certilens.open_document(path)
    assert doc.format == "PDF", doc.format

    result = doc.verify()
    assert result.status_label == "Not yet verified", result.status_label

    print("Bridge OK:", doc, result)
    Path(path).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
