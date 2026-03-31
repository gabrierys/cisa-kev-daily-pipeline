from __future__ import annotations

import json
import sys
from pathlib import Path


def strip_notebook(path: Path) -> bool:
    notebook = json.loads(path.read_text(encoding="utf-8"))
    changed = False

    for cell in notebook.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        if cell.get("outputs"):
            cell["outputs"] = []
            changed = True
        if cell.get("execution_count") is not None:
            cell["execution_count"] = None
            changed = True

    metadata = notebook.get("metadata", {})
    if isinstance(metadata, dict) and metadata.pop("widgets", None) is not None:
        changed = True

    if changed:
        path.write_text(json.dumps(notebook, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    return changed


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python3 scripts/strip_notebook_output.py <notebook.ipynb> [...]", file=sys.stderr)
        return 1

    changed_any = False
    for raw_path in argv[1:]:
        path = Path(raw_path)
        if path.suffix != ".ipynb" or not path.exists():
            continue
        changed_any = strip_notebook(path) or changed_any

    return 0 if changed_any or len(argv) > 1 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
