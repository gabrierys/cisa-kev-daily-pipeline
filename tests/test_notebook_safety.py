from __future__ import annotations

import json
import unittest
from pathlib import Path


class NotebookSafetyTests(unittest.TestCase):
    def test_notebook_has_no_saved_outputs(self) -> None:
        notebook = json.loads(Path("kev_pipeline_analysis.ipynb").read_text(encoding="utf-8"))

        for cell in notebook.get("cells", []):
            if cell.get("cell_type") != "code":
                continue
            self.assertEqual(cell.get("outputs", []), [])
            self.assertIsNone(cell.get("execution_count"))

    def test_notebook_does_not_embed_local_absolute_paths(self) -> None:
        content = Path("kev_pipeline_analysis.ipynb").read_text(encoding="utf-8")
        self.assertNotIn("/Users/", content)
        self.assertNotIn("\\\\Users\\\\", content)


if __name__ == "__main__":
    unittest.main()
