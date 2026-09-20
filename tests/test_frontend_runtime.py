import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrontendRuntimeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is required")
    def test_reset_and_visibility_behavior(self):
        result = subprocess.run(
            ["node", str(ROOT / "tests" / "frontend_runtime.cjs")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
