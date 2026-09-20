import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def called_attributes(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
    }


class ActionBoundaryTests(unittest.TestCase):
    def test_http_routes_cannot_call_mutating_ha_api_directly(self):
        for filename in ("server.py", "admin.py", "access.py", "internal.py"):
            with self.subTest(filename=filename):
                self.assertNotIn(
                    "call_service",
                    called_attributes(ROOT / filename),
                )

    def test_admin_preview_action_executor_owns_its_mutating_ha_call(self):
        self.assertIn(
            "call_service",
            called_attributes(ROOT / "actions.py"),
        )


if __name__ == "__main__":
    unittest.main()
