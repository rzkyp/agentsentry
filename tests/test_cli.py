import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agentsentry.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class CliTests(unittest.TestCase):
    def test_rules_lists_every_rule(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("EXF-001", buf.getvalue())
        self.assertIn("MCP-001", buf.getvalue())

    def test_json_scan_exit_code_1(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan", str(FIXTURES / "malicious-skill"), "--format", "json"])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertGreater(data["summary"]["findings"], 0)

    def test_clean_scan_exit_code_0(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan", str(FIXTURES / "clean-skill"), "--format", "json"])
        self.assertEqual(code, 0)

    def test_fail_on_none_always_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan", str(FIXTURES / "malicious-skill"), "--format", "json", "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_missing_path_is_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["scan", str(FIXTURES / "does-not-exist")])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
