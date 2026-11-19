import json
import unittest
from pathlib import Path

from agentsentry.report import render_json
from agentsentry.scanner import scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class MaliciousSkillTests(unittest.TestCase):
    def test_triggers_expected_rules(self):
        result = scan(FIXTURES / "malicious-skill")
        ids = {f.rule_id for f in result.findings}
        expected = {
            "INJ-001",
            "EXF-001",
            "EXEC-001",
            "EXEC-002",
            "EXEC-003",
            "OBF-001",
            "DESTR-001",
            "PERSIST-001",
            "CRED-001",
            "SCAN-001",
            "SKILL-001",
            "SEC-001",
        }
        missing = expected - ids
        self.assertFalse(missing, f"missing rules: {missing}")

    def test_has_critical_findings(self):
        result = scan(FIXTURES / "malicious-skill")
        self.assertTrue(any(f.severity == "CRITICAL" for f in result.findings))

    def test_lines_and_snippets_are_reported(self):
        result = scan(FIXTURES / "malicious-skill")
        self.assertTrue(result.findings)
        for finding in result.findings:
            self.assertGreaterEqual(finding.line, 1)
            self.assertTrue(finding.snippet)


class MaliciousMcpTests(unittest.TestCase):
    def test_triggers_expected_rules(self):
        result = scan(FIXTURES / "malicious-mcp")
        ids = {f.rule_id for f in result.findings}
        expected = {"MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-006", "SEC-001", "NET-001"}
        missing = expected - ids
        self.assertFalse(missing, f"missing rules: {missing}")


class CleanFixtureTests(unittest.TestCase):
    def test_clean_skill_has_no_findings(self):
        result = scan(FIXTURES / "clean-skill")
        self.assertEqual(result.findings, [], result.findings)

    def test_clean_mcp_has_no_findings(self):
        result = scan(FIXTURES / "clean-mcp")
        self.assertEqual(result.findings, [], result.findings)


class ReportTests(unittest.TestCase):
    def test_json_shape(self):
        result = scan(FIXTURES / "malicious-skill")
        data = json.loads(render_json(result))
        self.assertEqual(data["schema"], "agentsentry/report/1")
        self.assertEqual(len(data["findings"]), len(result.findings))
        self.assertGreaterEqual(data["summary"]["by_severity"]["CRITICAL"], 1)


if __name__ == "__main__":
    unittest.main()
