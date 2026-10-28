"""Regression tests for conservative SQL remediation behavior."""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "appsec_scanner"))
from scanner import SQLInjectionRule  # noqa: E402


class SQLRemediationTests(unittest.TestCase):
    def test_percent_format_finding_is_not_auto_remediable(self) -> None:
        source = 'query = "SELECT * FROM users WHERE id = %s" % user_id'
        rule = SQLInjectionRule()
        findings = rule.visit(ast.parse(source), "sample.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "percent-format")
        self.assertFalse(findings[0].remediable)
        self.assertIsNone(rule.remediate(source, findings[0]))

    def test_f_string_finding_is_not_auto_remediable(self) -> None:
        source = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = SQLInjectionRule().visit(ast.parse(source), "sample.py")

        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].remediable)


if __name__ == "__main__":
    unittest.main()
