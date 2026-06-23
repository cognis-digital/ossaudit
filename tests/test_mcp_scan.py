"""The MCP scan wrapper audits a manifest and returns the report dict.

Importing ossaudit.mcp_server must NOT require the optional cognis_core extra
(only building the live server does). No network.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "deps.json")


class TestMcpScan(unittest.TestCase):
    def test_import_does_not_require_cognis_core(self):
        import ossaudit.mcp_server as m  # must import cleanly
        self.assertTrue(hasattr(m, "scan"))
        self.assertTrue(hasattr(m, "run_mcp_server"))

    def test_scan_returns_report_dict(self):
        from ossaudit.mcp_server import scan
        report = scan(DEMO, policy="proprietary")
        self.assertIsInstance(report, dict)
        self.assertEqual(report["policy"], "proprietary")
        self.assertEqual(report["total"], 8)
        self.assertEqual(report["violations"], 4)
        self.assertFalse(report["passed"])

    def test_scan_accepts_parsed_object(self):
        from ossaudit.mcp_server import scan
        report = scan([{"name": "x", "version": "1", "license": "AGPL-3.0-only"}],
                      policy="proprietary")
        self.assertEqual(report["violations"], 1)

    def test_scan_clean_passes(self):
        from ossaudit.mcp_server import scan
        report = scan([{"name": "x", "version": "1", "license": "MIT"}],
                      policy="proprietary")
        self.assertTrue(report["passed"])


if __name__ == "__main__":
    unittest.main()
