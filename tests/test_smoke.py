"""Smoke tests for OSSAUDIT. Standard library only, no network."""
import io
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ossaudit import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    classify_license,
    normalize_license_id,
    audit_dependencies,
    load_dependencies,
    generate_notice,
)
from ossaudit.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "deps.json")


class TestNormalize(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(normalize_license_id("Apache 2.0"), "Apache-2.0")
        self.assertEqual(normalize_license_id("BSD"), "BSD-3-Clause")
        self.assertEqual(normalize_license_id("the MIT License"), "MIT")
        self.assertEqual(normalize_license_id("AGPLv3"), "AGPL-3.0-only")

    def test_unknown_and_empty(self):
        self.assertEqual(normalize_license_id(""), "NOASSERTION")
        self.assertEqual(normalize_license_id(None), "NOASSERTION")
        self.assertEqual(normalize_license_id("custom blah"), "NOASSERTION")

    def test_spdx_or_picks_permissive(self):
        # OR => consumer picks the least restrictive operand.
        self.assertEqual(normalize_license_id("MIT OR GPL-3.0-only"), "MIT")
        self.assertEqual(normalize_license_id("GPL-3.0-only OR Apache-2.0"), "Apache-2.0")

    def test_spdx_and_picks_restrictive(self):
        self.assertEqual(normalize_license_id("MIT AND GPL-3.0-only"), "GPL-3.0-only")


class TestClassify(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(classify_license("MIT"), "permissive")
        self.assertEqual(classify_license("LGPL-3.0-only"), "weak-copyleft")
        self.assertEqual(classify_license("GPL-3.0-only"), "strong-copyleft")
        self.assertEqual(classify_license("AGPL-3.0-only"), "network-copyleft")
        self.assertEqual(classify_license("SSPL-1.0"), "network-copyleft")
        self.assertEqual(classify_license("NOASSERTION"), "unknown")


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.deps = load_dependencies(DEMO)

    def test_proprietary_fails_on_copyleft(self):
        report = audit_dependencies(self.deps, policy="proprietary")
        self.assertFalse(report.passed)
        # AGPL, SSPL, GPL, and unknown => 4 violations.
        self.assertEqual(report.violations, 4)
        by_name = {f.name: f for f in report.findings}
        self.assertEqual(by_name["analytics-sdk"].status, "violation")
        self.assertEqual(by_name["analytics-sdk"].category, "network-copyleft")
        self.assertEqual(by_name["requests"].status, "ok")
        # crossbeam's MIT OR Apache-2.0 normalizes to a permissive id.
        self.assertEqual(by_name["crossbeam"].status, "ok")

    def test_gpl_policy_allows_gpl(self):
        report = audit_dependencies(self.deps, policy="gpl-project")
        by_name = {f.name: f for f in report.findings}
        self.assertEqual(by_name["chart-lib"].status, "ok")
        # AGPL/SSPL/unknown still fail.
        self.assertEqual(by_name["analytics-sdk"].status, "violation")
        self.assertEqual(report.violations, 3)

    def test_findings_sorted_worst_first(self):
        report = audit_dependencies(self.deps, policy="proprietary")
        sevs = [f.severity for f in report.findings]
        self.assertEqual(sevs, sorted(sevs, reverse=True))

    def test_bad_policy_raises(self):
        with self.assertRaises(ValueError):
            audit_dependencies(self.deps, policy="nonsense")


class TestNotice(unittest.TestCase):
    def test_notice_contains_all_deps(self):
        deps = load_dependencies(DEMO)
        text = generate_notice(deps, project="Acme Cloud")
        self.assertIn("Acme Cloud", text)
        for d in deps:
            self.assertIn(d.name, text)
        self.assertIn("Licenses present:", text)


class TestCli(unittest.TestCase):
    def test_audit_exit_code_violations(self):
        rc = main(["audit", DEMO, "--policy", "proprietary"])
        self.assertEqual(rc, 2)

    def test_audit_json_ok_exit(self):
        rc = main(["--format", "json", "audit", DEMO, "--policy", "permissive-audit"])
        self.assertEqual(rc, 0)

    def test_missing_file_exit_error(self):
        rc = main(["audit", "does-not-exist.json"])
        self.assertEqual(rc, 1)

    def test_notice_runs(self):
        rc = main(["notice", DEMO, "--project", "X"])
        self.assertEqual(rc, 0)

    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "ossaudit")
        self.assertTrue(TOOL_VERSION)


class TestHardening(unittest.TestCase):
    """Edge-case and error-path tests added during hardening."""

    # --- load_dependencies edge cases ---

    def test_load_empty_list(self):
        """An empty manifest list should return an empty deps list, not raise."""
        deps = load_dependencies([])
        self.assertEqual(deps, [])

    def test_load_pathlib_path(self):
        """load_dependencies should accept a pathlib.Path, not just str."""
        deps = load_dependencies(pathlib.Path(DEMO))
        self.assertGreater(len(deps), 0)

    def test_load_invalid_type_raises(self):
        """Passing an unexpected type (e.g. int) must raise ValueError."""
        with self.assertRaises(ValueError):
            load_dependencies(42)

    def test_load_malformed_json_exit_error(self):
        """A file containing invalid JSON should produce exit code 1 with no traceback."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            fh.write("{ this is not json }")
            bad_path = fh.name
        try:
            rc = main(["audit", bad_path])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(bad_path)

    # --- CLI I/O error paths ---

    def test_permission_error_exit_code(self):
        """Passing a directory as manifest (PermissionError / IsADirectoryError)
        must return exit 1 and print a clean error, not raise."""
        # Use the tests directory itself — guaranteed to exist and not be JSON.
        tests_dir = os.path.dirname(__file__)
        stderr_buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr_buf
        try:
            rc = main(["audit", tests_dir])
        finally:
            sys.stderr = old_stderr
        self.assertEqual(rc, 1)
        # Should have printed something useful to stderr.
        self.assertTrue(stderr_buf.getvalue().strip())

    def test_notice_output_bad_dir_exit_error(self):
        """--output pointing at a non-existent directory returns exit 1 cleanly."""
        bad_output = os.path.join(
            "definitely-does-not-exist-dir", "NOTICE.txt"
        )
        stderr_buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr_buf
        try:
            rc = main(["notice", DEMO, "--output", bad_output])
        finally:
            sys.stderr = old_stderr
        self.assertEqual(rc, 1)
        self.assertTrue(stderr_buf.getvalue().strip())

    # --- audit on empty deps ---

    def test_audit_empty_deps_passes(self):
        """Auditing an empty dependency list should pass with zero violations."""
        report = audit_dependencies([], policy="proprietary")
        self.assertTrue(report.passed)
        self.assertEqual(report.total, 0)
        self.assertEqual(report.violations, 0)

    def test_notice_empty_deps(self):
        """generate_notice on an empty list should produce valid output."""
        text = generate_notice([], project="Empty Project")
        self.assertIn("Empty Project", text)
        self.assertIn("Licenses present:", text)


if __name__ == "__main__":
    unittest.main()
