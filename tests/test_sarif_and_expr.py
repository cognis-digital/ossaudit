"""Tests for SARIF 2.1.0 export, the SPDX expression parser, and the
expanded license knowledge base. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ossaudit.core import (  # noqa: E402
    audit_dependencies,
    classify_license,
    load_dependencies,
    normalize_license_id,
    to_sarif,
)
from ossaudit.cli import main  # noqa: E402

DEMOS = os.path.join(os.path.dirname(__file__), "..", "demos")


def _demo(name, fname="deps.json"):
    return os.path.join(DEMOS, name, fname)


class TestExpressionParser(unittest.TestCase):
    def test_or_picks_least_severe(self):
        self.assertEqual(normalize_license_id("MIT OR Apache-2.0"), "MIT")
        self.assertEqual(
            normalize_license_id("LGPL-3.0-only OR GPL-3.0-only OR Commercial"),
            "LGPL-3.0-only",
        )

    def test_and_picks_most_severe(self):
        self.assertEqual(
            normalize_license_id("MIT AND GPL-3.0-only"), "GPL-3.0-only"
        )

    def test_nested_parens_and_precedence(self):
        # The historical bug: this used to mis-resolve to MIT. AND is binding.
        self.assertEqual(
            normalize_license_id("(MIT OR Apache-2.0) AND GPL-2.0-or-later"),
            "GPL-2.0-or-later",
        )

    def test_outer_parens_stripped_safely(self):
        self.assertEqual(normalize_license_id("(MIT OR GPL-3.0-only)"), "MIT")
        # Multiple permissive operands AND-joined stay permissive.
        self.assertEqual(
            classify_license(normalize_license_id("ISC AND MIT AND OpenSSL")),
            "permissive",
        )


class TestExpandedLicenseKB(unittest.TestCase):
    def test_real_uncommon_licenses(self):
        self.assertEqual(classify_license(normalize_license_id("FTL")), "permissive")
        self.assertEqual(
            classify_license(normalize_license_id("blessing")), "public-domain"
        )
        self.assertEqual(
            classify_license(normalize_license_id("CC-BY-4.0")), "permissive"
        )
        self.assertEqual(
            classify_license(normalize_license_id("CC-BY-SA-4.0")), "weak-copyleft"
        )
        self.assertEqual(
            classify_license(normalize_license_id("BSL-1.0")), "permissive"
        )
        self.assertEqual(
            classify_license(normalize_license_id("Elastic-2.0")), "proprietary"
        )


class TestSarif(unittest.TestCase):
    def setUp(self):
        deps = load_dependencies(_demo("01-basic"))
        self.report = audit_dependencies(deps, policy="proprietary")
        self.sarif = to_sarif(self.report, manifest_path="demos/01-basic/deps.json")

    def test_top_level_shape(self):
        self.assertEqual(self.sarif["version"], "2.1.0")
        self.assertIn("$schema", self.sarif)
        self.assertEqual(len(self.sarif["runs"]), 1)

    def test_driver_identity(self):
        driver = self.sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "ossaudit")
        self.assertTrue(driver["version"])
        self.assertTrue(driver["rules"])

    def test_results_and_levels(self):
        results = self.sarif["runs"][0]["results"]
        self.assertEqual(len(results), self.report.total)
        # Violations in 01-basic: AGPL, SSPL (network) + GPL (strong) => error.
        errors = [r for r in results if r["level"] == "error"]
        self.assertEqual(len(errors), 3)
        # Every result anchors to the manifest artifact.
        for r in results:
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertEqual(uri, "demos/01-basic/deps.json")
            self.assertIn("spdxId", r["properties"])

    def test_rules_referenced_by_results(self):
        run = self.sarif["runs"][0]
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for r in run["results"]:
            self.assertIn(r["ruleId"], rule_ids)

    def test_serializable(self):
        # Must round-trip through json without error.
        json.loads(json.dumps(self.sarif))


class TestSarifCli(unittest.TestCase):
    def test_sarif_format_exit_code(self):
        # Audit still returns 2 on violations even in sarif mode.
        rc = main(["--format", "sarif", "audit", _demo("01-basic"),
                   "--policy", "proprietary"])
        self.assertEqual(rc, 2)

    def test_sarif_format_clean_pass(self):
        rc = main(["--format", "sarif", "audit",
                   _demo("10-internal-tool-audit"), "--policy", "proprietary"])
        self.assertEqual(rc, 0)


class TestNewDemosFire(unittest.TestCase):
    """Every shipped demo must actually load and audit cleanly."""

    CASES = [
        ("01-agpl-contamination", "licenses.json", "proprietary", False),
        ("02-clean-license", "licenses.json", "proprietary", True),
        ("03-busl-and-mixed", "licenses.json", "proprietary", False),
        ("04-saas-agpl-database", "deps.json", "proprietary", False),
        ("05-mobile-app-store", "deps.json", "distribute-binary", False),
        ("06-permissive-only-relicense", "deps.json", "proprietary", True),
        ("07-weak-copyleft-lgpl", "deps.json", "proprietary", True),
        ("08-gpl-oss-project", "deps.json", "gpl-project", False),
        ("09-dual-license-spdx", "deps.json", "proprietary", False),
        ("10-internal-tool-audit", "deps.json", "proprietary", True),
    ]

    def test_each_demo_matches_expectation(self):
        for name, fname, policy, should_pass in self.CASES:
            with self.subTest(demo=name):
                deps = load_dependencies(_demo(name, fname))
                self.assertTrue(deps, f"{name} loaded zero deps")
                report = audit_dependencies(deps, policy=policy)
                self.assertEqual(
                    report.passed, should_pass,
                    f"{name} expected passed={should_pass}, got {report.passed}",
                )


if __name__ == "__main__":
    unittest.main()
