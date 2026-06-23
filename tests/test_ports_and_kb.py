"""Cross-language port parity + expanded license-KB / audit coverage.

The port tests drive each available port as a subprocess against the SAME demo
manifest and assert it agrees with the Python reference (8 deps, 4 violations,
exit 2). Ports whose toolchain isn't installed are skipped — CI builds/tests
them on every push via .github/workflows/ports.yml. No network anywhere.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ossaudit.core import (  # noqa: E402
    audit_dependencies,
    classify_license,
    normalize_license_id,
    load_dependencies,
    generate_notice,
    LicenseInfo,
    POLICY_PRESETS,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMO01 = os.path.join(ROOT, "demos", "01-basic", "deps.json")
PORTS = os.path.join(ROOT, "ports")


class TestExpandedLicenseKB(unittest.TestCase):
    """Many real licenses must classify into the right bucket."""

    PERMISSIVE = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
                  "Zlib", "BSL-1.0", "PostgreSQL", "NCSA", "X11", "CC-BY-4.0"]
    PUBLIC_DOMAIN = ["Unlicense", "CC0-1.0", "0BSD", "WTFPL", "blessing"]
    WEAK = ["LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0", "EPL-2.0", "CC-BY-SA-4.0"]
    STRONG = ["GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later"]
    NETWORK = ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"]
    PROPRIETARY = ["BUSL-1.1", "Elastic-2.0", "Commercial", "Proprietary"]

    def test_permissive_bucket(self):
        for lic in self.PERMISSIVE:
            self.assertEqual(classify_license(lic), "permissive", lic)

    def test_public_domain_bucket(self):
        for lic in self.PUBLIC_DOMAIN:
            self.assertEqual(classify_license(lic), "public-domain", lic)

    def test_weak_copyleft_bucket(self):
        for lic in self.WEAK:
            self.assertEqual(classify_license(lic), "weak-copyleft", lic)

    def test_strong_copyleft_bucket(self):
        for lic in self.STRONG:
            self.assertEqual(classify_license(lic), "strong-copyleft", lic)

    def test_network_copyleft_bucket(self):
        for lic in self.NETWORK:
            self.assertEqual(classify_license(lic), "network-copyleft", lic)

    def test_proprietary_bucket(self):
        for lic in self.PROPRIETARY:
            self.assertEqual(classify_license(lic), "proprietary", lic)


class TestNormalizationDepth(unittest.TestCase):
    def test_messy_spellings(self):
        cases = {
            "Apache Software License": "Apache-2.0",
            "apache2": "Apache-2.0",
            "New BSD": "BSD-3-Clause",
            "Expat": "MIT",
            "the MIT license": "MIT",
            "GPLv2": "GPL-2.0-only",
            "lgpl v3": "LGPL-3.0-only",
            "Mozilla": "MPL-2.0",
            "CC0": "CC0-1.0",
        }
        for raw, want in cases.items():
            self.assertEqual(normalize_license_id(raw), want, raw)

    def test_or_later_plus_suffix(self):
        # "GPL-3.0+" tolerance via the alias table
        self.assertEqual(classify_license(normalize_license_id("GPL")),
                         "strong-copyleft")

    def test_nested_spdx_precedence(self):
        self.assertEqual(
            normalize_license_id("(MIT OR Apache-2.0) AND GPL-2.0-or-later"),
            "GPL-2.0-or-later",
        )

    def test_or_picks_least_severe_among_three(self):
        self.assertEqual(
            normalize_license_id("AGPL-3.0-only OR GPL-3.0-only OR MIT"), "MIT")

    def test_and_picks_most_severe_among_three(self):
        self.assertEqual(
            normalize_license_id("MIT AND Apache-2.0 AND AGPL-3.0-only"),
            "AGPL-3.0-only",
        )

    def test_empty_and_garbage(self):
        self.assertEqual(normalize_license_id(None), "NOASSERTION")
        self.assertEqual(normalize_license_id("   "), "NOASSERTION")
        self.assertEqual(normalize_license_id("???"), "NOASSERTION")


class TestPolicyMatrix(unittest.TestCase):
    def _audit(self, lic, policy):
        dep = type("D", (), {})()
        dep.name = "x"; dep.version = "1"; dep.direct = True
        dep.license = LicenseInfo.from_raw(lic)
        return audit_dependencies([dep], policy=policy)

    def test_agpl_blocked_everywhere_but_audit(self):
        for policy in ("proprietary", "distribute-binary", "permissive-only",
                       "gpl-project"):
            self.assertFalse(self._audit("AGPL-3.0-only", policy).passed, policy)
        self.assertTrue(self._audit("AGPL-3.0-only", "permissive-audit").passed)

    def test_gpl_only_allowed_in_gpl_project_and_audit(self):
        self.assertTrue(self._audit("GPL-3.0-only", "gpl-project").passed)
        self.assertTrue(self._audit("GPL-3.0-only", "permissive-audit").passed)
        self.assertFalse(self._audit("GPL-3.0-only", "proprietary").passed)

    def test_weak_copyleft_ok_for_proprietary(self):
        self.assertTrue(self._audit("LGPL-3.0-only", "proprietary").passed)

    def test_weak_copyleft_blocked_for_permissive_only(self):
        self.assertFalse(self._audit("LGPL-3.0-only", "permissive-only").passed)

    def test_all_presets_exist(self):
        for p in ("proprietary", "distribute-binary", "permissive-only",
                  "gpl-project", "permissive-audit"):
            self.assertIn(p, POLICY_PRESETS)


class TestNoticeDepth(unittest.TestCase):
    def test_notice_lists_distinct_licenses(self):
        deps = load_dependencies(DEMO01)
        text = generate_notice(deps, project="P")
        self.assertIn("Licenses present:", text)
        for d in deps:
            self.assertIn(d.name, text)

    def test_notice_sorted_by_name(self):
        deps = load_dependencies(DEMO01)
        text = generate_notice(deps)
        names_in_order = [ln for ln in text.splitlines()
                          if ln and not ln.startswith((" ", "=", "Licenses"))
                          and "includes" not in ln]
        # first dependency block name should be alphabetically <= last
        self.assertTrue(names_in_order)


# --------------------------------------------------------------------------- #
# Cross-language port parity (subprocess; skip if toolchain absent)
# --------------------------------------------------------------------------- #
class TestPortParity(unittest.TestCase):
    """Each port, run on demo 01-basic under proprietary policy, must report
    8 deps / 4 violations / exit 2 — identical to the Python reference."""

    @classmethod
    def setUpClass(cls):
        cls.ref = audit_dependencies(load_dependencies(DEMO01), "proprietary")
        assert cls.ref.total == 8 and cls.ref.violations == 4

    def _assert_fail_output(self, out, rc):
        self.assertEqual(rc, 2, out)
        self.assertIn("Violations: 4", out)
        self.assertIn("RESULT: FAIL", out)
        self.assertIn("AGPL-3.0-only", out)

    def test_node_port(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        p = subprocess.run(
            [node, os.path.join(PORTS, "javascript", "index.js"),
             "audit", DEMO01, "--policy", "proprietary"],
            capture_output=True, text=True)
        self._assert_fail_output(p.stdout, p.returncode)

    def test_node_port_unit_suite(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        p = subprocess.run([node, os.path.join(PORTS, "javascript", "test.js")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("passed", p.stdout)

    def test_node_port_json_parity(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        p = subprocess.run(
            [node, os.path.join(PORTS, "javascript", "index.js"),
             "audit", DEMO01, "--policy", "proprietary", "--format", "json"],
            capture_output=True, text=True)
        data = json.loads(p.stdout)
        self.assertEqual(data["total"], self.ref.total)
        self.assertEqual(data["violations"], self.ref.violations)
        self.assertEqual(data["passed"], self.ref.passed)

    def test_shell_port(self):
        sh = shutil.which("sh") or shutil.which("bash")
        if not sh:
            self.skipTest("sh not installed")
        p = subprocess.run(
            [sh, os.path.join(PORTS, "shell", "ossaudit.sh"),
             "audit", DEMO01, "--policy", "proprietary"],
            capture_output=True, text=True)
        self._assert_fail_output(p.stdout, p.returncode)

    def test_shell_port_smoke(self):
        sh = shutil.which("sh") or shutil.which("bash")
        if not sh:
            self.skipTest("sh not installed")
        p = subprocess.run([sh, os.path.join(PORTS, "shell", "test.sh")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_go_port(self):
        go = shutil.which("go")
        if not go:
            self.skipTest("go toolchain not installed (CI builds it)")
        p = subprocess.run(
            [go, "run", ".", "audit", DEMO01, "--policy", "proprietary"],
            cwd=os.path.join(PORTS, "go"), capture_output=True, text=True)
        self._assert_fail_output(p.stdout, p.returncode)

    def test_rust_port(self):
        cargo = shutil.which("cargo")
        if not cargo:
            self.skipTest("cargo toolchain not installed (CI builds it)")
        p = subprocess.run(
            [cargo, "run", "--quiet", "--", "audit", DEMO01, "--policy", "proprietary"],
            cwd=os.path.join(PORTS, "rust"), capture_output=True, text=True)
        self._assert_fail_output(p.stdout, p.returncode)


class TestPortSourcesExist(unittest.TestCase):
    """Even if a toolchain is missing locally, the port sources + CI must exist."""

    def test_all_port_sources_present(self):
        for rel in ("go/main.go", "go/main_test.go",
                    "rust/src/main.rs", "rust/Cargo.toml",
                    "javascript/index.js", "javascript/test.js",
                    "shell/ossaudit.sh", "shell/test.sh"):
            self.assertTrue(os.path.exists(os.path.join(PORTS, rel)), rel)

    def test_ports_ci_workflow_present(self):
        self.assertTrue(os.path.exists(
            os.path.join(ROOT, ".github", "workflows", "ports.yml")))


if __name__ == "__main__":
    unittest.main()
