"""Offline tests for the OSV vulnerability enrichment + feeds CLI.

These NEVER hit the network: COGNIS_FEEDS_CACHE is pointed at a temp dir
seeded from committed fixtures (trimmed real OSV.dev responses) and every
query runs with offline=True. This mirrors the air-gap deployment path.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
MANIFEST = os.path.join(FIX, "vuln_manifest.json")


class _OfflineCacheBase(unittest.TestCase):
    """Seed an isolated feeds cache from the committed OSV fixtures."""

    def setUp(self):
        self._cache = tempfile.mkdtemp(prefix="cognis-feeds-test-")
        for fn in os.listdir(FIX):
            if fn.startswith("osv-q-"):
                shutil.copy(os.path.join(FIX, fn), os.path.join(self._cache, fn))
        self._prev = os.environ.get("COGNIS_FEEDS_CACHE")
        os.environ["COGNIS_FEEDS_CACHE"] = self._cache

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("COGNIS_FEEDS_CACHE", None)
        else:
            os.environ["COGNIS_FEEDS_CACHE"] = self._prev
        shutil.rmtree(self._cache, ignore_errors=True)


class TestQueryOffline(_OfflineCacheBase):
    def test_vulnerable_package_resolves_cve(self):
        from ossaudit.vulnscan import query_osv
        resp = query_osv("django", "3.2.0", "PyPI", offline=True)
        ids = [v["id"] for v in resp.get("vulns", [])]
        self.assertTrue(ids)

    def test_clean_package_no_vulns(self):
        from ossaudit.vulnscan import query_osv
        resp = query_osv("ossaudit-safe-shim", "9.9.9", "PyPI", offline=True)
        self.assertEqual(resp.get("vulns", []), [])

    def test_offline_miss_raises(self):
        from ossaudit.vulnscan import query_osv
        with self.assertRaises(FileNotFoundError):
            query_osv("not-cached-pkg", "0.0.1", "PyPI", offline=True)

    def test_ecosystem_normalization(self):
        from ossaudit.vulnscan import normalize_ecosystem
        self.assertEqual(normalize_ecosystem("pip"), "PyPI")
        self.assertEqual(normalize_ecosystem("node"), "npm")
        self.assertEqual(normalize_ecosystem("rust"), "crates.io")
        self.assertEqual(normalize_ecosystem(None), "PyPI")


class TestScanOffline(_OfflineCacheBase):
    def _deps(self):
        from ossaudit.core import load_dependencies
        return load_dependencies(MANIFEST)

    def test_scan_finds_vulnerable_and_clean(self):
        from ossaudit.vulnscan import scan_dependencies
        report = scan_dependencies(self._deps(), offline=True)
        self.assertEqual(report.total, 3)
        self.assertGreaterEqual(report.vulnerable, 2)  # django + lodash
        self.assertFalse(report.clean)
        by_name = {f.name: f for f in report.findings}
        self.assertGreater(by_name["django"].vuln_count, 0)
        self.assertEqual(by_name["ossaudit-safe-shim"].vuln_count, 0)
        self.assertEqual(by_name["ossaudit-safe-shim"].max_severity, "NONE")

    def test_django_has_real_cve(self):
        from ossaudit.vulnscan import scan_dependencies
        report = scan_dependencies(self._deps(), offline=True)
        django = {f.name: f for f in report.findings}["django"]
        # Aliases include real CVEs; the enrichment surfaces them.
        self.assertTrue(any(c.startswith("CVE-") for c in django.cve_ids))

    def test_findings_sorted_worst_first(self):
        from ossaudit.vulnscan import scan_dependencies, _SEVERITY_RANK
        report = scan_dependencies(self._deps(), offline=True)
        ranks = [_SEVERITY_RANK.get(f.max_severity, 0) for f in report.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_report_to_dict_serializable(self):
        from ossaudit.vulnscan import scan_dependencies
        report = scan_dependencies(self._deps(), offline=True)
        json.dumps(report.to_dict())  # must not raise


class TestCliOffline(_OfflineCacheBase):
    def test_vulnscan_cli_exit_code(self):
        from ossaudit.cli import main
        rc = main(["vulnscan", MANIFEST, "--offline"])
        self.assertEqual(rc, 2)  # vulnerabilities present

    def test_vulnscan_cli_json(self):
        from ossaudit.cli import main
        rc = main(["--format", "json", "vulnscan", MANIFEST, "--offline"])
        self.assertEqual(rc, 2)

    def test_feeds_list_restricted_to_osv(self):
        from ossaudit.cli import main, RELEVANT_FEEDS
        self.assertEqual(RELEVANT_FEEDS, ["osv"])
        rc = main(["feeds", "list"])
        self.assertEqual(rc, 0)

    def test_feeds_get_rejects_unlisted_feed(self):
        from ossaudit.cli import main
        rc = main(["feeds", "get", "cisa-kev", "--offline"])
        self.assertEqual(rc, 1)  # not consumed by this tool


class TestSnapshotRoundTrip(_OfflineCacheBase):
    def test_export_import_preserves_cache(self):
        from ossaudit import datafeeds
        with tempfile.TemporaryDirectory() as d:
            tarball = os.path.join(d, "osv-cache.tar.gz")
            n = datafeeds.snapshot_export(tarball)
            self.assertGreaterEqual(n, 0)
            self.assertTrue(os.path.exists(tarball))
            # Wipe the cache, then re-import.
            for fn in os.listdir(self._cache):
                os.remove(os.path.join(self._cache, fn))
            datafeeds.snapshot_import(tarball)
            from ossaudit.vulnscan import query_osv
            resp = query_osv("django", "3.2.0", "PyPI", offline=True)
            self.assertTrue(resp.get("vulns"))


if __name__ == "__main__":
    unittest.main()
