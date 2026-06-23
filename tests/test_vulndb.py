"""Offline tests for the bundled 262k OSV corpus + enrichment subcommand.

Every assertion runs against the real bundled ``cognis_vulndb.jsonl.gz`` — no
network, no fabricated data. These prove that real advisories (Log4Shell,
lodash, django, jinja2) resolve out of the on-disk corpus and that the
`vulndb` CLI surface behaves as designed.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ossaudit.vulndb import (  # noqa: E402
    LocalVulnDB,
    DBVulnFinding,
    DBVulnReport,
    enrich_dependency,
    enrich_manifest,
    extract_cve_refs,
    resolve_cve_refs,
    severity_of,
    cve_aliases,
    count as vulndb_count,
)
from ossaudit.core import Dependency, LicenseInfo, load_dependencies  # noqa: E402
from ossaudit.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "12-offline-vulndb", "deps.json")
REFS = os.path.join(os.path.dirname(__file__), "fixtures", "advisory_refs.txt")


def _dep(name, version="1.0.0", ecosystem=""):
    return Dependency(name=name, version=version,
                      license=LicenseInfo.from_raw("MIT"), ecosystem=ecosystem)


class TestCorpusLoads(unittest.TestCase):
    db = None

    @classmethod
    def setUpClass(cls):
        cls.db = LocalVulnDB()

    def test_db_file_exists(self):
        self.assertTrue(self.db.exists())

    def test_count_is_262k(self):
        # the bundled corpus is the documented 262,351-record OSV snapshot
        self.assertGreaterEqual(self.db.count(), 100000)
        self.assertEqual(self.db.count(), 262351)

    def test_module_count_helper(self):
        self.assertEqual(vulndb_count(), self.db.count())

    def test_iter_yields_dicts(self):
        first = next(iter(self.db))
        self.assertIsInstance(first, dict)

    def test_records_have_expected_fields(self):
        r = next(iter(self.db))
        for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            self.assertIn(f, r)

    def test_ecosystems_present(self):
        ecos = self.db.ecosystems()
        self.assertIn("npm", ecos)
        self.assertIn("PyPI", ecos)
        self.assertIn("Maven", ecos)
        # counts are positive ints summing to the total
        self.assertTrue(all(isinstance(v, int) and v > 0 for v in ecos.values()))
        self.assertEqual(sum(ecos.values()), self.db.count())


class TestRealLookups(unittest.TestCase):
    db = None

    @classmethod
    def setUpClass(cls):
        cls.db = LocalVulnDB()

    def test_log4shell_resolves_by_cve(self):
        recs = self.db.by_cve("CVE-2021-44228")
        self.assertTrue(recs, "Log4Shell CVE-2021-44228 must resolve")
        rec = recs[0]
        self.assertTrue(rec["id"].startswith("GHSA-"))
        self.assertIn("CVE-2021-44228", [a.upper() for a in rec["aliases"]])
        self.assertEqual(rec["ecosystem"], "Maven")

    def test_log4shell_is_critical(self):
        rec = self.db.by_cve("CVE-2021-44228")[0]
        self.assertEqual(severity_of(rec), "CRITICAL")

    def test_cve_lookup_case_insensitive(self):
        self.assertEqual(
            [r["id"] for r in self.db.by_cve("cve-2021-44228")],
            [r["id"] for r in self.db.by_cve("CVE-2021-44228")],
        )

    def test_by_id_round_trips(self):
        rid = self.db.by_cve("CVE-2021-44228")[0]["id"]
        self.assertIsNotNone(self.db.by_id(rid))
        self.assertEqual(self.db.by_id(rid)["id"], rid)
        self.assertEqual(self.db.by_id(rid.lower())["id"], rid)

    def test_lodash_has_advisories(self):
        recs = self.db.by_package("lodash")
        self.assertTrue(recs)
        # lodash advisories span npm (the JS lib) and RubyGems (a same-named gem)
        self.assertIn("npm", {r.get("ecosystem") for r in recs})

    def test_lodash_npm_filter_is_npm_only(self):
        recs = self.db.by_package("lodash", ecosystem="npm")
        self.assertTrue(recs)
        self.assertTrue(all(r.get("ecosystem") == "npm" for r in recs))

    def test_lodash_command_injection_present(self):
        recs = self.db.by_package("lodash")
        all_cves = {c for r in recs for c in cve_aliases(r)}
        self.assertIn("CVE-2021-23337", all_cves)  # known command injection

    def test_django_has_many_advisories(self):
        self.assertGreater(len(self.db.by_package("django")), 50)

    def test_package_lookup_case_insensitive(self):
        self.assertEqual(
            len(self.db.by_package("Django")), len(self.db.by_package("django"))
        )

    def test_jinja2_resolves(self):
        self.assertTrue(self.db.by_package("jinja2"))

    def test_ecosystem_filter_narrows(self):
        npm = self.db.by_package("lodash", ecosystem="npm")
        pypi = self.db.by_package("lodash", ecosystem="PyPI")
        self.assertTrue(npm)
        self.assertEqual(pypi, [])

    def test_unknown_package_empty(self):
        self.assertEqual(self.db.by_package("definitely-not-a-real-pkg-xyz"), [])

    def test_unknown_cve_empty(self):
        self.assertEqual(self.db.by_cve("CVE-1999-0001"), [])

    def test_search_substring(self):
        hits = self.db.search("remote code", limit=5)
        self.assertTrue(hits)
        self.assertLessEqual(len(hits), 5)
        for h in hits:
            self.assertIn("remote code", h["summary"].lower())

    def test_search_empty_text_returns_empty(self):
        self.assertEqual(self.db.search(""), [])


class TestSeverityHelpers(unittest.TestCase):
    def test_cvss_vector_to_band(self):
        rec = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        self.assertEqual(severity_of(rec), "CRITICAL")

    def test_single_high_impact_is_high(self):
        rec = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
        self.assertEqual(severity_of(rec), "HIGH")

    def test_empty_severity_is_unknown(self):
        self.assertEqual(severity_of({"severity": ""}), "UNKNOWN")
        self.assertEqual(severity_of({}), "UNKNOWN")

    def test_explicit_word_severity(self):
        self.assertEqual(severity_of({"severity": "HIGH"}), "HIGH")

    def test_cve_aliases_filters_and_sorts(self):
        rec = {"aliases": ["GHSA-x", "CVE-2021-2", "CVE-2020-1", "PYSEC-1"]}
        self.assertEqual(cve_aliases(rec), ["CVE-2020-1", "CVE-2021-2"])

    def test_cve_aliases_empty(self):
        self.assertEqual(cve_aliases({"aliases": []}), [])
        self.assertEqual(cve_aliases({}), [])


class TestCveRefExtraction(unittest.TestCase):
    def test_extract_basic(self):
        refs = extract_cve_refs("see CVE-2021-44228 and CVE-2021-23337 please")
        self.assertEqual(refs, ["CVE-2021-23337", "CVE-2021-44228"])

    def test_extract_dedups_and_uppercases(self):
        refs = extract_cve_refs("cve-2019-10906 CVE-2019-10906")
        self.assertEqual(refs, ["CVE-2019-10906"])

    def test_extract_none(self):
        self.assertEqual(extract_cve_refs("no identifiers here"), [])
        self.assertEqual(extract_cve_refs(""), [])

    def test_resolve_refs_against_corpus(self):
        resolved = resolve_cve_refs(["CVE-2021-44228", "CVE-1999-0001"])
        self.assertTrue(resolved["CVE-2021-44228"])      # Log4Shell resolves
        self.assertEqual(resolved["CVE-1999-0001"], [])  # ancient CVE does not

    def test_resolve_from_fixture_file(self):
        with open(REFS, encoding="utf-8") as fh:
            refs = extract_cve_refs(fh.read())
        self.assertIn("CVE-2021-44228", refs)
        resolved = resolve_cve_refs(refs)
        hits = [k for k, v in resolved.items() if v]
        self.assertIn("CVE-2021-44228", hits)
        self.assertIn("CVE-2021-23337", hits)
        self.assertIn("CVE-2019-10906", hits)


class TestEnrichment(unittest.TestCase):
    db = None

    @classmethod
    def setUpClass(cls):
        cls.db = LocalVulnDB()

    def test_enrich_single_vulnerable(self):
        f = enrich_dependency(_dep("lodash", "4.17.11", "npm"), self.db)
        self.assertIsInstance(f, DBVulnFinding)
        self.assertGreater(f.vuln_count, 0)
        self.assertNotEqual(f.max_severity, "NONE")
        self.assertTrue(any(c.startswith("CVE-") for c in f.cve_ids))

    def test_enrich_single_clean(self):
        f = enrich_dependency(_dep("ossaudit-clean-shim-xyz", "9.9.9", "PyPI"), self.db)
        self.assertEqual(f.vuln_count, 0)
        self.assertEqual(f.max_severity, "NONE")
        self.assertEqual(f.cve_ids, [])

    def test_enrich_manifest_demo(self):
        deps = load_dependencies(DEMO)
        report = enrich_manifest(deps, self.db)
        self.assertIsInstance(report, DBVulnReport)
        self.assertEqual(report.total, 5)
        self.assertGreaterEqual(report.vulnerable, 4)
        self.assertFalse(report.clean)
        self.assertEqual(report.db_records, self.db.count())

    def test_enrich_manifest_sorted_worst_first(self):
        from ossaudit.vulndb import _SEVERITY_RANK
        deps = load_dependencies(DEMO)
        report = enrich_manifest(deps, self.db)
        ranks = [_SEVERITY_RANK.get(f.max_severity, 0) for f in report.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_log4j_maven_coordinate_matches(self):
        f = enrich_dependency(
            _dep("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven"), self.db)
        self.assertGreater(f.vuln_count, 0)
        self.assertIn("CVE-2021-44228", f.cve_ids)

    def test_report_to_dict_serializable(self):
        deps = load_dependencies(DEMO)
        report = enrich_manifest(deps, self.db)
        s = json.dumps(report.to_dict())
        self.assertIn("findings", s)
        self.assertIn("db_records", s)


class TestVulndbCli(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    def test_count_cmd(self):
        rc, out = self._run(["vulndb", "count"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "262351")

    def test_stats_cmd(self):
        rc, out = self._run(["vulndb", "stats"])
        self.assertEqual(rc, 0)
        self.assertIn("npm", out)

    def test_stats_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "stats"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIn("ecosystems", data)
        self.assertEqual(data["records"], 262351)

    def test_cve_cmd_resolves(self):
        rc, out = self._run(["vulndb", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)  # found -> 0
        self.assertIn("GHSA-", out)

    def test_cve_cmd_miss_exit_2(self):
        rc, _ = self._run(["vulndb", "cve", "CVE-1999-0001"])
        self.assertEqual(rc, 2)  # not found -> 2

    def test_cve_cmd_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)
        recs = json.loads(out)
        self.assertTrue(recs)
        self.assertIn("CVE-2021-44228", [a.upper() for a in recs[0]["aliases"]])

    def test_pkg_cmd_found(self):
        rc, out = self._run(["vulndb", "pkg", "lodash", "--ecosystem", "npm"])
        self.assertEqual(rc, 2)  # advisories present -> 2 (gate signal)
        self.assertIn("lodash", out)

    def test_pkg_cmd_clean(self):
        rc, out = self._run(["vulndb", "pkg", "no-such-pkg-zzz"])
        self.assertEqual(rc, 0)  # no advisories -> 0

    def test_search_cmd(self):
        rc, out = self._run(["vulndb", "search", "remote code", "--limit", "3"])
        self.assertEqual(rc, 0)
        self.assertIn("match", out)

    def test_enrich_cmd_table(self):
        rc, out = self._run(["vulndb", "enrich", DEMO])
        self.assertEqual(rc, 2)  # demo is vulnerable
        self.assertIn("VULNERABLE", out)

    def test_enrich_cmd_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "enrich", DEMO])
        self.assertEqual(rc, 2)
        data = json.loads(out)
        self.assertEqual(data["total"], 5)
        self.assertFalse(data["clean"])

    def test_resolve_cmd(self):
        rc, out = self._run(["vulndb", "resolve", REFS])
        self.assertEqual(rc, 0)
        self.assertIn("CVE-2021-44228", out)

    def test_resolve_cmd_json(self):
        rc, out = self._run(["--format", "json", "vulndb", "resolve", REFS])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIn("CVE-2021-44228", data["refs_found"])


if __name__ == "__main__":
    unittest.main()
