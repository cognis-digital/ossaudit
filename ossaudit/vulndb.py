"""vulndb — offline enrichment against the bundled 262k-record OSV corpus.

This module is the *offline twin* of :mod:`ossaudit.vulnscan`. Where ``vulnscan``
queries OSV.dev live (and caches results for air-gap replay), ``vulndb`` matches
the dependencies / CVE references in a manifest against the
**bundled, on-disk** ``cognis_vulndb.jsonl.gz`` — a consolidated, compact OSV
corpus of ~262k real vulnerabilities across PyPI / npm / Go / Maven / RubyGems /
crates.io / NuGet. It needs **no network, no key** and works the moment the repo
is cloned, which is exactly what an air-gapped or disconnected enclave wants.

Every record carries: ``id`` (GHSA/PYSEC/RUSTSEC/…), ``aliases`` (incl. real
CVE ids), ``ecosystem``, ``summary``, ``severity`` (CVSS vector when published),
affected ``packages``, ``published`` / ``modified`` dates and a reference count.

    from ossaudit.vulndb import LocalVulnDB
    db = LocalVulnDB()
    db.count()                       # -> 262351
    db.by_cve("CVE-2021-44228")      # -> [records ...]  (Log4Shell)
    db.by_package("log4j-core")      # -> records affecting that package
    db.search("deserialization", 20) # -> summary substring matches

The enrichment API matches an OSSAUDIT manifest's components against this corpus
and produces a structured, JSON/SARIF-serialisable report:

    from ossaudit.core import load_dependencies
    from ossaudit.vulndb import enrich_manifest
    report = enrich_manifest(load_dependencies("deps.json"))

NO fabricated data — only the real OSV records shipped in the bundle. Refresh /
extend the corpus from NVD / OSV / GHSA on the edge with
``python -m ossaudit.datafeeds`` (see SOURCES.md / README "Edge / air-gap").

Defensive / authorized-use only.
"""
from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .core import Dependency

_HERE = Path(__file__).resolve().parent
_BUNDLED_DB = _HERE / "cognis_vulndb.jsonl.gz"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# CVSS-vector -> coarse severity band (only used when the record has no explicit
# severity word). Identical bands to vulnscan so the two layers agree.
_CVSS_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"))
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
                  "UNKNOWN": 0, "NONE": -1}


def _cvss_base_from_vector(vector: str) -> Optional[float]:
    """Coarse base score from a CVSS v3.x / v4.0 vector string."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    except ValueError:
        return None
    impacts = [parts.get(k, "N") for k in ("C", "I", "A", "VC", "VI", "VA")]
    highs = sum(1 for v in impacts if v == "H")
    if highs >= 2:
        return 9.0
    if highs == 1:
        return 7.0
    if any(v == "L" for v in impacts):
        return 5.0
    return None


def severity_of(record: Dict[str, Any]) -> str:
    """Human severity band for a bundled record.

    The bundled corpus stores ``severity`` as either a CVSS vector string or an
    empty string. Returns CRITICAL/HIGH/MEDIUM/LOW or UNKNOWN.
    """
    sev = record.get("severity")
    if isinstance(sev, str) and sev.strip():
        s = sev.strip()
        if s.upper() in _SEVERITY_RANK:
            return s.upper()
        if s.upper().startswith("CVSS"):
            base = _cvss_base_from_vector(s)
            if base is not None:
                for cutoff, label in _CVSS_BANDS:
                    if base >= cutoff:
                        return label
    return "UNKNOWN"


def cve_aliases(record: Dict[str, Any]) -> List[str]:
    """Real CVE ids declared in a record's aliases (uppercased, sorted)."""
    out = []
    for a in (record.get("aliases") or []):
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            out.append(a.upper())
    return sorted(set(out))


class LocalVulnDB:
    """Lazy, indexed, read-only view over the bundled gzipped OSV corpus."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else _BUNDLED_DB
        self._records: Optional[List[dict]] = None
        self._by_id: Optional[Dict[str, dict]] = None
        self._by_cve: Optional[Dict[str, List[dict]]] = None
        self._by_pkg: Optional[Dict[str, List[dict]]] = None

    # ----- loading --------------------------------------------------------
    def __iter__(self) -> Iterator[dict]:
        if self._records is not None:
            yield from self._records
            return
        if not self.path.exists():
            return
        with gzip.open(self.path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def load(self) -> List[dict]:
        if self._records is None:
            self._records = list(self)
        return self._records

    def count(self) -> int:
        return len(self.load())

    def exists(self) -> bool:
        return self.path.exists()

    # ----- indexes (built once, lazily) -----------------------------------
    def _index(self) -> None:
        if self._by_cve is not None:
            return
        self._by_id, self._by_cve, self._by_pkg = {}, {}, {}
        for r in self.load():
            rid = r.get("id")
            if rid:
                self._by_id[rid.upper()] = r
                self._by_cve.setdefault(rid.upper(), []).append(r)
            for alias in (r.get("aliases") or []):
                if isinstance(alias, str):
                    self._by_cve.setdefault(alias.upper(), []).append(r)
            for p in (r.get("packages") or []):
                if p:
                    self._by_pkg.setdefault(p.lower(), []).append(r)

    def by_id(self, vid: str) -> Optional[dict]:
        self._index()
        return self._by_id.get((vid or "").upper())

    def by_cve(self, cve: str) -> List[dict]:
        self._index()
        return list(self._by_cve.get((cve or "").upper(), []))

    def by_package(self, name: str, ecosystem: Optional[str] = None) -> List[dict]:
        self._index()
        hits = self._by_pkg.get((name or "").lower(), [])
        if ecosystem:
            eco = ecosystem.lower()
            hits = [r for r in hits if (r.get("ecosystem", "") or "").lower() == eco]
        return list(hits)

    def search(self, text: str, limit: int = 50) -> List[dict]:
        t = (text or "").lower()
        if not t:
            return []
        out: List[dict] = []
        for r in self:
            if t in (r.get("summary", "") or "").lower():
                out.append(r)
                if len(out) >= limit:
                    break
        return out

    def ecosystems(self) -> Dict[str, int]:
        """Count of records per ecosystem (handy for `vulndb stats`)."""
        counts: Dict[str, int] = {}
        for r in self.load():
            eco = r.get("ecosystem", "") or "(none)"
            counts[eco] = counts.get(eco, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


# --------------------------------------------------------------------------- #
# Enrichment: match manifest components against the bundled corpus (offline).
# --------------------------------------------------------------------------- #
@dataclass
class DBVulnFinding:
    name: str
    version: str
    ecosystem: str
    vuln_count: int
    max_severity: str
    osv_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    summaries: List[str] = field(default_factory=list)
    matched_via: str = "package"  # package | cve-ref


@dataclass
class DBVulnReport:
    source: str
    db_records: int
    total: int
    vulnerable: int
    findings: List[DBVulnFinding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.vulnerable == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "db_records": self.db_records,
            "total": self.total,
            "vulnerable": self.vulnerable,
            "clean": self.clean,
            "findings": [asdict(f) for f in self.findings],
        }


def _max_severity(records: List[dict]) -> str:
    worst = "NONE"
    for r in records:
        s = severity_of(r)
        if _SEVERITY_RANK.get(s, 0) > _SEVERITY_RANK.get(worst, -1):
            worst = s
    return worst


def _summarize(records: List[dict], limit: int = 5) -> List[str]:
    out = []
    for r in records:
        s = r.get("summary")
        if s:
            out.append(str(s))
        if len(out) >= limit:
            break
    return out


def enrich_dependency(dep: Dependency, db: Optional[LocalVulnDB] = None,
                      *, default_ecosystem: str = "") -> DBVulnFinding:
    """Match a single dependency against the bundled corpus by package name."""
    db = db or LocalVulnDB()
    eco = (getattr(dep, "ecosystem", "") or default_ecosystem or "").strip()
    records = db.by_package(dep.name, ecosystem=eco or None)
    osv_ids = sorted({r["id"] for r in records if r.get("id")})
    cves: List[str] = []
    for r in records:
        cves.extend(cve_aliases(r))
    return DBVulnFinding(
        name=dep.name,
        version=dep.version,
        ecosystem=eco or "(any)",
        vuln_count=len(records),
        max_severity=_max_severity(records) if records else "NONE",
        osv_ids=osv_ids,
        cve_ids=sorted(set(cves)),
        summaries=_summarize(records),
        matched_via="package",
    )


def enrich_manifest(deps: List[Dependency], db: Optional[LocalVulnDB] = None,
                    *, default_ecosystem: str = "") -> DBVulnReport:
    """Match every dependency's package name against the bundled OSV corpus.

    Fully offline. A dependency with one or more matching advisories is counted
    as ``vulnerable``; findings are sorted worst-first.
    """
    db = db or LocalVulnDB()
    findings = [enrich_dependency(d, db, default_ecosystem=default_ecosystem)
                for d in deps]
    findings.sort(key=lambda f: (-_SEVERITY_RANK.get(f.max_severity, 0),
                                 -f.vuln_count, f.name.lower()))
    vulnerable = sum(1 for f in findings if f.vuln_count > 0)
    return DBVulnReport(source=str(db.path.name), db_records=db.count(),
                        total=len(deps), vulnerable=vulnerable, findings=findings)


def extract_cve_refs(text: str) -> List[str]:
    """Pull every CVE id out of arbitrary text (e.g. an SBOM or advisory note)."""
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(text or "")})


def resolve_cve_refs(refs: List[str], db: Optional[LocalVulnDB] = None
                     ) -> Dict[str, List[dict]]:
    """Resolve a list of CVE ids to the bundled advisory records that carry them."""
    db = db or LocalVulnDB()
    return {ref.upper(): db.by_cve(ref) for ref in refs}


# convenience module-level helpers
def count() -> int:
    return LocalVulnDB().count()
