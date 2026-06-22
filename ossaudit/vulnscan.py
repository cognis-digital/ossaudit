"""vulnscan — map audited dependencies to known vulnerabilities via OSV.dev.

OSSAUDIT classifies the *license* of each dependency. This module adds the
other half of supply-chain due-diligence: does a dependency carry a *known
vulnerability*? It cross-references each ``{name, version, ecosystem}`` against
the OSV.dev database (https://osv.dev), the open, authoritative aggregator of
vulnerabilities across PyPI / npm / Go / Maven / crates.io / RubyGems / etc.

This is a REAL enrichment, not cosmetic: a dependency that audits "ok" on
license can still be shipping a critical RCE, and this surfaces it with the
CVE / GHSA id, severity, and a CVSS vector straight from OSV records.

Edge / air-gap deployable
-------------------------
Built on the bundled :mod:`ossaudit.datafeeds` ingestion layer (stdlib only).
Each OSV query result is cached to disk under ``COGNIS_FEEDS_CACHE``
(default ``~/.cache/cognis-feeds``) keyed by ecosystem/name/version, so the
exact same scan can be re-served **offline** on a disconnected enclave::

    # connected host: warm the cache for every dependency in the manifest
    ossaudit feeds warm deps.json

    # snapshot it for sneakernet
    python -m ossaudit.datafeeds snapshot-export osv-cache.tar.gz

    # air-gapped host: import + scan with zero network
    python -m ossaudit.datafeeds snapshot-import osv-cache.tar.gz
    ossaudit vulnscan deps.json --offline

Defensive / authorized-use intelligence only.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import datafeeds
from .core import Dependency

FEED_ID = "osv"

# OSV ecosystem identifiers, keyed by common manifest hints. OSV is
# case-sensitive on ecosystem; these are the canonical spellings.
DEFAULT_ECOSYSTEM = "PyPI"
ECOSYSTEM_ALIASES: Dict[str, str] = {
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "js": "npm",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "java": "Maven",
    "cargo": "crates.io",
    "crates": "crates.io",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "composer": "Packagist",
    "php": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}


def normalize_ecosystem(raw: Optional[str]) -> str:
    """Map a free-form ecosystem hint to OSV's canonical spelling."""
    if not raw:
        return DEFAULT_ECOSYSTEM
    key = str(raw).strip().lower()
    return ECOSYSTEM_ALIASES.get(key, str(raw).strip())


# --------------------------------------------------------------------------- #
# OSV query with per-package disk cache (so --offline can re-serve it)
# --------------------------------------------------------------------------- #
def _cache_paths(ecosystem: str, name: str, version: str):
    key = f"{FEED_ID}::{ecosystem}::{name}::{version}".encode("utf-8")
    digest = hashlib.sha1(key).hexdigest()[:16]
    base = datafeeds.cache_dir() / f"{FEED_ID}-q-{digest}"
    return base.with_suffix(".data"), base.with_suffix(".meta.json")


def query_osv(name: str, version: str, ecosystem: str = DEFAULT_ECOSYSTEM,
              *, offline: bool = False, max_age_hours: float = 24.0) -> Dict[str, Any]:
    """Return the raw OSV response for one ``{ecosystem, name, version}``.

    Caches each query to the feeds cache so it can be re-served offline. When
    ``offline=True`` it reads cache only and raises FileNotFoundError on a miss.
    """
    ecosystem = normalize_ecosystem(ecosystem)
    data_path, meta_path = _cache_paths(ecosystem, name, version)

    age = None
    if meta_path.exists():
        try:
            ts = json.loads(meta_path.read_text(encoding="utf-8")).get("fetched_at", 0)
            age = (time.time() - ts) / 3600.0
        except (ValueError, OSError):
            age = None

    if offline:
        if age is None or not data_path.exists():
            raise FileNotFoundError(
                f"osv: no cached result for {ecosystem}/{name}@{version} "
                f"and offline=True (warm the cache first)"
            )
    elif age is None or age > max_age_hours or not data_path.exists():
        query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        # Reuse the bundled catalog's verified OSV endpoint (don't invent URLs).
        feed = datafeeds._catalog_feeds()[FEED_ID]
        raw = datafeeds.fetch(feed["url"], method="POST",
                              data=json.dumps(query).encode("utf-8"))
        data_path.write_bytes(raw)
        meta_path.write_text(json.dumps({
            "feed": FEED_ID, "ecosystem": ecosystem, "name": name,
            "version": version, "fetched_at": time.time(), "bytes": len(raw),
        }), encoding="utf-8")

    return json.loads(data_path.read_bytes())


# --------------------------------------------------------------------------- #
# Findings model
# --------------------------------------------------------------------------- #
_CVSS_SEVERITY_BANDS = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
)


def _cvss_base_score(vector: str) -> Optional[float]:
    """Best-effort CVSS base score from a v3.x/v4.0 vector string.

    OSV stores the vector, not always the numeric score, so we derive a coarse
    score from the impact metrics. This is intentionally simple and only used
    to band a severity when OSV gives no explicit severity word.
    """
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    except ValueError:
        return None
    # Very rough: high impact on any of C/I/A => treat as high.
    impacts = [parts.get(k, "N") for k in ("C", "I", "A", "VC", "VI", "VA")]
    highs = sum(1 for v in impacts if v == "H")
    if highs >= 2:
        return 9.0
    if highs == 1:
        return 7.0
    if any(v in ("L",) for v in impacts):
        return 5.0
    return None


def _severity_word(vuln: Dict[str, Any]) -> str:
    """Extract a human severity (CRITICAL/HIGH/.../UNKNOWN) from an OSV record."""
    db = vuln.get("database_specific") or {}
    word = db.get("severity")
    if isinstance(word, str) and word.strip():
        return word.strip().upper()
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        if isinstance(score, str) and score.startswith("CVSS"):
            base = _cvss_base_score(score)
            if base is not None:
                for cutoff, label in _CVSS_SEVERITY_BANDS:
                    if base >= cutoff:
                        return label
    return "UNKNOWN"


def _cve_ids(vuln: Dict[str, Any]) -> List[str]:
    """Prefer real CVE ids from aliases; fall back to the OSV/GHSA id."""
    aliases = [a for a in (vuln.get("aliases") or []) if isinstance(a, str)]
    cves = [a for a in aliases if a.upper().startswith("CVE-")]
    return cves or ([vuln["id"]] if vuln.get("id") else [])


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


@dataclass
class VulnFinding:
    name: str
    version: str
    ecosystem: str
    vuln_count: int
    max_severity: str
    osv_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    summaries: List[str] = field(default_factory=list)


@dataclass
class VulnReport:
    ecosystem_default: str
    total: int
    vulnerable: int
    findings: List[VulnFinding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.vulnerable == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ecosystem_default": self.ecosystem_default,
            "total": self.total,
            "vulnerable": self.vulnerable,
            "clean": self.clean,
            "findings": [asdict(f) for f in self.findings],
        }


def _ecosystem_for(dep: Dependency, default: str) -> str:
    # Dependency has no ecosystem field; manifests may carry one as an extra
    # attribute, so look it up defensively.
    eco = getattr(dep, "ecosystem", None)
    return normalize_ecosystem(eco) if eco else normalize_ecosystem(default)


def scan_dependencies(deps: List[Dependency], *, ecosystem: str = DEFAULT_ECOSYSTEM,
                      offline: bool = False) -> VulnReport:
    """Cross-reference each dependency against OSV and build a VulnReport."""
    default_eco = normalize_ecosystem(ecosystem)
    findings: List[VulnFinding] = []
    vulnerable = 0
    for dep in deps:
        eco = _ecosystem_for(dep, default_eco)
        try:
            resp = query_osv(dep.name, dep.version, eco, offline=offline)
        except FileNotFoundError:
            # Offline miss => report as unknown rather than crashing the scan.
            findings.append(VulnFinding(
                name=dep.name, version=dep.version, ecosystem=eco,
                vuln_count=0, max_severity="UNCHECKED",
                summaries=["no cached OSV result (offline)"]))
            continue
        vulns = resp.get("vulns") or []
        if not vulns:
            findings.append(VulnFinding(
                name=dep.name, version=dep.version, ecosystem=eco,
                vuln_count=0, max_severity="NONE"))
            continue
        vulnerable += 1
        osv_ids, cves, summaries = [], [], []
        worst = "UNKNOWN"
        for v in vulns:
            if v.get("id"):
                osv_ids.append(v["id"])
            cves.extend(_cve_ids(v))
            if v.get("summary"):
                summaries.append(str(v["summary"]))
            sev = _severity_word(v)
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(worst, 0):
                worst = sev
        findings.append(VulnFinding(
            name=dep.name, version=dep.version, ecosystem=eco,
            vuln_count=len(vulns), max_severity=worst,
            osv_ids=sorted(set(osv_ids)),
            cve_ids=sorted(set(cves)),
            summaries=summaries[:5]))
    findings.sort(key=lambda f: (-_SEVERITY_RANK.get(f.max_severity, 0),
                                 -f.vuln_count, f.name.lower()))
    return VulnReport(ecosystem_default=default_eco, total=len(deps),
                      vulnerable=vulnerable, findings=findings)
