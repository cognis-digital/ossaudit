"""Core engine for OSSAUDIT.

The engine reads a dependency manifest (a JSON list of packages with declared
licenses), normalizes each SPDX-ish license identifier, classifies its copyleft
strength, and decides whether each dependency is permitted under the project's
distribution policy. It then emits structured findings (including the dreaded
AGPL network-copyleft contamination) and can render a NOTICE attribution file.

No network access, standard library only.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Tool identity (single source of truth; VERSION file wins if present)
# ---------------------------------------------------------------------------
TOOL_NAME = "ossaudit"


def _read_version() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, os.pardir, "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                v = fh.read().strip()
                if v:
                    return v
        except OSError:
            continue
    return "0.2.1"


TOOL_VERSION = _read_version()

# ---------------------------------------------------------------------------
# License knowledge base
# ---------------------------------------------------------------------------
# category: one of permissive | weak-copyleft | strong-copyleft | network-copyleft
#           | public-domain | proprietary | unknown
# Each canonical SPDX id maps to its category. Aliases are normalized first.

LICENSE_RULES: Dict[str, str] = {
    # permissive
    "MIT": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "Apache-2.0": "permissive",
    "ISC": "permissive",
    "Zlib": "permissive",
    "Python-2.0": "permissive",
    "PSF-2.0": "permissive",
    "FTL": "permissive",
    "BSL-1.0": "permissive",
    "PostgreSQL": "permissive",
    "Artistic-2.0": "permissive",
    "BSD-3-Clause-Clear": "permissive",
    "X11": "permissive",
    "NCSA": "permissive",
    "OpenSSL": "permissive",
    "Apache-1.1": "permissive",
    # Creative Commons content licenses (common for data/docs/icons).
    "CC-BY-4.0": "permissive",
    "CC-BY-3.0": "permissive",
    # Share-alike imposes copyleft-style obligations on derivatives.
    "CC-BY-SA-4.0": "weak-copyleft",
    "CC-BY-SA-3.0": "weak-copyleft",
    # public domain / equivalent
    "Unlicense": "public-domain",
    "CC0-1.0": "public-domain",
    "0BSD": "public-domain",
    "blessing": "public-domain",
    "WTFPL": "public-domain",
    # weak copyleft (file/library scope)
    "LGPL-2.1-only": "weak-copyleft",
    "LGPL-2.1-or-later": "weak-copyleft",
    "LGPL-3.0-only": "weak-copyleft",
    "LGPL-3.0-or-later": "weak-copyleft",
    "MPL-2.0": "weak-copyleft",
    "EPL-2.0": "weak-copyleft",
    "CDDL-1.0": "weak-copyleft",
    # strong copyleft (whole-program, on distribution)
    "GPL-2.0-only": "strong-copyleft",
    "GPL-2.0-or-later": "strong-copyleft",
    "GPL-3.0-only": "strong-copyleft",
    "GPL-3.0-or-later": "strong-copyleft",
    # network copyleft (triggers on network interaction, not just distribution)
    "AGPL-3.0-only": "network-copyleft",
    "AGPL-3.0-or-later": "network-copyleft",
    "SSPL-1.0": "network-copyleft",
    # proprietary / restricted
    "Commercial": "proprietary",
    "Proprietary": "proprietary",
    "BUSL-1.1": "proprietary",
    "Elastic-2.0": "proprietary",
}

# Common non-canonical spellings -> canonical SPDX id.
LICENSE_ALIASES: Dict[str, str] = {
    "APACHE": "Apache-2.0",
    "APACHE2": "Apache-2.0",
    "APACHE-2": "Apache-2.0",
    "APACHE2.0": "Apache-2.0",
    "APACHELICENSE2.0": "Apache-2.0",
    "APACHESOFTWARELICENSE": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "BSD3": "BSD-3-Clause",
    "BSD-3": "BSD-3-Clause",
    "NEWBSD": "BSD-3-Clause",
    "BSD2": "BSD-2-Clause",
    "MITLICENSE": "MIT",
    "THEMITLICENSE": "MIT",
    "EXPAT": "MIT",
    "GPL": "GPL-3.0-or-later",
    "GPL3": "GPL-3.0-only",
    "GPLV3": "GPL-3.0-only",
    "GPL-3": "GPL-3.0-only",
    "GPL2": "GPL-2.0-only",
    "GPLV2": "GPL-2.0-only",
    "LGPL": "LGPL-3.0-or-later",
    "LGPL3": "LGPL-3.0-only",
    "LGPLV3": "LGPL-3.0-only",
    "LGPL2": "LGPL-2.1-only",
    "AGPL": "AGPL-3.0-or-later",
    "AGPL3": "AGPL-3.0-only",
    "AGPLV3": "AGPL-3.0-only",
    "MPL": "MPL-2.0",
    "MOZILLA": "MPL-2.0",
    "ISCLICENSE": "ISC",
    "PUBLICDOMAIN": "Unlicense",
    "CC0": "CC0-1.0",
    "PSF": "PSF-2.0",
    "PYTHON": "Python-2.0",
    "FREETYPE": "FTL",
    "FREETYPELICENSE": "FTL",
    "BOOST": "BSL-1.0",
    "BOOSTSOFTWARELICENSE": "BSL-1.0",
    "BSL1.0": "BSL-1.0",
    "POSTGRESQL": "PostgreSQL",
    "ARTISTIC": "Artistic-2.0",
    "ARTISTIC2.0": "Artistic-2.0",
    "WTFPL": "WTFPL",
    "X11LICENSE": "X11",
    "UIUC": "NCSA",
    "BLESSING": "blessing",
    "SQLITEBLESSING": "blessing",
    "CCBY4.0": "CC-BY-4.0",
    "CCBY": "CC-BY-4.0",
    "CCBY3.0": "CC-BY-3.0",
    "CCBYSA4.0": "CC-BY-SA-4.0",
    "CCBYSA": "CC-BY-SA-4.0",
    "OPENSSL": "OpenSSL",
}

# Severity ranking used to sort findings (higher = worse).
CATEGORY_SEVERITY: Dict[str, int] = {
    "network-copyleft": 5,
    "strong-copyleft": 4,
    "proprietary": 4,
    "unknown": 3,
    "weak-copyleft": 2,
    "permissive": 1,
    "public-domain": 0,
}

# Distribution policy presets: which categories are allowed.
POLICY_PRESETS: Dict[str, set] = {
    # Closed-source SaaS / proprietary distribution: AGPL & GPL are radioactive.
    "proprietary": {"permissive", "public-domain", "weak-copyleft"},
    # Shipping a closed-source binary: GPL/AGPL/SSPL all forbidden.
    "distribute-binary": {"permissive", "public-domain", "weak-copyleft"},
    # Permissive-only (e.g. you relicense under Apache): no copyleft at all.
    "permissive-only": {"permissive", "public-domain"},
    # Open-source GPL project: everything copyleft except AGPL/SSPL is fine.
    "gpl-project": {
        "permissive",
        "public-domain",
        "weak-copyleft",
        "strong-copyleft",
    },
    # Anything goes (audit-only, never fails).
    "permissive-audit": {
        "permissive",
        "public-domain",
        "weak-copyleft",
        "strong-copyleft",
        "network-copyleft",
        "proprietary",
        "unknown",
    },
}

_NORMALIZE_STRIP = re.compile(r"[^A-Z0-9.+]")


def _strip_outer_parens(text: str) -> str:
    """Remove a single pair of fully-enclosing parentheses, if present.

    Unlike ``str.strip('()')`` this never removes a leading/trailing paren that
    is not actually balanced around the whole string, so a nested expression
    like ``(MIT OR Apache-2.0) AND GPL-2.0-or-later`` is left intact.
    """
    t = text.strip()
    while t.startswith("(") and t.endswith(")"):
        depth = 0
        enclosing = True
        for i, ch in enumerate(t):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                # Closed the opening paren before the end => not fully enclosing.
                if depth == 0 and i != len(t) - 1:
                    enclosing = False
                    break
        if enclosing:
            t = t[1:-1].strip()
        else:
            break
    return t


def _split_top_level(expr: str, op: str) -> List[str]:
    """Split an SPDX expression on a binary operator at paren depth 0.

    Returns a single-element list (the original expression) when the operator
    does not appear at the top level, so callers can fall through to the next
    precedence level.
    """
    parts: List[str] = []
    depth = 0
    token = op.upper()
    i = 0
    start = 0
    upper = expr.upper()
    n = len(expr)
    tlen = len(token)
    while i < n:
        ch = expr[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            i += 1
            continue
        if depth == 0 and upper[i:i + tlen] == token:
            before = expr[i - 1] if i > 0 else " "
            after = expr[i + tlen] if i + tlen < n else " "
            if before.isspace() and after.isspace():
                parts.append(expr[start:i].strip())
                i += tlen
                start = i
                continue
        i += 1
    parts.append(expr[start:].strip())
    return [p for p in parts if p]


def normalize_license_id(raw: Optional[str]) -> str:
    """Normalize a free-form license string to a canonical SPDX id.

    Handles SPDX 'OR'/'AND' expressions (including nested parentheses) by
    picking the most permissive operand of an OR (best case for the consumer)
    and the most restrictive operand of an AND. OR has lower precedence than
    AND, matching the SPDX license-expression grammar.
    """
    if not raw or not str(raw).strip():
        return "NOASSERTION"
    text = str(raw).strip()

    # SPDX expression handling with parentheses and precedence.
    expr = _strip_outer_parens(text)

    # OR binds loosest: split on OR first, recurse, choose least severe.
    or_parts = _split_top_level(expr, "OR")
    if len(or_parts) > 1:
        cands = [normalize_license_id(p) for p in or_parts]
        return min(cands, key=lambda c: CATEGORY_SEVERITY.get(classify_license(c), 3))

    # Then AND: all obligations apply, choose most severe.
    and_parts = _split_top_level(expr, "AND")
    if len(and_parts) > 1:
        cands = [normalize_license_id(p) for p in and_parts]
        return max(cands, key=lambda c: CATEGORY_SEVERITY.get(classify_license(c), 3))

    # Direct canonical match (case-insensitive).
    for canon in LICENSE_RULES:
        if expr.lower() == canon.lower():
            return canon

    # Alias match on a squashed key.
    key = _NORMALIZE_STRIP.sub("", expr.upper())
    key = key.rstrip(".")
    if key in LICENSE_ALIASES:
        return LICENSE_ALIASES[key]

    # "OR LATER" / "+" suffix tolerance, e.g. "GPL-3.0+".
    if key.endswith("+"):
        base = key[:-1]
        if base in LICENSE_ALIASES:
            return LICENSE_ALIASES[base]

    return "NOASSERTION"


def classify_license(canonical_id: str) -> str:
    """Return the copyleft category for a canonical license id."""
    if canonical_id in LICENSE_RULES:
        return LICENSE_RULES[canonical_id]
    return "unknown"


def is_compatible(category: str, allowed: set) -> bool:
    """True if a license category is permitted by the policy."""
    return category in allowed


@dataclass
class LicenseInfo:
    raw: str
    spdx_id: str
    category: str
    severity: int

    @classmethod
    def from_raw(cls, raw: Optional[str]) -> "LicenseInfo":
        spdx = normalize_license_id(raw)
        cat = classify_license(spdx)
        return cls(
            raw=(raw or "").strip(),
            spdx_id=spdx,
            category=cat,
            severity=CATEGORY_SEVERITY.get(cat, 3),
        )


@dataclass
class Dependency:
    name: str
    version: str
    license: LicenseInfo
    direct: bool = True
    homepage: str = ""
    copyright: str = ""
    # Optional package ecosystem (PyPI/npm/Go/...) used by OSV vulnerability
    # cross-referencing; empty => fall back to the scan default.
    ecosystem: str = ""


@dataclass
class AuditFinding:
    name: str
    version: str
    spdx_id: str
    category: str
    severity: int
    direct: bool
    status: str  # ok | violation
    reason: str


@dataclass
class AuditReport:
    policy: str
    allowed_categories: List[str]
    total: int
    violations: int
    findings: List[AuditFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.violations == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy": self.policy,
            "allowed_categories": self.allowed_categories,
            "total": self.total,
            "violations": self.violations,
            "passed": self.passed,
            "findings": [asdict(f) for f in self.findings],
        }


def _explain(dep: Dependency, allowed: set) -> Tuple[str, str]:
    """Return (status, reason) for a dependency under a policy."""
    cat = dep.license.category
    spdx = dep.license.spdx_id
    if is_compatible(cat, allowed):
        return "ok", f"{spdx} ({cat}) permitted by policy"
    if cat == "network-copyleft":
        return (
            "violation",
            f"{spdx} is network copyleft (AGPL/SSPL): use over a network "
            f"obligates you to release your full source. CONTAMINATION RISK.",
        )
    if cat == "strong-copyleft":
        return (
            "violation",
            f"{spdx} is strong copyleft: distributing software linked against "
            f"it obligates releasing the combined work under the GPL.",
        )
    if cat == "unknown":
        return (
            "violation",
            f"license '{dep.license.raw or 'NOASSERTION'}' could not be "
            f"identified; treat as unvetted until reviewed.",
        )
    if cat == "proprietary":
        return (
            "violation",
            f"{spdx} is proprietary/source-available; redistribution restricted.",
        )
    return "violation", f"{spdx} ({cat}) not permitted by policy"


def audit_dependencies(deps: List[Dependency], policy: str = "proprietary") -> AuditReport:
    """Run the compliance audit, returning a structured report."""
    if policy not in POLICY_PRESETS:
        raise ValueError(
            f"unknown policy '{policy}'; choose from {sorted(POLICY_PRESETS)}"
        )
    allowed = POLICY_PRESETS[policy]
    findings: List[AuditFinding] = []
    for dep in deps:
        status, reason = _explain(dep, allowed)
        findings.append(
            AuditFinding(
                name=dep.name,
                version=dep.version,
                spdx_id=dep.license.spdx_id,
                category=dep.license.category,
                severity=dep.license.severity,
                direct=dep.direct,
                status=status,
                reason=reason,
            )
        )
    # Sort worst-first, then by name for stability.
    findings.sort(key=lambda f: (-f.severity, f.status != "violation", f.name.lower()))
    violations = sum(1 for f in findings if f.status == "violation")
    return AuditReport(
        policy=policy,
        allowed_categories=sorted(allowed),
        total=len(deps),
        violations=violations,
        findings=findings,
    )


def load_dependencies(path_or_obj: Any) -> List[Dependency]:
    """Load dependencies from a manifest path or already-parsed object.

    Accepted shapes:
      * a JSON list of objects
      * a JSON object with a top-level "dependencies" list
    Each object: {name, version, license, direct?, homepage?, copyright?}.
    """
    if isinstance(path_or_obj, str):
        with open(path_or_obj, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = path_or_obj

    if isinstance(data, dict):
        data = data.get("dependencies", [])
    if not isinstance(data, list):
        raise ValueError("manifest must be a list or have a 'dependencies' list")

    deps: List[Dependency] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"dependency #{i} is not an object")
        name = str(entry.get("name", "")).strip()
        if not name:
            raise ValueError(f"dependency #{i} is missing a name")
        deps.append(
            Dependency(
                name=name,
                version=str(entry.get("version", "0.0.0")).strip(),
                license=LicenseInfo.from_raw(entry.get("license")),
                direct=bool(entry.get("direct", True)),
                homepage=str(entry.get("homepage", "")).strip(),
                copyright=str(entry.get("copyright", "")).strip(),
                ecosystem=str(entry.get("ecosystem", "")).strip(),
            )
        )
    return deps


def generate_notice(deps: List[Dependency], project: str = "This product") -> str:
    """Render a NOTICE / attribution document from dependency metadata."""
    lines: List[str] = []
    lines.append(f"{project} includes the following third-party open source software.")
    lines.append("")
    lines.append("=" * 70)
    lines.append("")
    for dep in sorted(deps, key=lambda d: d.name.lower()):
        lines.append(f"{dep.name} {dep.version}".rstrip())
        lines.append(f"  License: {dep.license.spdx_id} ({dep.license.category})")
        if dep.homepage:
            lines.append(f"  Homepage: {dep.homepage}")
        if dep.copyright:
            lines.append(f"  {dep.copyright}")
        lines.append("")
    # Summary of distinct licenses for legal review.
    distinct = sorted({d.license.spdx_id for d in deps})
    lines.append("=" * 70)
    lines.append("Licenses present: " + ", ".join(distinct))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SARIF 2.1.0 export
# ---------------------------------------------------------------------------
# Map our copyleft categories to SARIF result levels. SARIF defines four
# levels: error | warning | note | none. Violations that block distribution
# are errors; "ok" findings are reported as notes for full visibility.
_SARIF_LEVEL_BY_CATEGORY: Dict[str, str] = {
    "network-copyleft": "error",
    "strong-copyleft": "error",
    "proprietary": "error",
    "unknown": "warning",
    "weak-copyleft": "note",
    "permissive": "note",
    "public-domain": "note",
}

# Stable rule ids per category so downstream code-scanning UIs can group results.
_SARIF_RULE_BY_CATEGORY: Dict[str, Tuple[str, str]] = {
    "network-copyleft": ("OSSAUDIT-NETWORK-COPYLEFT",
                         "Network-copyleft dependency (AGPL/SSPL)"),
    "strong-copyleft": ("OSSAUDIT-STRONG-COPYLEFT",
                        "Strong-copyleft dependency (GPL)"),
    "weak-copyleft": ("OSSAUDIT-WEAK-COPYLEFT",
                      "Weak-copyleft dependency (LGPL/MPL/EPL)"),
    "proprietary": ("OSSAUDIT-PROPRIETARY",
                    "Proprietary / source-available dependency"),
    "unknown": ("OSSAUDIT-UNKNOWN-LICENSE",
                "Unidentified or unasserted license"),
    "permissive": ("OSSAUDIT-PERMISSIVE", "Permissive dependency"),
    "public-domain": ("OSSAUDIT-PUBLIC-DOMAIN", "Public-domain dependency"),
}


def to_sarif(report: "AuditReport", manifest_path: str = "manifest.json") -> Dict[str, Any]:
    """Render an AuditReport as a SARIF 2.1.0 log object.

    The manifest path is recorded as the physical artifact location so that
    code-scanning tools (GitHub, Azure DevOps, etc.) anchor each finding to the
    dependency manifest. Only the categories actually present become reporting
    descriptors (rules), keeping the run self-describing.
    """
    rules: List[Dict[str, Any]] = []
    seen_rules = set()
    results: List[Dict[str, Any]] = []

    for f in report.findings:
        rule_id, rule_name = _SARIF_RULE_BY_CATEGORY.get(
            f.category, ("OSSAUDIT-UNKNOWN-LICENSE", "Unidentified license")
        )
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL_BY_CATEGORY.get(f.category, "warning")
                },
            })
        # Report only meaningful results: violations always; ok findings as notes.
        level = (_SARIF_LEVEL_BY_CATEGORY.get(f.category, "warning")
                 if f.status == "violation" else "note")
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{f.name} {f.version} [{f.spdx_id}]: {f.reason}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest_path}
                },
                "logicalLocations": [{
                    "name": f.name,
                    "fullyQualifiedName": f"{f.name}@{f.version}",
                    "kind": "module",
                }],
            }],
            "properties": {
                "spdxId": f.spdx_id,
                "category": f.category,
                "severity": f.severity,
                "direct": f.direct,
                "status": f.status,
                "policy": report.policy,
            },
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/cognis-digital/ossaudit",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
