"""Command line interface for OSSAUDIT.

Subcommands:
  audit    - scan a dependency manifest for license-policy violations
  notice   - generate a NOTICE / attribution file from the manifest
  vulnscan - cross-reference dependencies against OSV.dev known vulnerabilities
  feeds    - manage the bundled edge/air-gap data-feed cache (OSV)

Global:
  --version          print tool version
  --format {table,json}

Exit codes:
  0  audit passed / command succeeded
  1  unexpected error (bad manifest, IO, etc.)
  2  audit found policy violations / vulnscan found known vulnerabilities
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    POLICY_PRESETS,
    audit_dependencies,
    generate_notice,
    load_dependencies,
    to_sarif,
)

# Feed ids from the bundled catalog (data_feeds_2026.json) that THIS tool
# consumes. ossaudit maps components to OSV.dev vulnerabilities; see SOURCES.md.
RELEVANT_FEEDS = ["osv"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VIOLATIONS = 2


def _render_audit_table(report) -> str:
    out: List[str] = []
    out.append(f"Policy: {report.policy}   Deps: {report.total}   "
               f"Violations: {report.violations}")
    out.append("-" * 78)
    out.append(f"{'STATUS':<10}{'SEV':<5}{'NAME':<24}{'VERSION':<12}{'LICENSE':<18}")
    out.append("-" * 78)
    for f in report.findings:
        mark = "VIOLATION" if f.status == "violation" else "ok"
        name = (f.name[:23]) if len(f.name) > 23 else f.name
        ver = (f.version[:11]) if len(f.version) > 11 else f.version
        lic = (f.spdx_id[:17]) if len(f.spdx_id) > 17 else f.spdx_id
        out.append(f"{mark:<10}{f.severity:<5}{name:<24}{ver:<12}{lic:<18}")
    out.append("-" * 78)
    for f in report.findings:
        if f.status == "violation":
            out.append(f"  ! {f.name} {f.version}: {f.reason}")
    out.append("")
    out.append("RESULT: " + ("PASS" if report.passed else "FAIL"))
    return "\n".join(out)


def _cmd_audit(args) -> int:
    deps = load_dependencies(args.manifest)
    report = audit_dependencies(deps, policy=args.policy)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(report, manifest_path=args.manifest), indent=2))
    else:
        print(_render_audit_table(report))
    return EXIT_OK if report.passed else EXIT_VIOLATIONS


def _cmd_notice(args) -> int:
    deps = load_dependencies(args.manifest)
    text = generate_notice(deps, project=args.project)
    if args.format == "json":
        print(json.dumps({
            "project": args.project,
            "dependency_count": len(deps),
            "notice": text,
        }, indent=2))
    else:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"Wrote NOTICE for {len(deps)} dependencies to {args.output}")
        else:
            print(text)
    return EXIT_OK


def _render_vuln_table(report) -> str:
    out: List[str] = []
    out.append(f"OSV scan   Deps: {report.total}   Vulnerable: {report.vulnerable}   "
               f"(default ecosystem: {report.ecosystem_default})")
    out.append("-" * 78)
    out.append(f"{'SEVERITY':<10}{'#':<4}{'NAME':<22}{'VERSION':<12}{'ECOSYSTEM':<10}")
    out.append("-" * 78)
    for f in report.findings:
        name = f.name[:21]
        ver = f.version[:11]
        out.append(f"{f.max_severity:<10}{f.vuln_count:<4}{name:<22}{ver:<12}{f.ecosystem:<10}")
    out.append("-" * 78)
    for f in report.findings:
        if f.vuln_count:
            ids = ", ".join((f.cve_ids or f.osv_ids)[:6])
            out.append(f"  ! {f.name} {f.version}: {f.vuln_count} known vuln(s) [{ids}]")
            if f.summaries:
                out.append(f"      {f.summaries[0][:72]}")
    out.append("")
    out.append("RESULT: " + ("CLEAN" if report.clean else "VULNERABLE"))
    return "\n".join(out)


def _cmd_vulnscan(args) -> int:
    from .vulnscan import scan_dependencies
    deps = load_dependencies(args.manifest)
    report = scan_dependencies(deps, ecosystem=args.ecosystem, offline=args.offline)
    if args.format in ("json", "sarif"):
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_vuln_table(report))
    return EXIT_OK if report.clean else EXIT_VIOLATIONS


def _cmd_feeds(args) -> int:
    from . import datafeeds
    catalog = datafeeds.load_catalog()
    relevant = {f["id"]: f for f in catalog.get("feeds", [])
                if f["id"] in RELEVANT_FEEDS}

    if args.feeds_cmd == "list":
        for fid, f in relevant.items():
            age = datafeeds.cached_age_hours(fid)
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {fid:8} {f.get('domain',''):8} [{fresh}]  {f['name']}")
            print(f"           {f['url']}")
        return EXIT_OK

    if args.feeds_cmd == "get":
        if args.id not in relevant:
            print(f"{TOOL_NAME}: feed '{args.id}' is not consumed by this tool; "
                  f"relevant: {RELEVANT_FEEDS}", file=sys.stderr)
            return EXIT_ERROR
        try:
            data = datafeeds.get(args.id, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as exc:
            print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(json.dumps(data, indent=2)[:4000]
              if isinstance(data, (dict, list)) else str(data)[:4000])
        return EXIT_OK

    if args.feeds_cmd == "update":
        ids = args.ids or RELEVANT_FEEDS
        rc = EXIT_OK
        for fid in ids:
            if fid not in relevant:
                print(f"  {fid}: not consumed by this tool (relevant: {RELEVANT_FEEDS})",
                      file=sys.stderr)
                rc = EXIT_ERROR
                continue
            try:
                pth = datafeeds.update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as exc:
                print(f"  {fid}: {exc}", file=sys.stderr)
                rc = EXIT_ERROR
        return rc

    if args.feeds_cmd == "warm":
        # Pre-fetch OSV results for every dependency so a later --offline scan
        # (e.g. on an air-gapped enclave) has a complete cache.
        from .vulnscan import query_osv
        deps = load_dependencies(args.manifest)
        n = 0
        for dep in deps:
            eco = dep.ecosystem or args.ecosystem
            try:
                query_osv(dep.name, dep.version, eco, offline=False)
                n += 1
            except ConnectionError as exc:
                print(f"  {dep.name}@{dep.version}: {exc}", file=sys.stderr)
        print(f"warmed OSV cache for {n}/{len(deps)} dependencies "
              f"(snapshot with: python -m ossaudit.datafeeds snapshot-export <file>)")
        return EXIT_OK

    return EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="OSS license compliance auditor: AGPL contamination + NOTICE generation.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json", "sarif"], default="table",
                   help="output format (default: table). sarif = SARIF 2.1.0 "
                        "for code-scanning (audit only)")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="scan a manifest for policy violations")
    a.add_argument("manifest", help="path to dependency manifest JSON")
    a.add_argument("--policy", choices=sorted(POLICY_PRESETS), default="proprietary",
                   help="distribution policy preset (default: proprietary)")
    a.set_defaults(func=_cmd_audit)

    n = sub.add_parser("notice", help="generate a NOTICE attribution file")
    n.add_argument("manifest", help="path to dependency manifest JSON")
    n.add_argument("--project", default="This product",
                   help="product name used in the NOTICE header")
    n.add_argument("--output", "-o", default="",
                   help="write NOTICE to this file instead of stdout (table mode)")
    n.set_defaults(func=_cmd_notice)

    v = sub.add_parser("vulnscan",
                       help="cross-reference deps against OSV.dev known vulnerabilities")
    v.add_argument("manifest", help="path to dependency manifest JSON")
    v.add_argument("--ecosystem", default="PyPI",
                   help="default OSV ecosystem when a dep declares none "
                        "(PyPI/npm/Go/Maven/crates.io/...; default: PyPI)")
    v.add_argument("--offline", action="store_true",
                   help="serve OSV results from the local cache only (air-gap)")
    v.set_defaults(func=_cmd_vulnscan)

    fe = sub.add_parser("feeds",
                        help="manage the bundled OSV data-feed cache (edge/air-gap)")
    fsub = fe.add_subparsers(dest="feeds_cmd", required=True)
    fl = fsub.add_parser("list", help="list the feeds this tool consumes")
    fl.set_defaults(func=_cmd_feeds)
    fu = fsub.add_parser("update", help="fetch + cache feed(s)")
    fu.add_argument("ids", nargs="*", help=f"feed ids (default: {RELEVANT_FEEDS})")
    fu.set_defaults(func=_cmd_feeds)
    fg = fsub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("id", help="feed id")
    fg.add_argument("--offline", action="store_true",
                    help="read cache only, never touch the network")
    fg.set_defaults(func=_cmd_feeds)
    fw = fsub.add_parser("warm",
                         help="pre-fetch OSV results for every dep in a manifest")
    fw.add_argument("manifest", help="path to dependency manifest JSON")
    fw.add_argument("--ecosystem", default="PyPI",
                    help="default ecosystem for deps that declare none")
    fw.set_defaults(func=_cmd_feeds)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"{TOOL_NAME}: error: file not found: {exc.filename}", file=sys.stderr)
        return EXIT_ERROR
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
