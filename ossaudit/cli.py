"""Command line interface for OSSAUDIT.

Subcommands:
  audit   - scan a dependency manifest for license-policy violations
  notice  - generate a NOTICE / attribution file from the manifest

Global:
  --version          print tool version
  --format {table,json}

Exit codes:
  0  audit passed / command succeeded
  1  unexpected error (bad manifest, IO, etc.)
  2  audit found policy violations
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
)

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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="OSS license compliance auditor: AGPL contamination + NOTICE generation.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")
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
