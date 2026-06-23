#!/usr/bin/env node
// ossaudit (Node port) — OSS license-compliance auditor.
//
// Mirrors the reference Python CLI's `audit` command: read a dependency
// manifest (JSON), normalise each SPDX-ish license id, classify copyleft
// strength, and decide whether each dependency is permitted under a
// distribution-policy preset. Standard library only, no network.
//
//   node index.js audit deps.json --policy proprietary
//   node index.js audit deps.json --format json
//
// Exit code 2 on policy violations (matches the Python tool).
// Defensive / authorized-use only.
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

export const TOOL_NAME = "ossaudit";
export const TOOL_VERSION = "0.3.0-node";

export const CATEGORY_SEVERITY = {
  "network-copyleft": 5, "strong-copyleft": 4, "proprietary": 4,
  "unknown": 3, "weak-copyleft": 2, "permissive": 1, "public-domain": 0,
};

const LICENSE_RULES = {
  "MIT": "permissive", "BSD-2-Clause": "permissive", "BSD-3-Clause": "permissive",
  "Apache-2.0": "permissive", "ISC": "permissive", "Zlib": "permissive",
  "BSL-1.0": "permissive", "CC-BY-4.0": "permissive",
  "Unlicense": "public-domain", "CC0-1.0": "public-domain", "0BSD": "public-domain",
  "LGPL-2.1-only": "weak-copyleft", "LGPL-3.0-only": "weak-copyleft",
  "MPL-2.0": "weak-copyleft", "EPL-2.0": "weak-copyleft", "CC-BY-SA-4.0": "weak-copyleft",
  "GPL-2.0-only": "strong-copyleft", "GPL-2.0-or-later": "strong-copyleft",
  "GPL-3.0-only": "strong-copyleft", "GPL-3.0-or-later": "strong-copyleft",
  "AGPL-3.0-only": "network-copyleft", "AGPL-3.0-or-later": "network-copyleft",
  "SSPL-1.0": "network-copyleft",
  "BUSL-1.1": "proprietary", "Elastic-2.0": "proprietary",
  "Commercial": "proprietary", "Proprietary": "proprietary",
};

const LICENSE_ALIASES = {
  "APACHE": "Apache-2.0", "APACHE2": "Apache-2.0", "APACHE2.0": "Apache-2.0",
  "BSD": "BSD-3-Clause", "BSD3": "BSD-3-Clause", "NEWBSD": "BSD-3-Clause",
  "BSD2": "BSD-2-Clause", "MITLICENSE": "MIT", "THEMITLICENSE": "MIT", "EXPAT": "MIT",
  "GPL": "GPL-3.0-or-later", "GPL3": "GPL-3.0-only", "GPLV3": "GPL-3.0-only",
  "GPL2": "GPL-2.0-only", "GPLV2": "GPL-2.0-only",
  "LGPL": "LGPL-3.0-only", "LGPLV3": "LGPL-3.0-only", "LGPL2": "LGPL-2.1-only",
  "AGPL": "AGPL-3.0-or-later", "AGPL3": "AGPL-3.0-only", "AGPLV3": "AGPL-3.0-only",
  "MPL": "MPL-2.0", "MOZILLA": "MPL-2.0", "CC0": "CC0-1.0",
};

const POLICY_PRESETS = {
  "proprietary": ["permissive", "public-domain", "weak-copyleft"],
  "distribute-binary": ["permissive", "public-domain", "weak-copyleft"],
  "permissive-only": ["permissive", "public-domain"],
  "gpl-project": ["permissive", "public-domain", "weak-copyleft", "strong-copyleft"],
  "permissive-audit": ["permissive", "public-domain", "weak-copyleft",
    "strong-copyleft", "network-copyleft", "proprietary", "unknown"],
};

function squash(s) {
  return s.toUpperCase().replace(/[^A-Z0-9.+]/g, "").replace(/\.+$/, "");
}

export function normalizeLicense(raw) {
  let t = (raw == null ? "" : String(raw)).trim();
  if (!t) return "NOASSERTION";
  if (t.startsWith("(") && t.endsWith(")")) t = t.slice(1, -1).trim();

  const orParts = splitTop(t, " OR ");
  if (orParts.length > 1) {
    return orParts.map(normalizeLicense)
      .reduce((best, c) =>
        CATEGORY_SEVERITY[classify(c)] < CATEGORY_SEVERITY[classify(best)] ? c : best);
  }
  const andParts = splitTop(t, " AND ");
  if (andParts.length > 1) {
    return andParts.map(normalizeLicense)
      .reduce((worst, c) =>
        CATEGORY_SEVERITY[classify(c)] > CATEGORY_SEVERITY[classify(worst)] ? c : worst);
  }
  for (const canon of Object.keys(LICENSE_RULES))
    if (t.toLowerCase() === canon.toLowerCase()) return canon;
  const key = squash(t);
  if (LICENSE_ALIASES[key]) return LICENSE_ALIASES[key];
  if (key.endsWith("+") && LICENSE_ALIASES[key.slice(0, -1)])
    return LICENSE_ALIASES[key.slice(0, -1)];
  return "NOASSERTION";
}

function splitTop(expr, op) {
  const up = expr.toUpperCase();
  if (!up.includes(op.trim())) return [expr];
  const parts = expr.split(new RegExp(op, "i")).map((p) => p.trim()).filter(Boolean);
  return parts.length ? parts : [expr];
}

export function classify(canonical) {
  return LICENSE_RULES[canonical] || "unknown";
}

export function loadDeps(path) {
  const data = JSON.parse(readFileSync(path, "utf8"));
  const list = Array.isArray(data) ? data : (data.dependencies || []);
  return list.map((d) => ({
    name: String(d.name || ""), version: String(d.version || "0.0.0"),
    license: d.license == null ? "" : String(d.license),
  }));
}

export function audit(deps, policy = "proprietary") {
  const allowed = new Set(POLICY_PRESETS[policy] || POLICY_PRESETS["proprietary"]);
  const findings = deps.map((d) => {
    const spdx = normalizeLicense(d.license);
    const category = classify(spdx);
    const status = allowed.has(category) ? "ok" : "violation";
    return { name: d.name, version: d.version, spdx_id: spdx, category,
             severity: CATEGORY_SEVERITY[category], status };
  });
  findings.sort((a, b) => b.severity - a.severity ||
    a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  const violations = findings.filter((f) => f.status === "violation").length;
  return { policy, total: deps.length, violations, passed: violations === 0, findings };
}

function renderTable(r) {
  const lines = [`Policy: ${r.policy}   Deps: ${r.total}   Violations: ${r.violations}`,
                 "-".repeat(70)];
  for (const f of r.findings) {
    const mark = f.status === "violation" ? "VIOLATION" : "ok";
    lines.push(`${mark.padEnd(10)} ${String(f.severity).padEnd(2)} ` +
               `${f.name.padEnd(24)} ${f.version.padEnd(12)} ${f.spdx_id}`);
  }
  lines.push("-".repeat(70), "RESULT: " + (r.passed ? "PASS" : "FAIL"));
  return lines.join("\n");
}

function main(argv) {
  if (argv[0] === "--version") { console.log(`${TOOL_NAME} ${TOOL_VERSION}`); return 0; }
  if (argv.length < 2 || argv[0] !== "audit") {
    console.error("usage: ossaudit audit <manifest.json> [--policy P] [--format json]");
    return 1;
  }
  const manifest = argv[1];
  let policy = "proprietary", format = "table";
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--policy") policy = argv[++i];
    else if (argv[i] === "--format") format = argv[++i];
  }
  let r;
  try { r = audit(loadDeps(manifest), policy); }
  catch (e) { console.error(`${TOOL_NAME}: error: ${e.message}`); return 1; }
  console.log(format === "json" ? JSON.stringify(r, null, 2) : renderTable(r));
  return r.passed ? 0 : 2;
}

// Run as a CLI when invoked directly (cross-platform: compares file URLs so
// Windows drive letters / backslashes don't break the guard).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
