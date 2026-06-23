// Smoke tests for the Node port. Run: node test.js  (stdlib assert only)
import assert from "assert";
import { normalizeLicense, classify, audit } from "./index.js";

let n = 0;
function check(name, fn) { fn(); n++; }

check("aliases", () => {
  assert.strictEqual(normalizeLicense("Apache 2.0"), "Apache-2.0");
  assert.strictEqual(normalizeLicense("BSD"), "BSD-3-Clause");
  assert.strictEqual(normalizeLicense("the MIT License"), "MIT");
  assert.strictEqual(normalizeLicense("AGPLv3"), "AGPL-3.0-only");
});

check("empty/unknown", () => {
  assert.strictEqual(normalizeLicense(""), "NOASSERTION");
  assert.strictEqual(normalizeLicense(null), "NOASSERTION");
  assert.strictEqual(normalizeLicense("custom thing"), "NOASSERTION");
});

check("spdx OR/AND", () => {
  assert.strictEqual(normalizeLicense("MIT OR GPL-3.0-only"), "MIT");
  assert.strictEqual(normalizeLicense("MIT AND GPL-3.0-only"), "GPL-3.0-only");
});

check("classify", () => {
  assert.strictEqual(classify("MIT"), "permissive");
  assert.strictEqual(classify("LGPL-3.0-only"), "weak-copyleft");
  assert.strictEqual(classify("GPL-3.0-only"), "strong-copyleft");
  assert.strictEqual(classify("AGPL-3.0-only"), "network-copyleft");
  assert.strictEqual(classify("SSPL-1.0"), "network-copyleft");
  assert.strictEqual(classify("NOASSERTION"), "unknown");
});

check("audit fails on copyleft", () => {
  const r = audit([
    { name: "requests", version: "2.0", license: "Apache-2.0" },
    { name: "analytics", version: "1.0", license: "AGPL-3.0-only" },
    { name: "chart", version: "4.0", license: "GPL-3.0-only" },
  ], "proprietary");
  assert.strictEqual(r.passed, false);
  assert.strictEqual(r.violations, 2);
  // worst-first
  assert.ok(r.findings[0].severity >= r.findings[r.findings.length - 1].severity);
});

check("audit passes when permissive", () => {
  const r = audit([{ name: "a", version: "1", license: "MIT" }], "proprietary");
  assert.strictEqual(r.passed, true);
});

console.log(`ok - ${n} test groups passed`);
