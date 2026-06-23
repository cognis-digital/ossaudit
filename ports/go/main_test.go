package main

import "testing"

func TestNormalizeAliases(t *testing.T) {
	cases := map[string]string{
		"Apache 2.0":     "Apache-2.0",
		"BSD":            "BSD-3-Clause",
		"the MIT License": "MIT",
		"AGPLv3":         "AGPL-3.0-only",
		"":               "NOASSERTION",
		"totally custom": "NOASSERTION",
	}
	for in, want := range cases {
		if got := NormalizeLicense(in); got != want {
			t.Errorf("NormalizeLicense(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"MIT":           "permissive",
		"LGPL-3.0-only": "weak-copyleft",
		"GPL-3.0-only":  "strong-copyleft",
		"AGPL-3.0-only": "network-copyleft",
		"SSPL-1.0":      "network-copyleft",
		"NOASSERTION":   "unknown",
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSpdxExpressions(t *testing.T) {
	if got := NormalizeLicense("MIT OR GPL-3.0-only"); got != "MIT" {
		t.Errorf("OR should pick permissive, got %q", got)
	}
	if got := NormalizeLicense("MIT AND GPL-3.0-only"); got != "GPL-3.0-only" {
		t.Errorf("AND should pick restrictive, got %q", got)
	}
}

func TestAuditViolations(t *testing.T) {
	deps := []dep{
		{"requests", "2.0", "Apache-2.0"},
		{"analytics", "1.0", "AGPL-3.0-only"},
		{"chart", "4.0", "GPL-3.0-only"},
	}
	r := Audit(deps, "proprietary")
	if r.Passed {
		t.Error("expected FAIL on AGPL+GPL under proprietary")
	}
	if r.Violations != 2 {
		t.Errorf("expected 2 violations, got %d", r.Violations)
	}
	// worst-first ordering: highest severity finding leads.
	if r.Findings[0].Severity < r.Findings[len(r.Findings)-1].Severity {
		t.Error("findings not sorted worst-first")
	}
}

func TestAuditPasses(t *testing.T) {
	deps := []dep{{"a", "1", "MIT"}, {"b", "1", "Apache-2.0"}}
	if !Audit(deps, "proprietary").Passed {
		t.Error("all-permissive manifest should pass proprietary policy")
	}
}
