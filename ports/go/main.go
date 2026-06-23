// ossaudit (Go port) — OSS license-compliance auditor.
//
// Mirrors the core surface of the reference Python CLI's `audit` command:
// it reads a dependency manifest (JSON), normalises each SPDX-ish license id,
// classifies its copyleft strength, and decides whether each dependency is
// permitted under a distribution-policy preset. Standard library only; no
// network. Output: a table (default) or JSON (--format json). Exit code 2 when
// the manifest contains policy violations, matching the Python tool.
//
//	go run . audit deps.json --policy proprietary
//	go run . audit deps.json --format json
//
// Defensive / authorized-use only.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const toolName = "ossaudit"
const toolVersion = "0.3.0-go"

// category severity: higher = worse (mirrors core.CATEGORY_SEVERITY).
var categorySeverity = map[string]int{
	"network-copyleft": 5,
	"strong-copyleft":  4,
	"proprietary":      4,
	"unknown":          3,
	"weak-copyleft":    2,
	"permissive":       1,
	"public-domain":    0,
}

var licenseRules = map[string]string{
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
}

var licenseAliases = map[string]string{
	"APACHE": "Apache-2.0", "APACHE2": "Apache-2.0", "APACHE2.0": "Apache-2.0",
	"BSD": "BSD-3-Clause", "BSD3": "BSD-3-Clause", "NEWBSD": "BSD-3-Clause",
	"BSD2": "BSD-2-Clause", "MITLICENSE": "MIT", "THEMITLICENSE": "MIT", "EXPAT": "MIT",
	"GPL": "GPL-3.0-or-later", "GPL3": "GPL-3.0-only", "GPLV3": "GPL-3.0-only",
	"GPL2": "GPL-2.0-only", "GPLV2": "GPL-2.0-only",
	"LGPL": "LGPL-3.0-only", "LGPLV3": "LGPL-3.0-only", "LGPL2": "LGPL-2.1-only",
	"AGPL": "AGPL-3.0-or-later", "AGPL3": "AGPL-3.0-only", "AGPLV3": "AGPL-3.0-only",
	"MPL": "MPL-2.0", "MOZILLA": "MPL-2.0", "CC0": "CC0-1.0",
}

var policyPresets = map[string]map[string]bool{
	"proprietary":       set("permissive", "public-domain", "weak-copyleft"),
	"distribute-binary": set("permissive", "public-domain", "weak-copyleft"),
	"permissive-only":   set("permissive", "public-domain"),
	"gpl-project":       set("permissive", "public-domain", "weak-copyleft", "strong-copyleft"),
	"permissive-audit": set("permissive", "public-domain", "weak-copyleft",
		"strong-copyleft", "network-copyleft", "proprietary", "unknown"),
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '+' {
			b.WriteRune(r)
		}
	}
	return strings.TrimRight(b.String(), ".")
}

// NormalizeLicense maps a free-form license string to a canonical SPDX id,
// handling simple SPDX `OR` (pick least severe) / `AND` (pick most severe).
func NormalizeLicense(raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "NOASSERTION"
	}
	t = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(t, "("), ")"))

	if parts := splitTop(t, " OR "); len(parts) > 1 {
		best, bestSev := "NOASSERTION", 99
		for _, p := range parts {
			c := NormalizeLicense(p)
			if s := categorySeverity[Classify(c)]; s < bestSev {
				best, bestSev = c, s
			}
		}
		return best
	}
	if parts := splitTop(t, " AND "); len(parts) > 1 {
		worst, worstSev := "NOASSERTION", -1
		for _, p := range parts {
			c := NormalizeLicense(p)
			if s := categorySeverity[Classify(c)]; s > worstSev {
				worst, worstSev = c, s
			}
		}
		return worst
	}
	for canon := range licenseRules {
		if strings.EqualFold(t, canon) {
			return canon
		}
	}
	key := squash(t)
	if v, ok := licenseAliases[key]; ok {
		return v
	}
	if strings.HasSuffix(key, "+") {
		if v, ok := licenseAliases[strings.TrimSuffix(key, "+")]; ok {
			return v
		}
	}
	return "NOASSERTION"
}

func splitTop(expr, op string) []string {
	if !strings.Contains(strings.ToUpper(expr), strings.TrimSpace(op)) {
		return []string{expr}
	}
	up := strings.ToUpper(expr)
	var parts []string
	last := 0
	for {
		i := strings.Index(up[last:], op)
		if i < 0 {
			break
		}
		parts = append(parts, strings.TrimSpace(expr[last:last+i]))
		last += i + len(op)
	}
	parts = append(parts, strings.TrimSpace(expr[last:]))
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{expr}
	}
	return out
}

// Classify returns the copyleft category for a canonical license id.
func Classify(canonical string) string {
	if c, ok := licenseRules[canonical]; ok {
		return c
	}
	return "unknown"
}

type dep struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type manifest struct {
	Dependencies []dep `json:"dependencies"`
}

type finding struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	SpdxID   string `json:"spdx_id"`
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Status   string `json:"status"`
}

type report struct {
	Policy     string    `json:"policy"`
	Total      int       `json:"total"`
	Violations int       `json:"violations"`
	Passed     bool      `json:"passed"`
	Findings   []finding `json:"findings"`
}

func loadDeps(path string) ([]dep, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err == nil && m.Dependencies != nil {
		return m.Dependencies, nil
	}
	var ds []dep
	if err := json.Unmarshal(b, &ds); err != nil {
		return nil, err
	}
	return ds, nil
}

// Audit runs the compliance audit and returns a report.
func Audit(deps []dep, policy string) report {
	allowed, ok := policyPresets[policy]
	if !ok {
		allowed = policyPresets["proprietary"]
	}
	var fs []finding
	viol := 0
	for _, d := range deps {
		spdx := NormalizeLicense(d.License)
		cat := Classify(spdx)
		status := "ok"
		if !allowed[cat] {
			status = "violation"
			viol++
		}
		fs = append(fs, finding{d.Name, d.Version, spdx, cat, categorySeverity[cat], status})
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return strings.ToLower(fs[i].Name) < strings.ToLower(fs[j].Name)
	})
	return report{policy, len(deps), viol, viol == 0, fs}
}

func renderTable(r report) {
	fmt.Printf("Policy: %s   Deps: %d   Violations: %d\n", r.Policy, r.Total, r.Violations)
	fmt.Println(strings.Repeat("-", 70))
	for _, f := range r.Findings {
		mark := "ok"
		if f.Status == "violation" {
			mark = "VIOLATION"
		}
		fmt.Printf("%-10s %-2d %-24s %-12s %s\n", mark, f.Severity, f.Name, f.Version, f.SpdxID)
	}
	fmt.Println(strings.Repeat("-", 70))
	if r.Passed {
		fmt.Println("RESULT: PASS")
	} else {
		fmt.Println("RESULT: FAIL")
	}
}

func main() {
	args := os.Args[1:]
	if len(args) >= 1 && args[0] == "--version" {
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return
	}
	if len(args) < 2 || args[0] != "audit" {
		fmt.Fprintln(os.Stderr, "usage: ossaudit audit <manifest.json> [--policy P] [--format json]")
		os.Exit(1)
	}
	manifestPath := args[1]
	policy := "proprietary"
	format := "table"
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 < len(args) {
				policy = args[i+1]
				i++
			}
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		}
	}
	deps, err := loadDeps(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", toolName, err)
		os.Exit(1)
	}
	r := Audit(deps, policy)
	if format == "json" {
		out, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(out))
	} else {
		renderTable(r)
	}
	if !r.Passed {
		os.Exit(2)
	}
}
