// ossaudit (Rust port) — OSS license-compliance auditor.
//
// Mirrors the reference Python CLI's `audit` command: normalise each SPDX-ish
// license id, classify copyleft strength, and decide whether each dependency is
// permitted under a distribution-policy preset. No external crates, no network.
//
//   cargo run -- audit deps.json --policy proprietary
//   cargo run -- audit deps.json --format json
//
// Exit code 2 on policy violations (matches the Python tool).
// Defensive / authorized-use only.

use std::env;
use std::fs;
use std::process::exit;

const TOOL_NAME: &str = "ossaudit";
const TOOL_VERSION: &str = "0.3.0-rust";

fn category_severity(cat: &str) -> i32 {
    match cat {
        "network-copyleft" => 5,
        "strong-copyleft" | "proprietary" => 4,
        "unknown" => 3,
        "weak-copyleft" => 2,
        "permissive" => 1,
        "public-domain" => 0,
        _ => 3,
    }
}

fn classify(canonical: &str) -> &'static str {
    match canonical {
        "MIT" | "BSD-2-Clause" | "BSD-3-Clause" | "Apache-2.0" | "ISC" | "Zlib"
        | "BSL-1.0" | "CC-BY-4.0" => "permissive",
        "Unlicense" | "CC0-1.0" | "0BSD" => "public-domain",
        "LGPL-2.1-only" | "LGPL-3.0-only" | "MPL-2.0" | "EPL-2.0" | "CC-BY-SA-4.0" => {
            "weak-copyleft"
        }
        "GPL-2.0-only" | "GPL-2.0-or-later" | "GPL-3.0-only" | "GPL-3.0-or-later" => {
            "strong-copyleft"
        }
        "AGPL-3.0-only" | "AGPL-3.0-or-later" | "SSPL-1.0" => "network-copyleft",
        "BUSL-1.1" | "Elastic-2.0" | "Commercial" | "Proprietary" => "proprietary",
        _ => "unknown",
    }
}

fn squash(s: &str) -> String {
    s.to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '+')
        .collect::<String>()
        .trim_end_matches('.')
        .to_string()
}

fn alias(key: &str) -> Option<&'static str> {
    Some(match key {
        "APACHE" | "APACHE2" | "APACHE2.0" => "Apache-2.0",
        "BSD" | "BSD3" | "NEWBSD" => "BSD-3-Clause",
        "BSD2" => "BSD-2-Clause",
        "MITLICENSE" | "THEMITLICENSE" | "EXPAT" => "MIT",
        "GPL" => "GPL-3.0-or-later",
        "GPL3" | "GPLV3" => "GPL-3.0-only",
        "GPL2" | "GPLV2" => "GPL-2.0-only",
        "LGPL" | "LGPLV3" => "LGPL-3.0-only",
        "LGPL2" => "LGPL-2.1-only",
        "AGPL" => "AGPL-3.0-or-later",
        "AGPL3" | "AGPLV3" => "AGPL-3.0-only",
        "MPL" | "MOZILLA" => "MPL-2.0",
        "CC0" => "CC0-1.0",
        _ => return None,
    })
}

const CANON: &[&str] = &[
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Zlib", "BSL-1.0",
    "CC-BY-4.0", "Unlicense", "CC0-1.0", "0BSD", "LGPL-2.1-only", "LGPL-3.0-only",
    "MPL-2.0", "EPL-2.0", "CC-BY-SA-4.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "Commercial", "Proprietary",
];

fn normalize_license(raw: &str) -> String {
    let mut t = raw.trim().to_string();
    if t.is_empty() {
        return "NOASSERTION".into();
    }
    if t.starts_with('(') && t.ends_with(')') {
        t = t[1..t.len() - 1].trim().to_string();
    }
    // SPDX OR -> least severe.
    let up = t.to_uppercase();
    if up.contains(" OR ") {
        let mut best = "NOASSERTION".to_string();
        let mut best_sev = i32::MAX;
        for p in split_top(&t, " OR ") {
            let c = normalize_license(&p);
            let s = category_severity(classify(&c));
            if s < best_sev {
                best = c;
                best_sev = s;
            }
        }
        return best;
    }
    if up.contains(" AND ") {
        let mut worst = "NOASSERTION".to_string();
        let mut worst_sev = -1;
        for p in split_top(&t, " AND ") {
            let c = normalize_license(&p);
            let s = category_severity(classify(&c));
            if s > worst_sev {
                worst = c;
                worst_sev = s;
            }
        }
        return worst;
    }
    for canon in CANON {
        if t.eq_ignore_ascii_case(canon) {
            return canon.to_string();
        }
    }
    let key = squash(&t);
    if let Some(a) = alias(&key) {
        return a.to_string();
    }
    if let Some(stripped) = key.strip_suffix('+') {
        if let Some(a) = alias(stripped) {
            return a.to_string();
        }
    }
    "NOASSERTION".into()
}

fn split_top(expr: &str, op: &str) -> Vec<String> {
    let up = expr.to_uppercase();
    let op_t = op.trim();
    if !up.contains(op_t) {
        return vec![expr.to_string()];
    }
    // case-insensitive split on the padded operator
    let mut parts = Vec::new();
    let mut rest = expr.to_string();
    loop {
        let r_up = rest.to_uppercase();
        if let Some(idx) = r_up.find(op) {
            parts.push(rest[..idx].trim().to_string());
            rest = rest[idx + op.len()..].to_string();
        } else {
            parts.push(rest.trim().to_string());
            break;
        }
    }
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

fn allowed_categories(policy: &str) -> Vec<&'static str> {
    match policy {
        "permissive-only" => vec!["permissive", "public-domain"],
        "gpl-project" => vec!["permissive", "public-domain", "weak-copyleft", "strong-copyleft"],
        "permissive-audit" => vec![
            "permissive", "public-domain", "weak-copyleft", "strong-copyleft",
            "network-copyleft", "proprietary", "unknown",
        ],
        // proprietary | distribute-binary | default
        _ => vec!["permissive", "public-domain", "weak-copyleft"],
    }
}

struct Dep {
    name: String,
    version: String,
    license: String,
}

struct Finding {
    name: String,
    version: String,
    spdx: String,
    category: &'static str,
    severity: i32,
    status: &'static str,
}

// Minimal field extractor for the simple manifest shape this tool consumes.
fn extract_string(obj: &str, key: &str) -> String {
    let pat = format!("\"{}\"", key);
    if let Some(k) = obj.find(&pat) {
        let after = &obj[k + pat.len()..];
        if let Some(colon) = after.find(':') {
            let mut v = after[colon + 1..].trim_start();
            if let Some(stripped) = v.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    return stripped[..end].to_string();
                }
            } else {
                // unquoted (number/bool) — read until , or }
                let end = v.find([',', '}']).unwrap_or(v.len());
                v = v[..end].trim();
                return v.to_string();
            }
        }
    }
    String::new()
}

fn parse_manifest(text: &str) -> Vec<Dep> {
    // Find the dependencies array (or treat the whole doc as the array).
    let body = match text.find("\"dependencies\"") {
        Some(i) => &text[i..],
        None => text,
    };
    let start = body.find('[').map(|i| i + 1).unwrap_or(0);
    let end = body.rfind(']').unwrap_or(body.len());
    let arr = &body[start..end];
    let mut deps = Vec::new();
    let mut depth = 0i32;
    let mut obj_start = None;
    for (i, ch) in arr.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = obj_start {
                        let obj = &arr[s..=i];
                        let name = extract_string(obj, "name");
                        if !name.is_empty() {
                            deps.push(Dep {
                                name,
                                version: {
                                    let v = extract_string(obj, "version");
                                    if v.is_empty() { "0.0.0".into() } else { v }
                                },
                                license: extract_string(obj, "license"),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    deps
}

fn audit(deps: &[Dep], policy: &str) -> (Vec<Finding>, usize) {
    let allowed = allowed_categories(policy);
    let mut findings: Vec<Finding> = deps
        .iter()
        .map(|d| {
            let spdx = normalize_license(&d.license);
            let category = classify(&spdx);
            let status = if allowed.contains(&category) { "ok" } else { "violation" };
            Finding {
                name: d.name.clone(),
                version: d.version.clone(),
                spdx,
                category,
                severity: category_severity(category),
                status,
            }
        })
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let violations = findings.iter().filter(|f| f.status == "violation").count();
    (findings, violations)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        println!("{} {}", TOOL_NAME, TOOL_VERSION);
        return;
    }
    if args.len() < 2 || args[0] != "audit" {
        eprintln!("usage: ossaudit audit <manifest.json> [--policy P] [--format json]");
        exit(1);
    }
    let path = &args[1];
    let mut policy = "proprietary".to_string();
    let mut format = "table".to_string();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" if i + 1 < args.len() => { policy = args[i + 1].clone(); i += 1; }
            "--format" if i + 1 < args.len() => { format = args[i + 1].clone(); i += 1; }
            _ => {}
        }
        i += 1;
    }
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => { eprintln!("{}: error: {}", TOOL_NAME, e); exit(1); }
    };
    let deps = parse_manifest(&text);
    let (findings, violations) = audit(&deps, &policy);
    let passed = violations == 0;
    if format == "json" {
        println!("{{");
        println!("  \"policy\": \"{}\",", policy);
        println!("  \"total\": {},", deps.len());
        println!("  \"violations\": {},", violations);
        println!("  \"passed\": {}", passed);
        println!("}}");
    } else {
        println!("Policy: {}   Deps: {}   Violations: {}", policy, deps.len(), violations);
        println!("{}", "-".repeat(70));
        for f in &findings {
            let mark = if f.status == "violation" { "VIOLATION" } else { "ok" };
            println!("{:<10} {:<2} {:<24} {:<12} {}", mark, f.severity, f.name, f.version, f.spdx);
        }
        println!("{}", "-".repeat(70));
        println!("RESULT: {}", if passed { "PASS" } else { "FAIL" });
    }
    if !passed {
        exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases() {
        assert_eq!(normalize_license("Apache 2.0"), "Apache-2.0");
        assert_eq!(normalize_license("BSD"), "BSD-3-Clause");
        assert_eq!(normalize_license("the MIT License"), "MIT");
        assert_eq!(normalize_license("AGPLv3"), "AGPL-3.0-only");
        assert_eq!(normalize_license(""), "NOASSERTION");
        assert_eq!(normalize_license("weird custom"), "NOASSERTION");
    }

    #[test]
    fn spdx_expressions() {
        assert_eq!(normalize_license("MIT OR GPL-3.0-only"), "MIT");
        assert_eq!(normalize_license("MIT AND GPL-3.0-only"), "GPL-3.0-only");
    }

    #[test]
    fn categories() {
        assert_eq!(classify("MIT"), "permissive");
        assert_eq!(classify("LGPL-3.0-only"), "weak-copyleft");
        assert_eq!(classify("GPL-3.0-only"), "strong-copyleft");
        assert_eq!(classify("AGPL-3.0-only"), "network-copyleft");
        assert_eq!(classify("SSPL-1.0"), "network-copyleft");
        assert_eq!(classify("NOASSERTION"), "unknown");
    }

    #[test]
    fn audit_fails_on_copyleft() {
        let deps = vec![
            Dep { name: "requests".into(), version: "2.0".into(), license: "Apache-2.0".into() },
            Dep { name: "analytics".into(), version: "1.0".into(), license: "AGPL-3.0-only".into() },
            Dep { name: "chart".into(), version: "4.0".into(), license: "GPL-3.0-only".into() },
        ];
        let (findings, viol) = audit(&deps, "proprietary");
        assert_eq!(viol, 2);
        assert!(findings[0].severity >= findings[findings.len() - 1].severity);
    }

    #[test]
    fn parse_manifest_object_form() {
        let text = r#"{"dependencies":[{"name":"a","version":"1.0","license":"MIT"},
                        {"name":"b","version":"2.0","license":"AGPL-3.0-only"}]}"#;
        let deps = parse_manifest(text);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "a");
        assert_eq!(deps[1].license, "AGPL-3.0-only");
    }

    #[test]
    fn audit_passes_permissive() {
        let deps = vec![
            Dep { name: "a".into(), version: "1".into(), license: "MIT".into() },
        ];
        let (_, viol) = audit(&deps, "proprietary");
        assert_eq!(viol, 0);
    }
}
