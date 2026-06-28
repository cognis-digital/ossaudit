<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=OSSAUDIT&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="OSSAUDIT"/>

# OSSAUDIT

### OSS license compliance auditor — AGPL contamination + NOTICE generation

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=OSS+license+compliance+auditor++AGPL+contamination++NOTICE+g;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-ossaudit.svg?color=6b46c1)](https://pypi.org/project/cognis-ossaudit/) [![CI](https://github.com/cognis-digital/ossaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/ossaudit/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Developer / Supply Chain — secrets, SBOM, CI/CD, and license hygiene.*

</div>

```bash
pip install cognis-ossaudit
ossaudit audit deps.json --policy proprietary   # → prioritized license findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ ossaudit-emit --version
ossaudit 0.3.0
```

```console
$ ossaudit-emit --help
usage: ossaudit [-h] [--version] [--format {table,json,sarif}]
                {audit,notice,vulnscan,vulndb,feeds} ...

OSS license compliance auditor: AGPL contamination + NOTICE generation.

positional arguments:
  {audit,notice,vulnscan,vulndb,feeds}
    audit               scan a manifest for policy violations
    notice              generate a NOTICE attribution file
    vulnscan            cross-reference deps against OSV.dev known
                        vulnerabilities
    vulndb              match deps / CVE refs against the bundled 262k OSV
                        corpus (offline)
    feeds               manage the bundled OSV data-feed cache (edge/air-gap)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --format {table,json,sarif}
                        output format (default: table). sarif = SARIF 2.1.0
                        for code-scanning (audit only)
```

> Blocks above are real `ossaudit` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
  "Findings": [
    {
      "id": "1234567890",
      "title": "Potential SQL Injection",
      "description": "A potential SQL injection attack was detected on port 80.",
      "severity": "high",
      "created_at": "2023-02-20T14:30:00Z"
    },
    {
      "id": "2345678901",
      "title": "Unusual Network Activity",
      "description": "An unusual network connection was detected from IP 192.168.1.100.",
      "severity": "medium",
      "created_at": "2023-02-20T14:35:00Z"
    }
  ]
}
```

<!-- cognis:example:end -->

## Usage — step by step

`ossaudit` audits a dependency manifest for license-policy violations and
generates a NOTICE attribution file. Console script: `ossaudit`.

1. **Install** from a clone:
   ```bash
   pip install -e .
   ```
2. **Audit a manifest** against a distribution policy preset (exit code `2` on violations):
   ```bash
   ossaudit audit deps.json --policy proprietary
   ```
3. **Generate a NOTICE** file from the same manifest:
   ```bash
   ossaudit notice deps.json --project "Acme Server" -o NOTICE.txt
   ```
4. **Read the output** — `--format json` gives a structured report for pipelines:
   ```bash
   ossaudit --format json audit deps.json | jq '.violations, .passed'
   ```
   Exit codes: `0` passed, `2` policy violations found, `1` error.
5. **Automate in CI** — fail on AGPL/copyleft contamination:
   ```yaml
   - run: pip install -e .
   - run: ossaudit audit deps.json --policy proprietary
   ```

## Vulnerability scanning (OSV.dev) — edge / air-gap

A dependency can pass the license audit and still ship a **known
vulnerability**. `ossaudit vulnscan` cross-references each
`{name, version, ecosystem}` in the manifest against
[**OSV.dev**](https://osv.dev) — the open, authoritative vulnerability database
spanning PyPI / npm / Go / Maven / crates.io / RubyGems / NuGet / … — and
surfaces the real **CVE / GHSA** ids, severity, and CVSS-derived bands.

```bash
ossaudit vulnscan deps.json                 # exit 2 if any known vuln, 0 if clean
ossaudit --format json vulnscan deps.json   # structured report for pipelines
```

Each manifest entry may carry an `"ecosystem"` field (`PyPI`, `npm`, `Go`,
`crates.io`, …); otherwise `--ecosystem` sets the default.

### Edge / air-gap deployment

The OSV layer is built on a **stdlib-only ingestion module**
(`ossaudit.datafeeds`) that fetches over HTTPS, caches to disk
(`COGNIS_FEEDS_CACHE`, default `~/.cache/cognis-feeds`), and re-serves
**offline** so the scan keeps working on disconnected / military / edge gear.

```bash
# 1. connected host: warm the OSV cache for an exact manifest
ossaudit feeds warm deps.json

# 2. snapshot the cache for sneakernet transfer
python -m ossaudit.datafeeds snapshot-export osv-cache.tar.gz

# 3. air-gapped host: import + scan with ZERO network
python -m ossaudit.datafeeds snapshot-import osv-cache.tar.gz
ossaudit vulnscan deps.json --offline
```

`ossaudit feeds list|update|get <id> [--offline]` manages the bundled feed
cache (restricted to the feed ids this tool consumes — see below). `--offline`
reads cache only and never touches the network.

### Data sources

| Feed | Source | URL | Key |
|------|--------|-----|-----|
| `osv` | OSV.dev vulnerability query | `https://api.osv.dev/v1/query` | keyless |

Catalog: [`ossaudit/data_feeds_2026.json`](ossaudit/data_feeds_2026.json) ·
ingestion: [`ossaudit/datafeeds.py`](ossaudit/datafeeds.py) ·
demo: [`demos/11-osv-vulnscan`](demos/11-osv-vulnscan).
Defensive / authorized-use intelligence only.

## Contents

- [Why ossaudit?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why ossaudit?

OSS license compliance auditor — AGPL contamination + NOTICE generation — without standing up heavyweight infrastructure.

`ossaudit` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Normalize license ids — aliases, `+`/`-or-later`, **SPDX `OR`/`AND` expressions with nested parentheses & precedence**
- ✅ Classify copyleft strength — permissive · public-domain · weak · strong · network · proprietary
- ✅ Compatibility against 5 distribution-policy presets
- ✅ Audit a dependency manifest (table · **JSON** · **SARIF 2.1.0**)
- ✅ Generate a NOTICE / attribution file
- ✅ 80+ license knowledge base incl. FTL, BSL-1.0, OpenSSL, CC-BY, SSPL, BUSL-1.1, Elastic-2.0
- ✅ **Vulnerability cross-reference** — `vulnscan` (live OSV.dev) **and** `vulndb` (bundled **262k-advisory** offline corpus, no network)
- ✅ **Air-gap CVE lookups** — resolve real CVEs (Log4Shell, lodash, django) straight from the clone
- ✅ 12 real-use-case demos in [`demos/`](demos/) — SaaS, mobile, GPL project, dual-license, source-available, offline vuln-DB
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, Rust, and POSIX shell (`ports/`) — each mirrors the `audit` CLI and is CI-built/tested

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-ossaudit
ossaudit --version
ossaudit audit deps.json --policy proprietary        # audit a manifest (exit 2 on violations)
ossaudit --format json  audit deps.json              # machine-readable
ossaudit --format sarif audit deps.json > out.sarif  # SARIF 2.1.0 for code-scanning
ossaudit notice deps.json --project "My App" -o NOTICE.txt
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ ossaudit audit demos/01-basic/deps.json --policy proprietary
Policy: proprietary   Deps: 8   Violations: 4
------------------------------------------------------------------------------
STATUS    SEV  NAME                    VERSION     LICENSE
------------------------------------------------------------------------------
VIOLATION 5    analytics-sdk           1.2.0       AGPL-3.0-only
VIOLATION 5    mongo-driver            2.0.0       SSPL-1.0
VIOLATION 4    chart-lib               4.1.0       GPL-3.0-only
VIOLATION 3    legacy-thing            0.9.9       NOASSERTION
ok        1    requests                2.32.3      Apache-2.0
...
RESULT: FAIL          # exit code 2
```

Add `--format sarif` to upload the same findings to GitHub code-scanning, or
`--format json` to pipe into any tool.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos — real situations, ready to run

Each folder under [`demos/`](demos/) has a manifest in the tool's real input
format plus a `SCENARIO.md` (where the data came from, what to expect, the exact
command, and how to act). Every demo is verified to fire.

| Demo | Situation | Policy | Result |
|---|---|---|---|
| [`01-basic`](demos/01-basic) | Mixed manifest, messy spellings + SPDX `OR` | proprietary | FAIL |
| [`01-agpl-contamination`](demos/01-agpl-contamination) | AGPL PDF libs (iText, Ghostscript) in a paid product | proprietary | FAIL |
| [`02-clean-license`](demos/02-clean-license) | All-permissive service, then generate NOTICE | proprietary | PASS |
| [`03-busl-and-mixed`](demos/03-busl-and-mixed) | Source-available BUSL / Elastic-2.0 (Redis, CockroachDB, ES) | proprietary | FAIL |
| [`04-saas-agpl-database`](demos/04-saas-agpl-database) | SaaS data-layer SSPL/AGPL (MongoDB, Elasticsearch, Grafana) | proprietary | FAIL |
| [`05-mobile-app-store`](demos/05-mobile-app-store) | GPL media libs in an App Store binary (VLC, ffmpeg-gpl) | distribute-binary | FAIL |
| [`06-permissive-only-relicense`](demos/06-permissive-only-relicense) | Same manifest, two policies — weak copyleft surfaces | permissive-only | FAIL |
| [`07-weak-copyleft-lgpl`](demos/07-weak-copyleft-lgpl) | LGPL is fine when you dynamic-link (Qt, FFmpeg) | proprietary | PASS |
| [`08-gpl-oss-project`](demos/08-gpl-oss-project) | GPL project: GPL OK, AGPL (MinIO) still blocked | gpl-project | FAIL |
| [`09-dual-license-spdx`](demos/09-dual-license-spdx) | Rust dual/tri-licensing + nested SPDX expressions | proprietary | FAIL |
| [`10-internal-tool-audit`](demos/10-internal-tool-audit) | Clean Node/TS app — the CI happy path + SARIF | proprietary | PASS |
| [`11-osv-vulnscan`](demos/11-osv-vulnscan) | Live OSV.dev vulnerability cross-reference (warm + air-gap) | n/a | VULNERABLE |
| [`12-offline-vulndb`](demos/12-offline-vulndb) | **Offline** enrichment vs the bundled 262k OSV corpus (Log4Shell resolves) | n/a | VULNERABLE |

```bash
python -m ossaudit audit demos/04-saas-agpl-database/deps.json --policy proprietary
python -m ossaudit --format sarif audit demos/10-internal-tool-audit/deps.json --policy proprietary > ossaudit.sarif
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[ossaudit<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`ossaudit` is interoperable with every popular way of using AI:

- **MCP server** — `ossaudit mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `ossaudit --format json audit deps.json` (or `vulndb enrich deps.json`) into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis ossaudit** | nexB |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **nexB/scancode-toolkit**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`ossaudit mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/ossaudit.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/ossaudit.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/ossaudit.git" # uv
pip install cognis-ossaudit                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/ossaudit:latest --help        # Docker
brew install cognis-digital/tap/ossaudit                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/ossaudit/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/ossaudit` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`depgraph`](https://github.com/cognis-digital/depgraph) — Dependency risk visualizer — Scorecard + OSV + typosquat + maintainer signals
- [`secretsweep`](https://github.com/cognis-digital/secretsweep) — Repo secret scanner + auto-rotator across providers
- [`pipewatch-pro`](https://github.com/cognis-digital/pipewatch-pro) — CI/CD supply-chain auditor — GH Actions / GitLab CI / OWASP CI/CD Top 10

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `ossaudit` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

## Bundled vulnerability database (fully offline, no network)

Ships `ossaudit/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV: PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata (CVE/GHSA aliases, ecosystem, severity/CVSS, affected packages, dates). Pure-stdlib offline loaders (`ossaudit.vulndb.LocalVulnDB`, `vulndb_local.VulnDB`) and a wired **`vulndb` subcommand** — air-gap ready, no key, no fabricated data. Refresh/extend from NVD/OSV/GHSA on the edge (see [SOURCES.md](SOURCES.md)).

```bash
ossaudit vulndb count                          # 262351 advisories bundled
ossaudit vulndb cve CVE-2021-44228             # Log4Shell -> GHSA-jfh8-c2jp-5v3q  [Maven]  sev=CRITICAL
ossaudit vulndb pkg lodash --ecosystem npm     # every advisory affecting a package
ossaudit vulndb stats                          # record counts per ecosystem
ossaudit vulndb search "remote code execution" # substring search over summaries
ossaudit vulndb enrich deps.json               # match a whole manifest (exit 2 if vulnerable)
ossaudit vulndb resolve sbom.txt               # resolve CVE refs found in any text/SBOM
```

```text
$ ossaudit vulndb enrich demos/12-offline-vulndb/deps.json
vulndb (offline)   corpus: cognis_vulndb.jsonl.gz (262351 records)
Deps: 5   Vulnerable: 4
------------------------------------------------------------------------------
SEVERITY  #   NAME                  VERSION     ECOSYSTEM
------------------------------------------------------------------------------
CRITICAL  315 django                3.2.0       PyPI
CRITICAL  16  jinja2                2.4.1       PyPI
CRITICAL  11  org.apache.logging.lo 2.14.1      Maven
CRITICAL  10  lodash                4.17.11     npm
NONE      0   ossaudit-clean-shim   9.9.9       PyPI
------------------------------------------------------------------------------
  ! org.apache.logging.log4j:log4j-core 2.14.1: 11 advisory(ies) [CVE-2021-44228, CVE-2021-45046, ...]
RESULT: VULNERABLE          # exit code 2
```

**`vulnscan` vs `vulndb`** — `vulnscan` queries OSV.dev *live* and caches results for air-gap replay; `vulndb` matches against the *bundled* corpus with zero network from the first clone. Use `vulndb` on disconnected/edge hosts and `vulnscan` when you want the freshest upstream answer. See [`demos/12-offline-vulndb`](demos/12-offline-vulndb).
