# Sources

## Authoritative data feeds (edge / air-gap)

Real, keyless intelligence feeds consumed by this tool via the bundled
stdlib ingestion layer (`ossaudit/datafeeds.py` + `ossaudit/data_feeds_2026.json`).
Each feed is fetched over HTTPS, cached to disk (`COGNIS_FEEDS_CACHE`), and
re-served offline (`--offline`) for disconnected / air-gapped deployment.

| Feed id | Source | URL | Used for |
|---------|--------|-----|----------|
| `osv` | OSV.dev vulnerability query | `https://api.osv.dev/v1/query` | `vulnscan`: map `{name, version, ecosystem}` to known CVE/GHSA vulnerabilities |

Manage with `ossaudit feeds list|update|get <id> [--offline]`. Defensive /
authorized-use intelligence only.

## Bundled offline vulnerability corpus (262k OSV advisories)

The repo ships `ossaudit/cognis_vulndb.jsonl.gz` — a consolidated, compact
snapshot of **262,351 real OSV advisories** across PyPI / npm / Go / Maven /
RubyGems / crates.io / NuGet. It is the offline baseline that lets
`ossaudit vulndb` resolve real CVEs (e.g. Log4Shell `CVE-2021-44228`) the moment
the repo is cloned — **no network, no key, no fabricated data**. Each record is
distilled from the upstream OSV record to: `id` (GHSA/PYSEC/RUSTSEC/…),
`aliases` (incl. real CVE ids), `ecosystem`, `summary`, `severity` (CVSS vector
when published), affected `packages`, `published`/`modified` dates, and a
reference count.

```bash
ossaudit vulndb count                       # 262351
ossaudit vulndb cve CVE-2021-44228          # Log4Shell -> GHSA-jfh8-c2jp-5v3q (CRITICAL)
ossaudit vulndb pkg lodash --ecosystem npm  # advisories affecting a package
ossaudit vulndb enrich deps.json            # match a whole manifest (exit 2 if vulnerable)
ossaudit vulndb resolve sbom.txt            # resolve CVE refs found in an SBOM/text
```

### Refreshing / extending the corpus on the edge

The bundle is a baseline, not a frozen artifact. On a connected host, refresh or
extend it from the authoritative upstreams below, then sneakernet the result
into an air-gapped enclave. All three are real, keyless (NVD optionally keyed),
and already catalogued in `ossaudit/data_feeds_2026.json`:

| Source | Endpoint | Scope |
|--------|----------|-------|
| **OSV.dev** (bulk) | `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip` | per-ecosystem full advisory dumps (PyPI/npm/Go/Maven/crates.io/RubyGems/NuGet) |
| **OSV.dev** (query) | `https://api.osv.dev/v1/query` | single `{name, version, ecosystem}` lookups (the `osv` feed) |
| **NIST NVD** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | authoritative CVE detail (keyless is rate-limited; `NVD_API_KEY` raises limits) |
| **GitHub GHSA** | `https://api.github.com/advisories` | GitHub Security Advisories (GHSA ids, ecosystem-aware) |

```bash
# connected host: pull a fresh per-ecosystem OSV bulk dump
python -m ossaudit.datafeeds update osv          # warms the query feed
# (rebuild the bundled jsonl.gz from OSV/NVD/GHSA dumps, then commit it)

# air-gap: snapshot the feed cache for sneakernet
python -m ossaudit.datafeeds snapshot-export osv-cache.tar.gz
python -m ossaudit.datafeeds snapshot-import osv-cache.tar.gz   # on the enclave
```

`ossaudit vulndb` reads only the on-disk bundle, so it keeps working with zero
network regardless of how stale or fresh the bundle is.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Geopolitics
- **feed** · https://www.reuters.com/arc/outboundfeeds/v3/all/?outputType=xml
- **feed** · https://apnews.com/hub/ap-top-news/feed
- **feed** · https://foreignpolicy.com/feed/
- **live search** · `new sanctions package designation 2026`
- **live search** · `diplomatic crisis summit 2026`
- **live search** · `trade tariff policy change`
- **api** · https://sanctionssearch.ofac.treas.gov (OFAC, free)
- **api** · https://www.gov.uk/government/publications/financial-sanctions-consolidated-list-of-targets (UK OFSI, free)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

