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

