# Demo 04 — Closed-source SaaS: data-layer copyleft contamination

## Where this data came from

Your platform team exported the dependency manifest of a closed-source,
network-delivered SaaS backend (FastAPI + SQLAlchemy + Pydantic) and the
self-hosted data services bundled with it. The web framework, ORM, and client
libraries are permissive (MIT / BSD-3-Clause). The danger lives in the **data
layer**: MongoDB Server 7.x and Elasticsearch 7.10.2 ship under **SSPL-1.0**,
and a bundled Grafana 8.5 dashboard is **AGPL-3.0-only** — both are
network-copyleft licenses that target exactly the SaaS deployment model.

These licenses are the publicly documented terms for these projects at these
version lines; nothing here is fabricated.

## What to expect

Network-copyleft licenses are **radioactive** for a proprietary SaaS: the
moment your service interacts with the SSPL/AGPL component over a network, the
license can obligate you to release your full service source. The auditor
ranks these severity 5 (the worst category).

## Run it

```
python -m ossaudit audit demos/04-saas-agpl-database/deps.json --policy proprietary
```

Expected: **FAIL** (exit code 2), three violations:
`mongodb-server` (SSPL-1.0), `elasticsearch` (SSPL-1.0), and `grafana`
(AGPL-3.0-only). All permissive deps pass.

## Emit SARIF for code scanning

```
python -m ossaudit --format sarif audit demos/04-saas-agpl-database/deps.json \
  --policy proprietary > ossaudit.sarif
```

Upload `ossaudit.sarif` to GitHub code-scanning (or any SARIF 2.1.0 consumer)
to see each violation as an `error`-level result anchored to the manifest.

## How to act

1. Replace MongoDB/Elasticsearch with permissively licensed forks or
   alternatives (e.g. an Apache-2.0 search engine, a community-licensed
   document store), **or** purchase a commercial license from the vendor.
2. Run Grafana out-of-process as a separately deployed service you do not link
   into or redistribute with your product, or move to a permissive dashboard.
3. Re-run the audit; it should report `RESULT: PASS`.
