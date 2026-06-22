# Demo 11 — OSV vulnerability cross-reference (edge / air-gap)

A dependency can pass the **license** audit and still ship a **known
vulnerability**. `ossaudit vulnscan` cross-references each `{name, version,
ecosystem}` against [OSV.dev](https://osv.dev), the open vulnerability database
(PyPI / npm / Go / Maven / crates.io / RubyGems / …).

## Online

```sh
ossaudit vulnscan demos/11-osv-vulnscan/deps.json
```

`django 3.2.0` and `lodash 4.17.11` resolve to real CVEs (e.g. CVE-2022-28346
SQL injection, CVE-2021-23337 ReDoS); `requests 2.31.0` is clean. Exit code is
`2` when any known vulnerability is present, `0` when clean.

## Air-gapped enclave

```sh
# 1. connected host: warm the OSV cache for this exact manifest
ossaudit feeds warm demos/11-osv-vulnscan/deps.json

# 2. snapshot the cache for sneakernet
python -m ossaudit.datafeeds snapshot-export osv-cache.tar.gz

# 3. disconnected host: import + scan with ZERO network
python -m ossaudit.datafeeds snapshot-import osv-cache.tar.gz
ossaudit vulnscan demos/11-osv-vulnscan/deps.json --offline
```

The cache lives under `COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).
`--offline` reads cache only and never touches the network.
