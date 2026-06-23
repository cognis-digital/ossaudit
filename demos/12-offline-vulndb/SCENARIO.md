# Demo 12 — Offline vulnerability enrichment (bundled 262k OSV corpus)

**Situation.** You are on an air-gapped / disconnected build host (a SCIF, a
factory floor, a CI runner with egress blocked). You still need to know whether
the components in your manifest carry **known vulnerabilities** — but you cannot
reach OSV.dev or NVD over the network.

**Data.** `ossaudit` ships `ossaudit/cognis_vulndb.jsonl.gz` — a consolidated,
compact corpus of **262,351 real OSV advisories** across PyPI / npm / Go / Maven
/ RubyGems / crates.io / NuGet. Each record carries the GHSA/PYSEC/RUSTSEC id,
real CVE aliases, ecosystem, CVSS severity, affected packages, and dates. No
network, no key, no fabricated data.

**Manifest.** [`deps.json`](deps.json) mixes known-vulnerable components
(`lodash`, `django`, `jinja2`, Log4Shell's `org.apache.logging.log4j:log4j-core`)
with a clean shim that matches nothing.

## Run it (fully offline)

```bash
# How many advisories are bundled?
python -m ossaudit vulndb count
# -> 262351

# Log4Shell resolves by CVE id straight out of the bundle:
python -m ossaudit vulndb cve CVE-2021-44228
# -> GHSA-jfh8-c2jp-5v3q  [Maven]  sev=CRITICAL  Remote code injection in Log4j

# Every advisory affecting a package:
python -m ossaudit vulndb pkg lodash --ecosystem npm

# Match the whole manifest against the corpus (exit 2 if anything is vulnerable):
python -m ossaudit vulndb enrich demos/12-offline-vulndb/deps.json
python -m ossaudit --format json vulndb enrich demos/12-offline-vulndb/deps.json
```

## Expected result

`enrich` reports the manifest as **VULNERABLE** (exit code `2`): `lodash`,
`django`, `jinja2`, and the Log4j coordinate all match advisories; the clean
shim matches none. `vulndb cve CVE-2021-44228` resolves to the Log4Shell GHSA
record at `CRITICAL`.

## Refreshing the corpus on the edge

The bundle is the offline baseline. To extend or refresh it from authoritative
sources (NVD / OSV / GHSA) while still on a connected host, see
[`SOURCES.md`](../../SOURCES.md) and `python -m ossaudit.datafeeds`. Then
sneakernet the snapshot into the air gap.

Defensive / authorized-use intelligence only.
