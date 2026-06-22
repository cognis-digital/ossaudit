# Demo 10 — Clean internal web app: the CI happy path

## Where this data came from

A standard internal Node/TypeScript web app (React front end, Express back end)
exported its npm dependency licenses. Everything is permissive: React/lodash/
axios/express (MIT), TypeScript (Apache-2.0), the `caniuse-lite` browser-support
data (CC-BY-4.0), and `spdx-license-ids` (CC0-1.0). These are the publicly
documented licenses for these packages.

This is the **green build** — what a healthy manifest looks like, and how to
wire ossaudit into CI so it stays that way.

## Run it (should PASS)

```
python -m ossaudit audit demos/10-internal-tool-audit/deps.json --policy proprietary
```

Expected: **PASS** (exit code 0), zero violations. Note that `caniuse-lite`
(CC-BY-4.0) is recognized as permissive and `spdx-license-ids` (CC0-1.0) as
public domain — common data/content licenses, not just code licenses.

## Wire it into CI

```yaml
# .github/workflows/license.yml
- run: pip install -e .
- run: python -m ossaudit audit deps.json --policy proprietary   # fails the job on exit 2
```

## Upload SARIF to code scanning

```yaml
- run: python -m ossaudit --format sarif audit deps.json --policy proprietary > ossaudit.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ossaudit.sarif
```

Findings show up in the repo's Security → Code scanning tab, anchored to the
manifest. On a clean manifest there are only `note`-level results.

## JSON for any other pipeline

```
python -m ossaudit --format json audit deps.json --policy proprietary | jq '.passed, .violations'
```

## How to act

Keep this audit as a required check. When someone later adds a copyleft or
unrecognized-license dependency, the build turns red and the new finding is the
diff — exactly the signal you want before it reaches production.
