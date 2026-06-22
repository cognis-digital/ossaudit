# Demo 03 — Source-available licenses (BUSL / Elastic-2.0)

## Where this data came from

A backend platform that adopted several infrastructure projects which moved from
open source to **source-available** licenses: Redis Stack and CockroachDB
(BUSL-1.1, the Business Source License) and Elasticsearch 8.x (Elastic-2.0).
`valkey` (the BSD-3-Clause Redis fork) is included as the permissive escape
hatch. These are the publicly documented license moves for these projects.

## Why source-available is not "open enough"

BUSL-1.1 and Elastic-2.0 restrict exactly the deployment models commercial
software relies on — typically you may not offer the product as a competing
managed service, and BUSL adds a time-delayed conversion to an open license.
ossaudit classifies both as **proprietary** (severity 4), so they fail any
distribution-oriented policy.

## Run it

```
python -m ossaudit audit demos/03-busl-and-mixed/licenses.json --policy proprietary
```

Expected: **FAIL** (exit code 2). `redis-stack`, `cockroachdb` (BUSL-1.1) and
`elasticsearch` (Elastic-2.0) are flagged proprietary/source-available;
`valkey` (BSD-3-Clause) passes.

## How to act

Either accept the BUSL/Elastic restrictions explicitly (document that you do not
offer a competing managed service) and buy a commercial license where needed, or
migrate to the permissive fork — e.g. **Valkey** in place of Redis Stack, or an
Apache-2.0 search engine in place of Elasticsearch. Re-run until clean.
