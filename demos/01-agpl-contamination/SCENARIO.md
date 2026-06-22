# Demo 01b — AGPL contamination of a proprietary build

## Where this data came from

A .NET document-processing product (proprietary, distributed to customers)
exported its dependency licenses. Two PDF libraries are **AGPL**: iText 7
(AGPL-3.0-only) and Ghostscript (AGPL-3.0-or-later) — both publicly dual-licensed
as AGPL/commercial, where the free build is AGPL. Newtonsoft.Json is MIT.

## Run it

```
python -m ossaudit audit demos/01-agpl-contamination/licenses.json --policy proprietary
```

Expected: **FAIL** (exit code 2). `itext7-core` and `ghostscript` are flagged as
network-copyleft CONTAMINATION RISK (severity 5); `newtonsoft-json` passes.

## Why this matters

AGPL in a proprietary distribution is a real legal exposure: ship it and you may
be obligated to release your full source. iText and Ghostscript exist precisely
to sell **commercial** licenses to teams who can't accept the AGPL.

## How to act

Either buy the commercial license from the vendor, or replace with a permissively
licensed PDF library before the next release. Re-run until `RESULT: PASS`.
