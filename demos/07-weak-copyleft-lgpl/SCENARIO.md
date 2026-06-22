# Demo 07 — Desktop app: LGPL is OK when you dynamic-link

## Where this data came from

A proprietary cross-platform desktop application (Qt-based) exported its native
dependency list. The headline components are **weak copyleft**: Qt6 Core
(LGPL-3.0-only) and FFmpeg (LGPL-2.1-or-later). The rest are permissive or
public-domain: OpenSSL 3.x (Apache-2.0), zlib/libpng (Zlib), FreeType (FTL),
and SQLite (its public-domain "blessing" license). These are the publicly
documented licenses for these projects.

## Why this should PASS under `proprietary`

LGPL is **weak (file/library-scope) copyleft**. As long as you dynamic-link and
let users relink a modified library, you can ship LGPL components inside a
closed-source product. The `proprietary` policy correctly *allows* weak
copyleft — this demo proves the auditor doesn't cry wolf on legitimate LGPL
usage.

It also exercises the license knowledge base for real-but-uncommon SPDX ids:
**FTL** (FreeType, permissive) and **blessing** (SQLite, public domain).

## Run it

```
python -m ossaudit audit demos/07-weak-copyleft-lgpl/deps.json --policy proprietary
```

Expected: **PASS** (exit code 0), zero violations. FFmpeg and Qt6 are reported
`ok` as weak-copyleft.

## Generate the NOTICE you must ship

LGPL still requires attribution and a notice. Generate it:

```
python -m ossaudit notice demos/07-weak-copyleft-lgpl/deps.json \
  --project "Acme Studio" -o NOTICE.txt
```

The NOTICE lists every dependency, its SPDX id and category, homepage, and
copyright line, plus a "Licenses present" summary for legal review.

## How to act

Confirm your build dynamic-links Qt and FFmpeg (no static LGPL linking without
relink provisions), ship the generated NOTICE, and keep the audit in CI so a
future static-link change is caught.
