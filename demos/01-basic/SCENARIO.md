# Demo 01 - Catching AGPL contamination in a proprietary SaaS

You maintain a closed-source SaaS product. Legal needs to know whether any
third-party dependency would force you to open-source your code, and they need
a NOTICE file for the attributions you DO ship.

The manifest `deps.json` lists the dependency tree with declared licenses,
including a few deliberately messy spellings (`Apache 2.0`, `BSD`) and an SPDX
`OR` expression.

## Run the audit (proprietary policy)

```
python -m ossaudit audit demos/01-basic/deps.json --policy proprietary
```

Expected: **FAIL** (exit code 2). The auditor flags:

- `mongo-driver` **SSPL-1.0** and `analytics-sdk` **AGPL-3.0-only** as
  network-copyleft CONTAMINATION RISK (network use forces source release).
- `chart-lib` **GPL-3.0-only** as strong copyleft (distribution forces GPL).
- `legacy-thing` with an unrecognized license as unvetted/unknown.

The permissive deps (`requests` MIT, `flask` BSD-3-Clause, `pyyaml` MIT,
the `MIT OR Apache-2.0` crate which normalizes to the most permissive operand)
pass.

## See it pass under an open-source GPL policy

```
python -m ossaudit audit demos/01-basic/deps.json --policy gpl-project
```

The GPL dep is now allowed; only AGPL/SSPL/unknown remain violations.

## Machine-readable output for CI

```
python -m ossaudit --format json audit demos/01-basic/deps.json --policy proprietary
```

## Generate the NOTICE file

```
python -m ossaudit notice demos/01-basic/deps.json --project "Acme Cloud" -o NOTICE
```
