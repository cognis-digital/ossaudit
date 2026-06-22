# Demo 02 — Clean license posture, then generate the NOTICE

## Where this data came from

A small proprietary Python service with three permissive deps: FastAPI and
Pydantic (MIT) and requests (Apache-2.0). This is the simplest green case.

## Run the audit (should PASS)

```
python -m ossaudit audit demos/02-clean-license/licenses.json --policy proprietary
```

Expected: **PASS** (exit code 0), zero violations.

## Generate the NOTICE / attribution file

Even with a clean posture you still owe attribution for permissive deps:

```
python -m ossaudit notice demos/02-clean-license/licenses.json \
  --project "Acme API" -o NOTICE.txt
```

This writes a NOTICE listing each dependency, its SPDX id and category, and a
"Licenses present" summary you can hand to legal.

## Why this matters

A passing audit isn't the end — Apache-2.0 and MIT both require you to ship the
notice. Make NOTICE generation part of your release so attributions stay current.
