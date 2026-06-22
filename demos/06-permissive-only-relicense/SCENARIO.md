# Demo 06 — Library you intend to relicense under Apache-2.0

## Where this data came from

You maintain an open-source library and want to keep the option to relicense
it (or vendor it into permissively licensed downstream projects). Your policy
is the strictest: **no copyleft at all**, even weak copyleft. This manifest is
a typical Python utility library's dependency set, with publicly documented
licenses: NumPy/Click (BSD-3-Clause), requests (Apache-2.0), rich (MIT), plus
weak-copyleft transitives `chardet` (LGPL-2.1-or-later) and `certifi`/`tqdm`
(MPL-2.0).

## Why `permissive-only` is stricter than `proprietary`

Under the `proprietary` policy, weak copyleft (LGPL/MPL) is *allowed* — you can
dynamically link it. But if you plan to **relicense or fully vendor** the code,
even file-scope copyleft like MPL-2.0 creates obligations you can't satisfy.
The `permissive-only` policy surfaces these.

## Run both policies to see the difference

```
# Lenient: weak copyleft is fine -> PASS
python -m ossaudit audit demos/06-permissive-only-relicense/deps.json --policy proprietary

# Strict: weak copyleft is a violation -> FAIL
python -m ossaudit audit demos/06-permissive-only-relicense/deps.json --policy permissive-only
```

Expected: `proprietary` **PASSES**; `permissive-only` **FAILS** (exit 2) on
`chardet` (LGPL), `certifi` (MPL-2.0), and `tqdm` (MPL-2.0).

## How to act

1. Replace `chardet` with `charset-normalizer` (MIT) — the modern, permissive
   drop-in that `requests` itself moved to.
2. MPL-2.0 is file-scope; if you must keep `certifi`/`tqdm`, isolate them in a
   process boundary or accept that those files stay MPL.
3. Re-run `--policy permissive-only` until clean.
