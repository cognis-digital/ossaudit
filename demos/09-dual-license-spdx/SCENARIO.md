# Demo 09 — Dual-licensed crates and SPDX expressions

## Where this data came from

A Rust service exported its `cargo`-style dependency licenses. The Rust
ecosystem leans heavily on **SPDX license expressions**, and this manifest
exercises every shape the auditor must understand:

- `serde` — `MIT OR Apache-2.0` (the canonical Rust dual license)
- `rustls` — `Apache-2.0 OR ISC OR MIT` (three-way OR)
- `ring` — `ISC AND MIT AND OpenSSL` (conjunction: all apply)
- `qt-bindings` — `LGPL-3.0-only OR GPL-3.0-only OR Commercial`
  (the classic Qt tri-license)
- `font-kit` — `(MIT OR Apache-2.0) AND GPL-2.0-or-later`
  (nested parentheses + mixed operators)

These reflect the publicly documented license expressions for these crates.

## What the resolver does (and the precedence that matters)

- **OR** = the consumer may pick, so ossaudit chooses the **least severe**
  operand. `MIT OR Apache-2.0` → `MIT`; the Qt tri-license → `LGPL-3.0-only`
  (you take the weak-copyleft option, not GPL or Commercial).
- **AND** = every obligation applies, so it chooses the **most severe** operand.
- **Precedence + parentheses**: `(MIT OR Apache-2.0) AND GPL-2.0-or-later`
  resolves to **GPL-2.0-or-later** — the GPL obligation is unavoidable because
  it is AND-joined. A naive flat parser gets this wrong; ossaudit parses paren
  groups at the correct depth.

## Run it

```
python -m ossaudit audit demos/09-dual-license-spdx/deps.json --policy proprietary
```

Expected: **FAIL** (exit code 2), exactly one violation — `font-kit`, because
its expression reduces to `GPL-2.0-or-later`. `serde`, `rustls`, `ring`
(reduces to a permissive operand), and `qt-bindings` (you take LGPL) all pass.

## How to act

For `font-kit`, choose a build/feature flag or alternative that avoids the
GPL-joined component, or move it behind a process boundary. The dual/tri-
licensed crates are fine as-is under your chosen permissive/LGPL options —
record which option you elected in your compliance log.
