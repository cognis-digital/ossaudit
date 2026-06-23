# Ports of ossaudit

The **same license-compliance audit**, ported across languages so you can drop
`ossaudit` into any stack or ship a single static binary — air-gapped, no
network. Every port mirrors the reference Python CLI's `audit` command:

- reads a dependency manifest (`{"dependencies":[{name,version,license}, …]}`
  or a bare JSON array),
- normalises each SPDX-ish license id (aliases + SPDX `OR`/`AND` expressions),
- classifies copyleft strength
  (`permissive · public-domain · weak · strong · network · proprietary · unknown`),
- decides each dependency against a distribution-policy preset
  (`proprietary`, `distribute-binary`, `permissive-only`, `gpl-project`,
  `permissive-audit`),
- prints a table (or JSON), and **exits `2` when the manifest has violations** —
  the exact contract the Python tool uses, so the ports are CI-drop-in
  compatible.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../ossaudit/` | `python -m ossaudit audit deps.json --policy proprietary` | `pytest` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js audit deps.json --policy proprietary` | `node ports/javascript/test.js` |
| Go | `go/` | `cd ports/go && go run . audit ../../demos/01-basic/deps.json` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- audit ../../demos/01-basic/deps.json` | `cd ports/rust && cargo test` |
| POSIX shell | `shell/` | `sh ports/shell/ossaudit.sh audit demos/01-basic/deps.json --policy proprietary` | `sh ports/shell/test.sh` |

## Parity

Run any port against `demos/01-basic/deps.json` under `--policy proprietary` and
you get **8 deps, 4 violations** (AGPL, SSPL, GPL, NOASSERTION), sorted
worst-first, `RESULT: FAIL`, exit code `2` — identical across all five
implementations.

## CI

Every push builds and tests each port on GitHub Actions
([`.github/workflows/ports.yml`](../.github/workflows/ports.yml)) — Go and Rust
are compiled + unit-tested + a CLI parity check, so the ports are **real and
verifiable**, not vaporware, even when those toolchains aren't installed
locally.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).
