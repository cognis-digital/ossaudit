# OSSAUDIT — OSS license compliance auditor — AGPL contamination + NOTICE generation

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `dev-supply-chain`

[![PyPI](https://img.shields.io/pypi/v/cognis-ossaudit.svg)](https://pypi.org/project/cognis-ossaudit/)
[![CI](https://github.com/cognis-digital/ossaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/ossaudit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

OSS license compliance auditor — AGPL contamination + NOTICE generation.

## Install

```bash
pip install cognis-ossaudit
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
ossaudit --version
ossaudit scan demos/                          # run against bundled demo
ossaudit scan demos/ --format sarif --out r.sarif --fail-on high
ossaudit mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-agpl-contamination/` — see [`SCENARIO.md`](demos/01-agpl-contamination/SCENARIO.md)
- `demos/02-clean-license/` — see [`SCENARIO.md`](demos/02-clean-license/SCENARIO.md)
- `demos/03-busl-and-mixed/` — see [`SCENARIO.md`](demos/03-busl-and-mixed/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
