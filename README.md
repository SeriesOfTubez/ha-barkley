# 🐕 Sniff Test

Every integration gets a sniff before it gets into the house.

Sniff Test is a static security scanner for Home Assistant Marketplace (formerly HACS)
custom integrations and frontend cards. Custom integrations run unsandboxed inside the HA
Python process; cards run in the HA frontend origin and can read your tokens. Nobody
reviews them before you install. Sniff Test does a first pass.

> **Status:** early development (step 1: CLI). Not yet a substitute for reading the code.

## Usage

```sh
uv run sniff-test scan https://github.com/owner/repo            # latest release, as HACS installs it
uv run sniff-test scan owner/repo --ref v1.2.3                  # a specific tag
uv run sniff-test scan ./path/to/repo                           # local checkout
uv run sniff-test scan owner/repo --exposure public             # HA reachable from the internet
uv run sniff-test scan owner/repo --json -o report.json         # machine-readable report
```

| Score | Verdict |
|---|---|
| 90–100 | 🦴 Good Boy (passed the sniff test) |
| 70–89 | 🐕 Kinda Sus (a few things worth a look) |
| 40–69 | 🐕‍🦺 Very Sus (the dog won't stop staring at it) |
| 0–39 | 🚨 BORK BORK BORK (do not install) |

Scoring is deterministic. Any critical finding (e.g. proven token exfiltration) caps the
score at 39; any high caps it at 89; an incomplete scan (missing tool, timeout) also caps
at 89, so a partial scan can never pass as a Good Boy.

## Safety model

The scanned code is treated as hostile. Sniff Test never executes, imports, builds or
installs it. Archives are extracted into a fresh temp dir outside this repo with
zip-slip, symlink and size protections, and in-tree `.semgrepignore`/`.gitignore` files
are removed so a repo can't hide files from the scanner.

## Requirements

Python 3.13, [uv](https://docs.astral.sh/uv/), and on `PATH`: `semgrep`
(`osv-scanner` and `guarddog` will be needed by upcoming dependency analysis).
A GitHub token (`GITHUB_TOKEN`, or a logged-in `gh`) avoids API rate limits.

## Development

```sh
uv sync
uv run pytest                 # unit + rule tests + planted-malware fixtures
uv run pytest -m network      # opt-in tests that hit GitHub
uv run ruff check . && uv run ruff format --check .
semgrep scan --test --config rules/ tests/rules/
```

Rules live in `rules/` (Semgrep YAML) with annotated test targets in `tests/rules/`.
`tests/fixtures/` contains deliberately malicious sample repos. They are never executed
and only send to `.invalid` hosts.
