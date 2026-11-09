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
uv run sniff-test scan owner/repo --ha-version 2026.10.2        # resolve deps for a specific HA release
uv run sniff-test scan ./path/to/repo --offline                 # no PyPI/OSV lookups (marked incomplete)
```

## What gets checked

- **Code** (Semgrep, bundled HA-specific rules): token and data exfiltration, encoded
  payload loaders, auth internals, other integrations' credentials, unauthenticated views.
- **Python dependencies** (integrations): the `manifest.json` requirements are resolved
  the way HA installs them (HA's constraints, its Python version, PyPI plus HA's wheel
  index) for both x86_64 and aarch64 HA OS / Container. Then: typosquats (offline, from
  the name alone), VCS/URL requirements, brand-new packages, known vulnerabilities and
  known-malicious packages (osv-scanner), and heuristic malware checks (GuardDog) on every
  package HA doesn't already ship.
- **npm dependencies** (cards): the repo's lockfile, checked with osv-scanner. Known
  malware is reported for every package; CVEs only for packages bundled into the card,
  not for build-only tools.

- **Endpoints**: every host and IP literal in the shipped code, classified as declared
  (the manifest's documentation/issue tracker, or the integration's own name), local,
  infrastructure or undeclared. Paste sites, request catchers, tunnels, chat webhooks
  with a baked-in token, and URLs with a hardcoded public IP are findings.
- **Possible exfiltration**: reading secrets, auth data or other integrations'
  credentials *and* being able to send data to an undeclared host is flagged high, even
  when the read and the send are in different files.
- **Repo signals**: ownership transfers (proven from GitHub's redirect, or from the
  repo's own old links resolving to the same repository), scored by whether the people
  publishing releases changed; a first release by a new publisher; very new repos; and
  release zips whose code differs from the tagged source.

The JSON report also carries a `graph` section (what the item hooks into: HA
services, views and events, the user's data, hosts, packages, publishers, with an
evidence level on every edge) and a `provenance` section (release timeline,
publishers, former names). Neither affects the score.

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

Dependencies are resolved with `uv pip compile --no-build` (wheels only), so no
`setup.py` or build backend ever runs; packages that only ship source archives are
downloaded and extracted, never built. Manifest requirements are validated before uv sees
them, so a manifest can't smuggle in installer options like `-e` or `--index-url`.
Lockfiles are scanned in isolation with Sniff Test's own osv-scanner config, so a planted
`osv-scanner.toml` can't hide a malicious package.

## Requirements

Python 3.13, [uv](https://docs.astral.sh/uv/), and on `PATH`: `semgrep`, `osv-scanner`
(v2) and `guarddog` (3.2). A missing tool marks the scan incomplete. A GitHub token
(`GITHUB_TOKEN`, or a logged-in `gh`) avoids API rate limits. HA release data and the
resolved package sets are cached in `~/.cache/sniff-test/` (override with
`SNIFF_TEST_CACHE`).

## Development

```sh
uv sync
uv run pytest                 # unit + rule tests + planted-malware fixtures
uv run pytest -m network      # opt-in tests that hit GitHub / PyPI / OSV
uv run ruff check . && uv run ruff format --check .
semgrep scan --test --config rules/ tests/rules/
```

Rules live in `rules/` (Semgrep YAML) with annotated test targets in `tests/rules/`.
`tests/fixtures/` contains deliberately malicious sample repos. They are never executed
and only send to `.invalid` hosts.
