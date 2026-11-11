<p align="center"><img src="docs/brand/barkley-banner.png" alt="Barkley" width="500"></p>

# 🐕 Barkley

Every integration gets a sniff test before it gets into the house.

Barkley is the dog behind a static security scanner for Home Assistant Marketplace
(formerly HACS) custom integrations and frontend cards. Custom integrations run unsandboxed inside the HA
Python process; cards run in the HA frontend origin and can read your tokens. Nobody
reviews them before you install. Barkley does a first pass.

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

uv run sniff-test diff old.json new.json                        # what an update changes (reports from scan -o)
uv run sniff-test diff owner/repo --from v1.2.3                 # scan v1.2.3 and what HACS installs now, compare
uv run sniff-test diff owner/repo --from v1.2.3 --to v1.3.0 -v  # two tags; -v lists every change
uv run sniff-test diff owner/repo --from v1.2.3 --ha-version auto  # old side: the HA of its time
uv run sniff-test releases owner/repo                           # release timeline: HACS default, publishers, handovers

uv run sniff-test scan owner/repo --store scans.db              # also keep the scan in a SQLite scan store
uv run sniff-test diff owner/repo --from v1.2.3 --store scans.db  # reuse a matching stored scan, store new ones
uv run sniff-test diff @3 @7 --store scans.db                   # compare two stored scans
uv run sniff-test history --store scans.db                      # list stored scans (or set SNIFF_TEST_STORE)
uv run sniff-test serve --store scans.db --allow 127.0.0.1      # the add-on's web panel (HA ingress)
```

`diff` puts the few changes that matter first (new findings, new data flows, evidence
going from possible to proven, new publishers, new undeclared hosts) and summarizes the
rest in one line. It compares; it never changes how either scan is scored.

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
- **Code you can't read**: compiled `.pyc` files that HA's Python would run instead of
  (or without) the `.py` next to them (unchecked-hash, checked-hash matching the source,
  or sourceless bytecode for HA's Python version), and native `.so` extension modules
  HA's Python would load, either in place of a same-named `.py` or with no source at all.
- **Scanner evasion**: `<!--` and `-->` hide the rest of a line from Semgrep in JS but are
  ordinary code in the ES modules HA loads. Barkley rewrites them (with the same
  meaning) in its copy before scanning, and flags a real `<!--` in code.
- **Repo signals**: ownership transfers (proven from GitHub's redirect, or from the
  repo's own old links resolving to the same repository), scored by whether the people
  publishing releases changed; a first release by a new publisher; very new repos;
  release tags whose commit isn't on the default branch; and release zips whose code
  differs from the tagged source.

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

The scanned code is treated as hostile. Barkley never executes, imports, builds or
installs it. Archives are extracted into a fresh temp dir outside this repo with
zip-slip, symlink and size protections, and in-tree `.semgrepignore`/`.gitignore` files
are removed so a repo can't hide files from the scanner.

Dependencies are resolved with `uv pip compile --no-build` (wheels only), so no
`setup.py` or build backend ever runs; packages that only ship source archives are
downloaded and extracted, never built. Manifest requirements are validated before uv sees
them, so a manifest can't smuggle in installer options like `-e` or `--index-url`.
Lockfiles are scanned in isolation with Barkley's own osv-scanner config, so a planted
`osv-scanner.toml` can't hide a malicious package.

## Home Assistant add-on (app)

`addon/sniff_test/` is the add-on: a Debian-based image with Semgrep, GuardDog,
osv-scanner and uv pinned, an ingress panel (`sniff-test serve`), and the scan store in
`/data/sniff-test.db`. "What would updating change?" scans the release HACS would
install now and diffs it against the stored scan of the installed tag. **Auto-sniff**
watches the Marketplace: every install or update is scanned at the version that landed
(reusing a scan sniffed from search), an update gets its diff, and a notification says
what was found. Note that a new integration runs as soon as it's installed, so the
protection for a new install is sniffing it from search first. Build from the
repository root: `docker buildx build -f addon/sniff_test/Dockerfile .`. See
[`addon/sniff_test/DOCS.md`](addon/sniff_test/DOCS.md).

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
