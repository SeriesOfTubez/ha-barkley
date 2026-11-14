<p align="center"><img src="docs/brand/barkley-banner.png" alt="Barkley" width="500"></p>

# 🐕 Barkley

[![Tests](https://github.com/SeriesOfTubez/ha-barkley/actions/workflows/ci.yaml/badge.svg)](https://github.com/SeriesOfTubez/ha-barkley/actions/workflows/ci.yaml)
[![Security](https://github.com/SeriesOfTubez/ha-barkley/actions/workflows/security.yaml/badge.svg)](https://github.com/SeriesOfTubez/ha-barkley/actions/workflows/security.yaml)

Every integration gets a sniff test before it gets into the house.

Barkley is the dog behind a static security scanner for Home Assistant Marketplace
(formerly HACS) custom integrations and frontend cards. Custom integrations run
unsandboxed inside the HA Python process; cards run in the HA frontend origin and can
read your tokens. Nobody reviews them before you install. Barkley does a first pass, as
an app (add-on) in your Home Assistant sidebar or from the command line.

> **Status:** young, and built by one person. Barkley is a first pass, not a substitute
> for reading the code: a clean sniff means the checks below found nothing, not that
> the code is safe. Other tools exist for this job (HA Security Sandbox, Marketplace
> Guard); Barkley's difference is depth: dependencies resolved the way HA installs
> them, data-flow rules, release and publisher history, and the diff of an update.
> This project was built with AI assistance: see
> [AI-assisted development](#ai-assisted-development) for what that means and what is
> checked before anything ships.

## What Barkley does

**Sniff before you install.** Search the whole Marketplace catalog from Barkley's panel
and sniff an app at exactly the version the Marketplace would install, or pick one of
its 10 newest releases, betas included. The code is downloaded and read; it is never
run, built or installed.

**See what you already have.** Barkley asks the Marketplace what is installed and leads
with what needs a look: an update that brings something important, or a scan that isn't
a Good Boy. Updates you haven't checked come next, and everything that is fine folds
into one line. The counts at the top are filters, and the list shows as cards or a table.

**Auto-sniff, on by default.** When the Marketplace installs or updates an integration
or card, Barkley sniffs the version that landed and sends a notification (the bell, and
your phone if you pick a notify service). When the Marketplace starts *offering* an
update, Barkley sniffs that version right away, so the heads-up comes before you click
Update. Notifications carry scores, counts and the app's name, never text taken from the
scanned code. One thing to know: Home Assistant runs a new integration as soon as it is
installed, so the protection for a brand-new install is sniffing it from search first.

**"What would updating change?"** Barkley compares the version you run with the one you
would get and puts the few changes that matter first: new findings, new data flows, new
publishers, new hosts nobody declared. The comparison never changes a score.

**Advisories asked again every day.** A scan keeps the exact package list it resolved,
and once a day Barkley asks the advisory database about it again, without fetching or
scanning any code. A newly published vulnerability in a dependency of something you
installed months ago becomes a new scan entry and a notification. Earlier entries are
never edited.

**A page per app, in plain English.** The score and verdict, "In short", every finding
explained in plain words, a diagram of where data can
flow, the addresses and ports the app talks to, privacy notes (telemetry, analytics,
unencrypted connections), what the app hooks into in Home Assistant, and the scan
history of that app.

**The developer's security habits.** Whether the project runs security scanners in its
own workflows, has Dependabot or Renovate and a security policy, how many dependency
updates are waiting, and open issues that look security-related. It is context from
public signs and never changes the score.

**Addresses you trust.** Barkley can't know every host an app legitimately uses. For
findings that are only about where an address points, you can mark the address trusted,
for one app or for all. Barkley's own score always stays visible next to yours, and
findings about *what* is sent can't be switched off.

**AI explanations, if you want them.** Pick one of your Home Assistant AI Task entities
and Barkley can explain an app's findings, or (in deep mode) read the code around one
finding and answer with statements that must cite the lines they rest on. Nothing is
sent until you click, and only findings and code from the public project are sent, never
anything from your Home Assistant. The AI never sets, clears or changes a score or a
finding: scoring is done by fixed rules. **The explanations are only as good as the
model behind the entity you pick**, and they can be wrong.

**Built for a small box.** Barkley checks free memory before every scan, warns under
2 GB and refuses under 1 GB, so a scan can't push Home Assistant out of memory. A
Diagnostics page shows each tool, the memory figure and the AppArmor profile in use.

The app's own [documentation](addon/sniff_test/DOCS.md) has the details: every option,
how auto-sniff and the AI features work, and what the app is allowed to do.

## Install on Home Assistant

Barkley runs as an app (add-on), so it needs Home Assistant OS or Supervised.

1. Settings → Apps → the app store → ⋮ → Repositories, and add
   `https://github.com/SeriesOfTubez/ha-barkley`.
2. Install **Barkley**, start it, and open it from the sidebar.

The app store downloads a prebuilt image (amd64 or aarch64, about 200 MB). Plan for
0.5 to 1 GB of free memory while a scan runs.

## What gets checked

- **Code** (Semgrep, bundled HA-specific rules): token and data exfiltration, encoded
  payload loaders, auth internals, other integrations' credentials, unauthenticated views.
- **Python dependencies** (integrations): the `manifest.json` requirements are resolved
  the way HA installs them (HA's constraints, its Python version, PyPI plus HA's wheel
  index) for both x86_64 and aarch64 HA OS / Container. Then: typosquats (offline, from
  the name alone), VCS/URL requirements, brand-new packages, known vulnerabilities and
  known-malicious packages (osv-scanner), and heuristic malware checks (GuardDog) on every
  package HA doesn't already ship.
- **Addresses you trust.** A few findings are only about where an address points: a
  hardcoded public IP, or an address in a dependency that GuardDog finds suspicious-looking
  (`https://api.together.xyz/`, which is Together AI). Barkley can't know every host an
  app legitimately uses, so in the panel you can mark such an address trusted, for one app
  or for every app. The finding stays listed and stops costing points until the address
  changes; Barkley's own score is always shown next to yours, and the stored scan is never
  changed. Findings about what is sent, and paste sites, tunnels and chat webhooks, can't
  be switched off. A shipped list (`src/sniff_test/data/known_services.txt`) names who runs
  well-known hosts as a hint; it is matched locally (no host is ever sent anywhere to be
  looked up) and changes no score.
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
  It also rewrites two forms Semgrep misreads (`n?.5:1`, and `new as(...)` for a class
  minified to the name `as`). A code file Semgrep still can't read at all is its own
  finding, and the score can't pass 89 while one is there.
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

## How Barkley itself is secured

A security tool that reads hostile code should be held to its own standard. Three
layers, each of which you can check in this repository.

### The app on your box

- **One permission.** The app asks for the Home Assistant API and nothing else: no host
  network, no open port, no Supervisor role, and no access to your configuration folder,
  so `secrets.yaml` and the auth storage are out of its reach. What it uses the API for
  is a fixed list of calls, named one by one in the
  [documentation](addon/sniff_test/DOCS.md#permissions).
- **Its own AppArmor profile, enforcing** (`addon/sniff_test/apparmor.txt`, Home
  Assistant security rating 8). Every process in the container can run only the tools
  the image ships, write only under `/data` and `/tmp`, and open only ordinary network
  sockets (no raw sockets, no capabilities). Nothing downloaded is executable. A hole
  in one of the parsers that read hostile code is confined to that.
- **The panel** answers only Home Assistant's ingress, which handles the login, and it
  ships no JavaScript at all: its content security policy allows no scripts, only the
  page's own styles, images and fonts.

### Where the image comes from

`.github/workflows/build.yaml` builds the image when a release is published, on
GitHub's runners, from `scripts/stage_addon.py`'s output (the app's files plus the
scanner's source, never the tests or the malicious samples). The Dockerfile pins every
tool's version: uv and osv-scanner are release binaries checked against a sha256,
Semgrep and GuardDog are installed from wheels only (nothing is compiled), and the
scanner's own dependencies are installed with hashes required. The base image's
signature is checked before the build, the workflow's actions are pinned to commits,
and a version that is already published is never overwritten.

Each image is signed with [Cosign](https://docs.sigstore.dev/) by that workflow. Home
Assistant doesn't check app signatures, so there is nothing you have to do; if you'd
like to check the signature yourself:

```sh
cosign verify ghcr.io/seriesoftubez/barkley:0.10.3 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/SeriesOfTubez/ha-barkley/'
```

To build it yourself instead: `uv run python scripts/stage_addon.py`, then
`docker buildx build dist/addon/sniff_test`, or install the staged folder as a local
app (see the app's documentation).

### Checks on every change

`.github/workflows/security.yaml` runs on every push and pull request, and once a
week. The `main` branch only takes changes that passed it and the tests.

| Kind | Tool | What it reads |
|---|---|---|
| Secrets | Gitleaks | every commit |
| SAST | Semgrep's registry rules, CodeQL | the scanner's code and the workflows |
| SCA | Trivy | the lockfile, plus an SBOM |
| IaC | Checkov, Hadolint | the Dockerfile and the workflows |
| Container | Trivy | the image built from the staged folder: CVEs that have a fix (high and critical), configuration, plus an SBOM |

A finding fails the run. Anything accepted is written down with its reason:
`.checkov.yaml`, `.hadolint.yaml`, `.trivyignore` (empty today). The malicious samples
in `tests/` and `demo/` are left out of the code and dependency checks, since being
caught is their job.

## AI-assisted development

Barkley was built with AI pair-programming assistance (Claude, via Claude Code) under
human direction and review; most of the code and docs are AI-generated. If that's a
dealbreaker for you, that's a reasonable position, and this project isn't for you.
Here's what's in place either way, so you can judge for yourself rather than take it on
faith:

- **Security scanning runs on every push and pull request** (the table above, and the
  badge at the top of this page).
- **Those scans have already changed real decisions.** Before the first release Trivy
  found 31 high CVEs in the image: osv-scanner moved up a version, a base-image binary
  nothing used was removed, and the image now takes Debian's security fixes at build
  time.
- **The detection rules are tested**: each rule has annotated test code, the planted
  malware in `tests/fixtures/` must be caught on every run, and a new rule is tried on
  real integrations and cards for noise before its severity is settled.
- **All source is here to read**; nothing is obfuscated or minified. Issues and pull
  requests are welcome, especially reports of a missed detection or a false alarm. AI
  assistance doesn't put the code beyond scrutiny: it means you get to scrutinize it.

## Command line

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
and only send to `.invalid` hosts. To report a security problem, see
[SECURITY.md](SECURITY.md). MIT licensed.
