# Sniff Test

Sniffs Home Assistant Marketplace (HACS) integrations and cards before they get into
the house: token theft, data sent off-box, obfuscated or compiled code that isn't the
code you can read, risky dependencies, and repos that changed hands.

## How it works

- Open **Sniff Test** in the sidebar (HA ingress; HA handles the login).
- **Sniff it:** scan a repo at the release HACS would install, or at a tag.
- **What would updating change?** Give the tag you have installed. The app scans the
  release HACS would install now, reuses the stored scan of your installed tag (or
  scans it), and shows what the update changes, most important first: new publishers,
  new data flows, new hosts, new findings. The diff never changes a score.
- **Installed through HACS:** the panel asks HACS what you have installed, with the
  version you run and the one HACS would install now (it follows your "show beta"
  switch). It leads with what needs a look (a checked update that brings a new
  publisher or new findings, or a scan that isn't Good Boy), then updates you haven't
  checked yet. **Check update** runs the update diff, reusing stored scans. Items that
  are up to date fold into one line. The list is refreshed at most every 5 minutes.
- **The list:** the counts at the top are filters (worth a look, no concerns, privacy
  notes, updates). Switch between cards and a table; long lists are split into pages. A
  status box at the top shows what's being sniffed, and the page reloads itself every
  5 seconds while anything runs.
- **Find an app to sniff before you install it:** search the Marketplace catalog.
  **Other versions** lists the 10 newest releases, betas included, so you can sniff the
  exact version you plan to pick.
- **Sniff this version again** (on an app's page) runs a fresh scan instead of reusing
  the stored one.
- **The developer's security habits** (on an app's page): whether the repository runs
  security scanners in its workflows, has Dependabot or Renovate and a SECURITY.md, how
  many dependency-update pull requests wait, and open issues that look security-related.
  It's context read from public signs (GitHub keeps scan alerts private) and never
  changes the score. It costs 2 GitHub requests per scan.
- Every scan is stored in `/data/sniff-test.db` (SQLite), which is part of the app's
  backups. Downloaded HA constraints are cached in `/data/cache` and left out of
  backups.

Scanned code is treated as hostile: it is downloaded and read, never run, built or
installed. Scores are computed by fixed rules; no AI decides anything.

## Options

| Option | Default | Meaning |
|---|---|---|
| `exposure` | `local` | `public` if your HA is reachable from the internet. Raises inbound findings; never lowers exfiltration findings. |
| `jobs` | `1` | Parallel Semgrep jobs inside one scan. More is faster and uses more memory. |
| `parallel_scans` | `2` | How many scans may run at once. A second scan starts only while the box has room for another full scan above the 2 GB warning line (1.5 GB counted for each scan already running); otherwise it waits. Two checks of the same project never run together. |
| `github_token` | empty | A GitHub token (no scopes needed) for the 5,000 requests/hour limit instead of 60. |
| `ai_entity` | empty | Optional. Easier: pick your AI in the panel (any app's page, "Explain this app with AI"), which lists your AI Task entities. A choice made in the panel wins over this option. |

### AI explanations

Pick an AI on any app's page (the dropdown lists your AI Task entities; Home Assistant
renders one fixed template that returns only their ids and names), and each app's page
gets an **Explain this app** button. Nothing is
sent until you click it. Sniff Test then calls Home Assistant's `ai_task.generate_data`
with that scan's findings: rule names, severities, file names and short code excerpts
from the public project that was scanned. No Home Assistant data is sent. The request
goes to whatever AI provider your AI Task entity uses, which for OpenRouter and similar
integrations is a cloud service.

The AI only explains. The score, the verdict and the list of findings are computed
without it, and nothing it says can change them. Its answer is shown as plain text
labeled "AI explanation", next to the fixed explanation, and it can be wrong. Code
from the scanned project can contain text aimed at the AI; it is marked as untrusted
in the request.

The entity needs a model that supports structured output. Home Assistant's OpenRouter
integration asks for a strict JSON schema, so a model without schema support will fail
with an error on the page.

## Resources

Semgrep is the heavy part: plan for 0.5–1 GB of RAM while a large card bundle is
scanned (an integration scan peaked at about 1.1 GB). Up to `parallel_scans` scans run
at once, but only while memory allows. Home Assistant sets no memory limit for apps, so
Sniff Test guards itself: with under 2 GB available on the box the panel warns, and
under 1 GB it refuses to start a scan, so a scan can't push Home Assistant out of
memory. Diagnostics shows the current figure.

## Permissions

The app asks for the Home Assistant API only. It reads the installed HA version (so
dependencies resolve against the release you run), asks the Marketplace for its
installed list (`marketplace/repositories/list`, or HACS's `hacs/repositories/list` on
older HA; the only websocket commands the app sends), and, only when you click
"Explain this app", calls `ai_task.generate_data` (the only service it calls). To
fill the AI dropdown it asks Home Assistant to render one fixed template that returns
only the ids and names of AI Task entities. No host network,
no ports, no Supervisor role, no folder access: the app never reads your config folder
and never opens the installed copies.

## Installing as a local add-on

1. In the repository: `uv run python scripts/stage_addon.py` (writes
   `dist/addon/sniff_test/`, the add-on plus the scanner's source, and
   `dist/addon/sniff_test.tar`, a plain archive of it).
2. Stream the archive into Home Assistant's local add-on folder, `/local_apps` in the
   Terminal & SSH add-on (older installs: `/addons`):
   `ssh root@homeassistant.local 'rm -rf /local_apps/sniff_test && tar -C /local_apps -xf -' < dist/addon/sniff_test.tar`
   Don't pipe macOS `tar` instead: it adds pax headers that the HA side extracts as
   stray files.
3. Settings → Apps → the app store → ⋮ → Check for updates (older HA: Settings →
   Add-ons → Add-on store). Sniff Test appears in the local section. Install it (your box builds the image: a few minutes, about
   1 GB of disk), then start it and open it from the sidebar.

To update, stage again, stream the archive again, then use Rebuild on the app's page.

## Building the image elsewhere

```
uv run python scripts/stage_addon.py
docker buildx build --platform linux/amd64,linux/arm64 dist/addon/sniff_test
```
