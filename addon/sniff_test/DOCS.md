# Barkley

Barkley is the dog who gives Home Assistant Marketplace (HACS) integrations and cards a
sniff test before they get into the house. It looks for token theft, data sent off-box,
obfuscated or compiled code that isn't the code you can read, risky dependencies, and
repos that changed hands.

## How it works

- Open **Barkley** in the sidebar (HA ingress; HA handles the login).
- **What you have installed:** the first page asks the Marketplace what you have
  installed, with the version you run and the one the Marketplace would install now. It
  leads with what needs a look (a checked update that brings something important, or a
  scan that scored under 90 or didn't finish), then updates you haven't checked yet,
  then checked updates that change nothing important. Items that are up to date and
  fine fold into one line. The installed list is read again at most every 5 minutes.
- **Sniff it / Sniff again** on an app scans the version you have installed.
  **Check update** scans the offered version and shows what the update would change,
  most important first: new publishers, new data flows, new hosts, new findings. Stored
  scans are reused on both sides, and the comparison never changes a score.
- **One button for the rest:** "Sniff the N not yet sniffed" scans every installed app
  that has no scan by this version of Barkley (after an update of Barkley, that is all
  of them). "Sniff the N unfinished again" repeats every scan that didn't finish. Apps
  already queued or running are skipped.
- **The list:** the counts at the top are filters (worth a look, no concerns found,
  with privacy notes, updates waiting, not checked). Switch between cards and a table;
  long lists are split into pages. A status box at the top shows what's being sniffed,
  and the page reloads itself every 5 seconds while anything runs. A button brings you
  back to the page, filter and view you clicked it on.
- **Check any repository** (further down the first page): sniff a repository by name, at
  the release the Marketplace would install or at a tag you give. Its second form,
  **What would updating change?**, takes a repository and the tag you have installed
  and compares that tag with the release the Marketplace would install now.
- **Addresses you trust:** a few findings are only about where an address points (an
  internet address written into the code as a number, or an address in a code library
  that an automatic check finds suspicious-looking). Such a finding offers **Trust for
  this app** and **Trust for every app**. The finding stays listed, under "Findings
  about addresses you trust", and stops costing points until the address changes;
  Barkley's own score is always shown beside yours, and the stored scan is never
  changed. Findings about what an app sends, and paste sites, tunnels and chat
  webhooks, can't be trusted away. Only your own clicks create a trust mark; no list
  and no AI does. **Stop trusting** on the app's page, or the "Addresses you trust"
  page (linked at the foot of the first page), undoes it.
- **Find an app to sniff before you install it:** search the Marketplace catalog.
  **Other versions** lists the 10 newest releases, betas included, so you can sniff the
  exact version you plan to pick.
- **Sniff this version again** (on an app's page) runs a fresh scan instead of reusing
  the stored one.
- **Auto-sniff (on by default):** when the Marketplace installs or updates an integration
  or card, Barkley sniffs the version that landed and sends a notification (see below).
  Turn it off, or pick who else gets notified, in the box on the panel's first page.
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

## Auto-sniff: installs and updates

Barkley watches the Marketplace (its `marketplace/subscribe` events, with a read of the
installed list every 10 minutes as a fallback, and once at start to catch what changed
while Barkley was stopped). When an integration or card is installed or updated:

- It sniffs **the version that landed**, not the newest release. A stored scan of that
  exact version is reused, for example one you sniffed from search before installing.
- For an update it shows **what changed** since the version you had, using the stored
  scan of that version (scanning it first if there is none). One scan per version; the
  scan queues behind whatever is already running.
- **An offered update is sniffed before you install it.** When the Marketplace starts
  offering a new version of something you have, Barkley sniffs that version right away
  and tells you what it changes, so the heads-up comes before you click Update. The
  auto-sniff after the update then reuses those scans.
- **Advisories are asked again once a day.** A scan is reused for as long as an app stays
  at that version, but a vulnerability, or a package found to be malicious, can be
  published after the scan. So each scan keeps the list of packages it resolved (the
  lockfiles, stored beside the scan), and once a day Barkley asks OSV about exactly those
  packages again, for every installed version and every update waiting. It takes seconds:
  the app's code is not fetched or scanned again, and GitHub is not asked anything. When
  nothing changed you hear nothing. When something did, the result is stored as a **new
  entry** (the earlier one stays in the history as it was), the score is worked out again
  by the same rules, and the notification gives the old and new score and counts of what
  changed, with a link to the comparison. If OSV can't be reached nothing changes and
  Barkley tries again an hour later. "Check advisories again" on an app's page does the
  same on request.
- It sends a **bell notification** in Home Assistant (always) and, if you picked one in
  the panel, a `notify.<target>` message (for example your phone through the companion
  app): the app and version, the verdict and score, up to three things worth a look in
  plain words, and for an update what changed. Nothing from the scanned project (no
  README text, code or evidence) is ever put in a notification. A test button sends a
  sample through both.

**Read this before you rely on it. A new integration runs as soon as it's installed.**
Since Home Assistant 2026.11 the Marketplace sets a new integration up without a restart:
right after the files land, Home Assistant opens its setup dialog, which loads its code.
Barkley's auto-sniff comes after that, so for a new install it can only tell you what
you already let in. The protection for a new install is to **sniff it from search
first** (the search box on the panel's first page) and install only what passes. An
update's new code waits for the next restart, so there the auto-sniff and its diff come
before the code runs. Barkley reports; it never moves, refuses or blocks anything.

Scans of apps that aren't installed are deleted after 7 days (sniff-before-install scans
included, unless the app was installed by then, in which case the scan is reused). A
scan of anything installed, at any version, is never deleted.

## Options

| Option | Default | Meaning |
|---|---|---|
| `exposure` | `local` | `public` if your HA is reachable from the internet. Raises inbound findings; never lowers exfiltration findings. |
| `jobs` | `1` | Parallel Semgrep jobs inside one scan. More is faster and uses more memory. |
| `parallel_scans` | `2` | How many scans may run at once. A second scan starts only while the box has room for another full scan above the 2 GB warning line (1.5 GB counted for each scan already running); otherwise it waits. Two checks of the same project never run together. |
| `github_token` | empty | A GitHub token (no scopes needed) for the 5,000 requests/hour limit instead of 60. |
| `ai_entity` | empty | Optional. Easier: pick your AI in the panel (any app's page, "Explain this app with AI"), which lists your AI Task entities. A choice made in the panel wins over this option. |
| `ai_mode` | `summary` | `summary`: the AI explains the findings. `deep`: it can also read the code around one finding, port or unknown address when you click **Explain in context**. Also set in the panel (wins over this option). |
| `auto_scan` | `true` | Sniff every Marketplace install, update and offered update, and send a notification. Also set in the panel (wins over this option). |
| `notify_target` | empty | A `notify` service name (for example `mobile_app_my_phone`) that gets each auto-sniff result besides the bell notification. Easier: pick it in the panel, which lists your notify services (wins over this option). |

### AI explanations

Pick an AI on any app's page (the dropdown lists your AI Task entities; Home Assistant
renders one fixed template that returns only their ids and names), and each app's page
gets an **Explain this app** button. Nothing is
sent until you click it. Barkley then calls Home Assistant's `ai_task.generate_data`
with that scan's findings: rule names, severities, file names and short code excerpts
from the public project that was scanned. No Home Assistant data is sent. The request
goes to whatever AI provider your AI Task entity uses, which for OpenRouter and similar
integrations is a cloud service.

The AI only explains. The score, the verdict and the list of findings are computed
without it, and nothing it says can change them. Its answer is shown as plain text
labeled "AI explanation", next to the fixed explanation, and it can be wrong. Code
from the scanned project can contain text aimed at the AI; it is marked as untrusted
in the request.

### AI deep analysis (`ai_mode: deep`)

Each finding, each port, and each address the app's docs don't explain gets an
**Explain in context** button. During the scan, Barkley keeps the code around it:
the function it's in, the functions that use a flagged address, the functions and
classes of the app that it calls or refers to (in the same file or a sibling module),
starting with the ones named on the flagged line, and the import lines and constants
behind the names used. That is at most 150 lines of code plus 40 of imports and
constants, and you can open it under "The code it reads" before you click. When you
click, that code and the question go to your AI; nothing is sent before. It is the
app's own public code, never anything from your Home Assistant.

For integrations the AI may ask once to see more of the app's code. It can only pick
from a list of names Barkley offers (at most three picks; never a file path, never its
own words), Barkley adds that code (at most 150 more lines) and asks again. The sheet
shows the checked statements of both readings together. Your one
click covers both requests; the sheet says what was asked for and shows the added code.
For this, Barkley keeps a compressed copy of an integration's Python files in its
store: one per version, for the installed version and a waiting update, never over 1 MB
per app (a bigger app, or one with more than 3,000 Python files, gets no copy, and the
sheet says the AI can't ask for more).

For the finding "Changes how Home Assistant itself works" the page also says what is
replaced and whose code that is ("What it replaces"). Barkley reads that from the
code's import lines; no AI is involved. When a function of Home Assistant's own source
is replaced by a function of the app, Barkley also reads that one file of Home Assistant
(at your version, from Home Assistant's repository on GitHub) during the scan and
compares the two line by line: "How it differs from the original" gives the counts and
the comparison, or says why there is none. "The rest of the replacement" says whether
the scan has anything else on the replacement's lines. Neither changes the score, and
neither says the code is safe.

On that finding, the AI is also sent the first lines of the app's
README (at most 80) and may add one sentence saying the code is consistent with it. It
is shown apart, as the AI's opinion, only if it cites README lines and code lines and
gives no verdict. A README is written by the app's author, so matching it is not the
same as safe; the score does not change. No other finding gets this opinion.

The AI answers in short statements, and each must cite the lines it rests on.
Barkley shows a statement only if the cited lines are in the code it sent, they are
code (not comments), and they contain the names the statement mentions. A statement
that calls a finding a false positive, safe or harmless is dropped: the AI may add
questions but can't clear anything, and the score never changes. The page says how
many statements were left out and why.

The entity needs a model that supports structured output. Home Assistant's OpenRouter
integration asks for a strict JSON schema, so a model without schema support will fail
with an error on the page.

## Resources

Semgrep is the heavy part: plan for 0.5–1 GB of RAM while a large card bundle is
scanned (an integration scan peaked at about 1.1 GB). Up to `parallel_scans` scans run
at once, but only while memory allows. Home Assistant sets no memory limit for apps, so
Barkley guards itself: with under 2 GB available on the box the panel warns, and
under 1 GB it refuses to start a scan, so a scan can't push Home Assistant out of
memory. Diagnostics shows the current figure.

## Permissions

The app asks for the Home Assistant API only. It reads the installed HA version (so
dependencies resolve against the release you run), asks the Marketplace for its
installed list (`marketplace/repositories/list`, or HACS's `hacs/repositories/list` on
older HA; the only websocket commands the app sends), and, only when you click
"Explain this app" or "Explain in context", calls `ai_task.generate_data`. To
fill the AI dropdown it asks Home Assistant to render one fixed template that returns
only the ids and names of AI Task entities. For auto-sniff it subscribes to two of the
Marketplace's websocket signals (an install that ended, an uninstall), calls
`persistent_notification.create` and, only when you picked one, `notify.<target>`; to
offer the targets it reads the list of services once and keeps only the `notify` names.
It reads its own app info from the Supervisor (allowed for every app) to build the
"Open Barkley" link. No host network,
no ports, no Supervisor role, no folder access: the app never reads your config folder
and never opens the installed copies.

The app ships its own AppArmor profile (`apparmor.txt`, security rating 8). It confines
every process in the container to what Barkley needs: run only the image's own Python,
the scanner and the pinned tools (Semgrep, GuardDog, osv-scanner, uv), write only under
`/data` (the scan store, options and caches) and `/tmp` (one workspace per scan), and
use only ordinary network sockets. Nothing downloaded is executable. The scanner reads
hostile code with several parsers, and this is the line that holds if one of them has a
bug. Diagnostics shows the profile the app runs under; the Supervisor loads the profile
when the app is installed or updated, so after an update check that the Diagnostics
line names Barkley's own profile, ending in `sniff_test (enforce)`
(`local_sniff_test (enforce)` for a local install), rather than `docker-default`.

## Installing

From the app store: Settings → Apps → the app store → ⋮ → Repositories, add
`https://github.com/SeriesOfTubez/ha-barkley`, then install Barkley. Home Assistant
downloads a prebuilt image for your box (amd64 or aarch64). Updates then appear on the
app's page like any other app's.

## Installing as a local add-on (for development)

1. In the repository: `uv run python scripts/stage_addon.py` (writes
   `dist/addon/sniff_test/`, the add-on plus the scanner's source, and
   `dist/addon/sniff_test.tar`, a plain archive of it).
2. Stream the archive into Home Assistant's local add-on folder, `/local_apps` in the
   Terminal & SSH add-on (older installs: `/addons`):
   `ssh root@homeassistant.local 'rm -rf /local_apps/sniff_test && tar -C /local_apps -xf -' < dist/addon/sniff_test.tar`
   Don't pipe macOS `tar` instead: it adds pax headers that the HA side extracts as
   stray files.
3. Settings → Apps → the app store → ⋮ → Check for updates (older HA: Settings →
   Add-ons → Add-on store). Barkley appears in the local section. Install it (your box builds the image: a few minutes, about
   1 GB of disk), then start it and open it from the sidebar.

To update, stage again, stream the archive again, then use Rebuild on the app's page.
When the version in `config.yaml` changed, Home Assistant refuses Rebuild: reload the
store (`ha store reload`) and use Update instead.

## Building the image elsewhere

```
uv run python scripts/stage_addon.py
docker buildx build --platform linux/amd64,linux/arm64 dist/addon/sniff_test
```
