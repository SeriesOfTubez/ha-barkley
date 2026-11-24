# Barkley

Barkley gives Home Assistant Marketplace (HACS) integrations and cards a sniff test
before they get into the house. It looks for token theft, data sent off-box, obfuscated
or compiled code that isn't the code you can read, risky dependencies, and repos that
changed hands.

Barkley was built with AI assistance, under human direction and review. The optional AI
features are only as good as the model you pick.

## The sniff report

Since 0.15 the panel shows no 0–100 score. Each app has a sniff report with two readings:

- **Threat**: signs of malicious behavior only. It reads none found, possible
  (🐕 Grrrrr) or found (🚨 BORK BORK BORK). With none found, the label follows Exposure:
  🦴 Good Boy (low), 🐾 Needs training (medium) or 🦮 Needs a leash (high). A found
  threat puts one sentence at the top of the app's page, and the list says how many apps
  show malicious behavior.
- **Exposure**, from 0 to 10, shown as Low (under 2), Medium (2 to under 5) or High
  (5 and up): what the app opens up to someone who isn't an administrator. It counts
  pages that open without logging in to Home Assistant, login tokens the app may hand
  out, published vulnerabilities in its libraries, and code a card loads from another
  site or takes from the page address while it runs. Something only an administrator
  can do adds nothing. The pages, tokens and library vulnerabilities count a quarter more on a
  shared or work network and half more when Home Assistant is reachable from the
  internet (Settings → Where Home Assistant runs). A found threat sets it to 10.

Everything else on an app's page is context and isn't scored. Each block is tagged with
where it comes from: **Barkley's scan**, **The developer's words** or **AI**. The
developer's words, and the AI's summary of them ("AI inferred"), are never shown beside
a found or possible threat. Nothing from the developer or the AI changes a reading.

The old number is still in the technical report (the raw JSON link at the foot of an
app's page), as the capability score: what the code openly uses, not a judgment.

**What changed from 0.14:** reviews are gone (Accept, Mark reviewed, Accept all), and so
are Malware check only, Addresses you trust and Paranoid mode. On its first start 0.15
deletes what 0.14 stored for them, once; stored scans and other settings stay. If you
think Barkley got something wrong, use **Report a false positive** under the item. It
opens a pre-filled public issue that you finish and submit.

## How it works

- Open **Barkley** in the sidebar (HA ingress; HA handles the login).
- **What you have installed:** the first page asks the Marketplace what you have
  installed, with the version you run and the one the Marketplace would install now. It
  leads with what needs a look: a found or possible threat, High exposure, a check that
  didn't finish, or a checked update that brings a change to check. The installed list
  is read again at most every 5 minutes.
- **Sniff it / Sniff again** on an app scans the version you have installed.
  **Check update** scans the offered version and shows what the update would change,
  most important first: new publishers, new data flows, new sites, new items. Stored
  scans are reused on both sides, and the comparison never changes a reading.
- **One button for the rest:** "Sniff N apps not yet sniffed with the current rules"
  scans every installed app that has no scan with Barkley's current rules (after an
  update of Barkley that changed what a scan finds, that is all of them; an update that
  didn't keeps them). "Sniff N unfinished again" repeats every scan that didn't finish,
  and "Sniff all N again" runs a fresh scan of each. Apps already queued or running are
  skipped.
- **The list:** Barkley currently checks integrations and dashboard cards only; the list says what
  else you have that it doesn't check. The counts at the top are filters (needs a look,
  with signs of a threat, with medium or high Exposure, no concerns found, with privacy
  notes, updates waiting, not checked), and Order sorts by most concern first, Threat,
  Exposure or name. Switch between cards and a table;
  long lists are split into pages. A status box at the top shows what's being sniffed,
  and the page reloads itself every 5 seconds while anything runs. A button brings you
  back to the page, filter and view you clicked it on.
- **Check any repository** (further down the first page): sniff a repository by name, at
  the release the Marketplace would install or at a tag you give. Its second form,
  **What would updating change?**, takes a repository and the tag you have installed
  and compares that tag with the release the Marketplace would install now.
- **Find an app to sniff before you install it:** search the Marketplace catalog.
  **Other versions** lists the 10 newest releases, betas included, so you can sniff the
  exact version you plan to pick.
- **Sniff this version again** (on an app's page) runs a fresh scan instead of reusing
  the stored one.
- **Auto-sniff (on by default):** when the Marketplace installs or updates an integration
  or card, Barkley sniffs the version that landed and sends a notification (see below).
  Turn it off, pick who else gets notified, or choose which results notify you (Notify
  when), on the Settings page.
- **An app's page**, top to bottom: the two readings, the Threat box and the Exposure
  box, In short (with the developer's description after an AI request), privacy notes,
  What Barkley found (items that add to Exposure are marked), What it touches, Where the login
  you gave this app goes, Where it connects, Other addresses in its code, Where its code
  comes from, Environment variables it uses, The developer's security habits, Everything
  it uses inside Home Assistant, and History.
- **What it touches:** a picture of the app in your home. Seven rooms, the same for every
  app (users and logins, other apps' settings, devices and entities, files, programs
  and the system, your home network, your browser session), blue where the app reaches
  beyond its own job and dashed where it does nothing; its own space said in grey; the
  sites it sends requests to outside; a red line for a path from your data to a site
  that isn't the app's own, a purple one to where the login you gave this app goes, and
  orange doors for each way in.
- **Where the login you gave this app goes:** the login you entered when you set up the
  app (not your Home Assistant login), followed through its code, or into a library it
  hands it to, to the requests that carry it. For a library, Barkley downloads its
  published package and reads it as text (see Permissions). Context only.
- **Where it connects:** the sites Barkley read a request to, one line each, plus
  flagged sites and ports. A line folds open to show the scheme and port, who runs the
  site, the addresses and where the code names it, and how the code sends requests
  there: the method (GET, POST and so on) and the names of what goes into the body, the
  headers and the address; for a card also the sites its map images come from. Values
  are never recorded. Requests to an address the code puts together while it runs are
  listed apart, with where the address comes from (what you entered at setup, a
  server's answer, a list in the code, a device found on your network, Home Assistant's
  own address, or "couldn't tell"). Sites the code only names are under Other addresses
  in its code.
- **Where its code comes from:** what the Marketplace installs, the project and whose
  account it is under, who published this release and the earlier ones, how the
  release's commit is signed, every Python package Home Assistant would install (the
  ones that come along included), the npm packages a card is built from, published
  libraries copied into the app, and code it gets while it runs.
- **The developer's security habits:** whether the repository runs security scanners in
  its workflows or commit hooks, has Dependabot or Renovate and a SECURITY.md, how many
  dependency-update pull requests wait, and open issues that look security-related.
  It's context read from public signs (GitHub keeps scan alerts private) and never
  changes a reading.
- Every scan is stored in `/data/sniff-test.db` (SQLite), which is part of the app's
  backups. Downloaded HA constraints are cached in `/data/cache` and left out of
  backups.

Scanned code is treated as hostile: it is downloaded and read, never run, built or
installed. The readings are computed by fixed rules; no AI decides anything.

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
  entry** (the earlier one stays in the history as it was), the readings are worked out
  again by the same rules, and the notification gives the readings, the Exposure number
  before, and counts of what changed, with a link to the comparison. If OSV can't be reached nothing changes and
  Barkley tries again an hour later. "Check advisories again" on an app's page does the
  same on request.
- It sends a **bell notification** in Home Assistant (always) and, if you picked one in
  the panel, a `notify.<target>` message (for example your phone through the companion
  app): the app and version, the two readings with a coloured light each (🟢 🟡 🔴), for
  a found or possible threat one fixed sentence saying what it is, and for an update
  counts of what changed. Nothing from the scanned project (no README text, code or
  evidence) and nothing from an AI is ever put in a notification. A test button sends a
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

## Settings and options

Barkley has its own **Settings** page (the Settings link on the panel's first page).
It has two sections, each with Reset to defaults:

- **Readings:** Where Home Assistant runs (Only my home network, A shared or work
  network, Reachable from the internet), Minor items (Hide or Show), Build tool known
  to be malware (2, 2.5 or 3) and Quiet projects.
- **Checking and notifications:** Auto-sniff, Notify, Notify when, AI, AI mode, AI
  answers, AI time limit,
  Parallel scans, Semgrep jobs, Published libraries, Cache of code already read, Memory
  for scans, Low memory and the GitHub token.

The options below are the starting values; once you save the Settings page, it wins. A
GitHub token saved there is kept in its own file next to the database and wins over the
option's.

| Option | Default | Meaning |
|---|---|---|
| `exposure` | `local` | `public` if your HA is reachable from the internet. It starts "Where Home Assistant runs" at Reachable from the internet. That raises the Exposure reading by half, and new sniffs count pages without a login, pages other websites may call and webhooks one level higher. A known vulnerability in a library is at most medium while `local`. Never lowers exfiltration or malware. |
| `jobs` | `1` | Parallel Semgrep jobs inside one scan. More is faster and uses more memory. |
| `parallel_scans` | `2` | How many scans may run at once. A second scan starts only while there's memory for it (Settings → Memory for scans); otherwise it waits. Two checks of the same project never run together. |
| `github_token` | empty | A GitHub token (no scopes needed) for the 5,000 requests/hour limit instead of 60. |
| `ai_entity` | empty | Optional. Easier: pick your AI in the panel (any app's page, "Explain this app with AI"), which lists your AI Task entities. A choice made in the panel wins over this option. |
| `ai_mode` | `deep` | `summary` (Explain only): the AI explains what the scan found. `deep` (Explain and read code): it can also read the code around one item, port or unknown address when you click **Explain in context**. Also set in the panel (wins over this option). |
| `auto_scan` | `true` | Sniff every Marketplace install, update and offered update, and send a notification. Also set in the panel (wins over this option). |
| `notify_target` | empty | A `notify` service name (for example `mobile_app_my_phone`) that gets each auto-sniff result besides the bell notification. Easier: pick it in the panel, which lists your notify services (wins over this option). |

### AI explanations

Pick an AI on any app's page (the dropdown lists your AI Task entities; Home Assistant
renders one fixed template that returns only their ids and names), and each app's page
gets an **Explain this app** button. Nothing is
sent until you click it. Barkley then calls Home Assistant's `ai_task.generate_data`
with what that scan found: rule names, severities, file names and short code excerpts
from the public project that was scanned. No Home Assistant data is sent. The request
goes to whatever AI provider your AI Task entity uses, which for OpenRouter and similar
integrations is a cloud service.

The AI only explains. The readings and the list of items are computed without it, and
nothing it says can change them. Its answer is shown as plain text labeled "AI
explanation", tagged AI, next to the fixed explanation, and it can be wrong. It's only
as good as the model behind the entity you pick. Code from the scanned project can
contain text aimed at the AI; it is marked as untrusted in the request.

In the Explain and read code mode, the same click makes one more request, with the
start of the README, the README passages on logins, accounts, where data goes, privacy
and what the app runs, and the descriptions in the code (docstrings and the comment
block above a function) that the scan stored: at most 6,000, 12,000 (the default) or
18,000 characters (Settings → AI answers). The AI may write up to four sentences at
6,000 and up to six above, on what the developer says the app does, each ending
with the lines it rests on. Barkley shows a sentence only if those lines were sent and
have text on them, every code name it mentions is on them, at least three of its longer
words are on them, and it gives no verdict. Shown sentences are tagged **AI inferred**,
under the item they are about or under In short as "The developer's description". The
developer wrote those lines: Barkley checks that they exist and hold the words, not that
they are true. This request is not sent when a threat was found. With a possible threat,
the descriptions on the threat and on the logins it could take are not sent, and only a
sentence about another listed item is kept. Nothing from it changes a reading, the list
or a notification.

### AI deep analysis (`ai_mode: deep`)

Each item, each port, and each address that isn't one of the app's own sites gets an
**Explain in context** button. During the scan, Barkley keeps the code around it:
the function it's in, the functions that use a flagged address, the functions and
classes of the app that it calls or refers to (in the same file or a sibling module),
starting with the ones named on the flagged line, and the import lines and constants
behind the names used. That is at most 150 lines of code plus 40 of imports and
constants, and you can open it under "The code it reads" before you click. When you
click, that code and the question go to your AI; nothing is sent before. It is the
app's own public code, never anything from your Home Assistant.
A privacy note shows the button, or the reading, of the address or port behind it:
the same reading as under "Where it connects", not a second one. A note whose addresses
are all the app's own sites has none, and says so.

For integrations the AI may ask once to see more of the app's code. It can only pick
from a list of names Barkley offers (at most three picks; never a file path; in a pick
written as a sentence only the listed names count), Barkley adds that code (at most 150
more lines) and asks again. The sheet shows the checked statements of both readings
together; one that repeats an earlier one in other words is shown once. Your one
click covers both requests; the sheet says what was asked for and shows the added code.
For this, Barkley keeps a compressed copy of an integration's Python files in its
store: one per version, for the installed version and a waiting update, never over 1 MB
per app (a bigger app, or one with more than 3,000 Python files, gets no copy, and the
sheet says the AI can't ask for more).

For the item "Changes how Home Assistant itself works" the page also says what is
replaced and whose code that is ("What it replaces"). Barkley reads that from the
code's import lines; no AI is involved. When a function of Home Assistant's own source
is replaced by a function of the app, Barkley also reads that one file of Home Assistant
(at your version, from Home Assistant's repository on GitHub) during the scan and
compares the two line by line: "How it differs from the original" gives the counts and
the comparison, or says why there is none. "The rest of the replacement" says whether
the scan has anything else on the replacement's lines. Neither changes a reading, and
neither says the code is safe.

On that item, the AI is also sent the first lines of the app's
README (at most 80) and may add one sentence saying the code is consistent with it. It
is shown apart, under "The AI thinks the code matches the README", only if it cites
README lines and code lines and gives no verdict. A README is written by the app's
author, so matching it is not the same as safe; no reading changes. No other item gets
this opinion.

The AI answers in short statements, and each must cite the lines it rests on.
Barkley shows a statement only if the cited lines are in the code it sent, they are
code (not comments), and they contain the names the statement mentions. A statement
that calls an item a false positive, safe or harmless is dropped: the AI may add
questions but can't clear anything, and no reading changes. The page says how
many statements were left out and why.

The entity needs a model that supports structured output. Home Assistant's OpenRouter
integration asks for a strict JSON schema, so a model without schema support will fail
with an error on the page.

## Resources

Semgrep is the heavy part. Across the 6,753 Marketplace apps Barkley scanned in
November 2026, half the scans needed under 0.4 GB, 99 in 100 under 1 GB, and 18 more
than 1.5 GB (the biggest, an integration, about 8.5 GB). Up to `parallel_scans` scans run
at once, but only while memory allows. Home Assistant sets no memory limit for apps, so
Barkley guards itself: with under 2 GB available on the box the panel warns, and by
default it won't start a scan with under 1 GB free (Settings → Low memory), so a scan
can't push Home Assistant out of memory. Diagnostics shows the current figure.

## Permissions

The app asks for the Home Assistant API only. It reads the installed HA version (so
dependencies resolve against the release you run) and whether an external URL is set
(yes or no; the address isn't kept), asks the Marketplace for its installed list
(`marketplace/repositories/list`, or HACS's `hacs/repositories/list` on older HA), and,
only when you click
"Explain this app" or "Explain in context", calls `ai_task.generate_data` over the
websocket (`call_service`, with the answer returned; a request through the Supervisor's
API would end after 5 minutes). To
fill the AI dropdown it asks Home Assistant to render one fixed template that returns
only the ids and names of AI Task entities. For auto-sniff it subscribes to two of the
Marketplace's websocket signals (`marketplace/subscribe`: an install that ended, an
uninstall); that, the installed list and the AI call are the only websocket commands
the app sends. It calls
`persistent_notification.create` and, only when you picked one, `notify.<target>`; to
offer the targets it reads the list of services once and keeps only the `notify` names.
It reads its own app info from the Supervisor (allowed for every app) to build the
"Open Barkley" link. No host network,
no ports, no Supervisor role, no folder access: the app never reads your config folder
and never opens the installed copies.

Scanned code is never run, built or installed. One kind of library is downloaded and
read: one an integration hands the login you gave it (or an address) to. Barkley
downloads that library's published package from PyPI's file host (the exact version
the app gets, checksum checked, at most four per scan and 40 MB each), unpacks it as
files and reads it as text.

The app ships its own AppArmor profile (`apparmor.txt`, security rating 8). It confines
every process in the container to what Barkley needs: run only programs the image
ships (its own Python, the scanner and the pinned tools), and use only ordinary
network sockets. Barkley writes only under `/data` (the scan store, options and caches)
and `/tmp` (one workspace per scan); s6, the start-up system the container runs on, also
writes its own folders under `/run` and `/etc`. Nothing downloaded is executable. The
scanner reads
hostile code with several parsers, and this is the line that holds if one of them has a
bug. Diagnostics shows the profile the app runs under; the Supervisor loads the profile
when the app is installed or updated, so after an update check that the Diagnostics
line names Barkley's own profile, ending in `sniff_test (enforce)`
(`local_sniff_test (enforce)` for a local install), rather than `docker-default`.

Inside that, each run of a scanner tool gets a sandbox of its own (Landlock, a Linux
kernel feature): it can write only that scan's folder, can't read the scan store, the
options or other scans, can run only what the image ships, and can connect only to port
443 (Semgrep nowhere). It can't read Barkley's environment, where the Supervisor's
token is, or signal Barkley (Linux 6.12 or later). The Tool sandbox line on Diagnostics
names Landlock. On a kernel without
Landlock (HA OS today), each tool runs in a narrower AppArmor profile of the app's own,
`tools`: it can't read the Supervisor's token, the options or the scan store, and writes
only to `/tmp` and the cache. Diagnostics then names that profile. If neither sandbox
works, Barkley doesn't start, and the log says why.

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
