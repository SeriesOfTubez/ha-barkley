# What gets checked and how the readings work

Barkley scans exactly what the Marketplace would install: the version you ask for, else
the newest release, else the default branch pinned to one commit.

## What gets checked

- **Code** (Semgrep with Barkley's Home Assistant rules): token and data exfiltration,
  encoded payload loaders, use of auth internals, other integrations' credentials,
  unauthenticated views, tampering with Home Assistant itself.
- **Python dependencies** (integrations): the requirements are resolved the way Home
  Assistant installs them, for x86_64 and aarch64. Then: typosquats, requirements that
  point at a URL or repository, brand-new packages, known vulnerabilities and
  known-malicious packages (osv-scanner), for every package Home Assistant doesn't
  already ship.
- **npm dependencies** (cards): the repository's lockfile, checked with osv-scanner.
  Known malware is reported for every package; vulnerabilities for packages the lockfile
  lists as run-time packages. Dev-only packages and known build tools are left out. Since 0.15 a vulnerability in browser code is rated like a Python
  package's (GitHub's rating, else its CVSS score, at most high), because a card's or
  panel's JavaScript runs on Home Assistant's own origin. One that can only slow or stop
  the page (no confidentiality or integrity impact in its CVSS vector, such as a slow
  regular expression) is at most medium. Where Home Assistant runs then applies (see
  [Where Home Assistant runs](#where-home-assistant-runs)).
- **Published libraries** (integrations, since 0.15): a JavaScript file of 64 KB or more
  that is byte for byte a file of a well-known npm package (that version published at
  least 30 days ago, 10,000 downloads in the last week, no malware advisory) isn't read as
  code. It's listed on the app's page as a library and checked for advisories like any
  dependency. Barkley asks jsDelivr by the file's SHA-256. Anything else, including no
  answer or a rate limit, means the file is read in full; skipping by folder or file name
  never happens. Off with [Published libraries](Options) on the Settings page.
- **Addresses:** every host and IP in the shipped code, grouped as on your home network,
  the app's own sites, servers the developer runs, analytics, other sites, or project
  and help links. A site is "the app's own" when the app's `manifest.json` or
  `package.json` links to it or it matches the app's name. On code hosting (GitHub,
  GitLab, Bitbucket, Codeberg, SourceForge) that holds only when every address the code
  names there is under the repository owner's path. Paste sites, request catchers,
  tunnels, chat webhooks with a built-in token and URLs with a hardcoded public IP are
  reported.
- **Possible exfiltration:** reading secrets, auth data or other integrations'
  credentials, plus a request from the code to a site that isn't the app's own, is a
  possible threat, even when the two are in different files. A site the code only names,
  such as a link in a message, doesn't count, unless some request's address couldn't be
  read. Another integration's saved data counts only for a field named like a login
  (password, token, key, secret and so on). Since 0.15 a site that only
  appears in a list of sign-in return addresses (OAuth) doesn't count: it must be a
  constant whose name says redirect or callback, its path must end in a callback or
  redirect segment, and no file of the app may hand it to a call that sends or connects.
  The site stays listed, with a line saying what Barkley found.
- **Requests** (integrations and cards) **and environment variables** (integrations),
  since 0.15: how the code sends each request (the method, and the names of what goes
  into the body, the headers and the address; for a card, also the sites its map images
  come from), and which environment variables it reads and sets. Names only, never
  values. These are facts for the app's page and aren't scored.
- **Code you can't read:** compiled `.pyc` files or native `.so` modules that Home
  Assistant's Python would run instead of, or without, readable source.
- **Packed files** (since 0.15): long base64 or hex text, and compressed data, is
  unpacked as data (at most 32 MB per app) and read like the app's own files. The page
  says so, says what kind of code they hold, and says when the unpacked files change
  another app's files. Recognised pictures, fonts and keys aren't treated as hidden code.
  Barkley has no checks for Lua code, so in packed Lua it only looks for web addresses.
- **A card's login token:** sending it to Home Assistant itself is fine, and Barkley
  follows helpers, guards and Home Assistant's websocket to prove where it goes. Sent to
  the address in the card's own settings, where the card's default is one of Home
  Assistant's own paths (or there is none), it's a note, not a Threat (since 0.15).
- **Scanner evasion:** forms that hide code from the scanner are rewritten in Barkley's
  copy (with the same meaning) or flagged. Since 0.15 that includes JavaScript class
  static blocks (`static { … }`), which Semgrep can't parse. A code file the rules still
  can't read is listed under "What Barkley couldn't read".
- **Repository signals:** ownership transfers, a first release by a new publisher, very
  new repositories, release tags that aren't on the default branch, release zips whose
  code differs from the tagged source, and how the release's commit is signed (a fact,
  never scored).

## Kinds of items

Every item a scan reports has a kind, and an app's page groups them:

- **Threats**: signs of malicious behavior. Sending your data or logins out of your home
  (traced, or possible), addresses used to collect stolen data, known malware, code
  that decodes or downloads code and runs it, disguised code, and code you can't read
  (compiled files, native modules, the `<!--` trick, names built from pieces).
- **What it can do**: powerful things the app is able to do, such as changing who can
  log in, reading other apps' settings or running programs. Some apps need them. They
  are also what an attacker would get if the app were ever taken over.
- **Known vulnerabilities in its libraries**: published security flaws in the code libraries it uses.
- **How it's made**: release and dependency habits, usage reporting.
- **What Barkley couldn't read**: code files the rules couldn't parse.

Threats are shown in the Threat box. Everything else is listed under "What it can do".
The items that add to Exposure are marked **Counts in Exposure** there; the rest is
context. One item there still counts toward Threat: a library whose name is one typo away
from a popular one (it's a How it's made item). Each item still has a severity (critical,
high, medium or low) in the technical report; the kind never changes it.

## The two readings

Since 0.15 the panel shows two readings in place of the 0–100 score. Both run from 0 to
10, and higher is worse. They are worked out from a stored scan by fixed rules each time
a page or a notification needs them. The same scan and the same setting always give the
same readings. No AI is involved.

### Threat

Threat counts only signs of malicious behavior: the Threats kind above, plus a library
whose name is one typo away from a popular one.

| Severity of the sign | Points for the first of a rule |
|---|---|
| Critical | 6 |
| High | 2.5 |
| Medium | 0.8 |
| Low | 0.2 |

Each repeat of the same rule adds a quarter of its points. The total stops at 10, and
any critical sign makes it at least 7. A build tool known to be malware counts 2.5
whatever its severity (Settings → Build tool known to be malware: 2, 2.5 or 3), so on
its own it reads Possible: it runs on the developer's machine, not in your home.

Neither reading counts anything in the developer's test scripts that Home Assistant
never loads. The app's page lists them apart. When the app imports code by a name
Barkley can't follow, nothing is set aside.

| Threat | The panel says |
|---|---|
| 0 | None found · the label follows Exposure (below) |
| above 0, under 7 | Possible · 🐕 Grrrrr · a possible sign of malicious behavior |
| 7 to 10 | Found · 🚨 BORK BORK BORK · malicious behavior found |

With no threat, the label says how much the app opens up:

| Exposure | The panel says |
|---|---|
| Low (under 2) | 🦴 Good Boy · no signs of malicious behavior, low exposure |
| Medium (2 to under 5) | 🐾 Needs training · no signs of malicious behavior, medium exposure |
| High (5 and up) | 🦮 Needs a leash · no signs of malicious behavior, high exposure |

A threat always decides the label. A found threat puts one sentence at the top of the
app's page, saying what the app does and to remove it. The list says how many apps show
malicious behavior.

### Exposure

Exposure counts only what lets someone who isn't an administrator in. An administrator
can already do everything in Home Assistant, so nothing else is counted.

| What | Points |
|---|---|
| A page that opens without logging in to Home Assistant, in a file that checks a signed link or a login token | 0.25 |
| A page that opens without logging in, with no such check that Barkley can confirm | 0.75 |
| The app works with Home Assistant login tokens | 1.25 |
| A published vulnerability in one of its libraries | 1 (medium), 3 (high), 5 (critical) |
| A card loads code from another site while it runs, and which version is picked while it runs | 5 |
| A card loads one fixed version of code from another site | 2 |
| A card runs code taken from the page address (anyone who gets you to open a link could run code in your dashboard) | 5 |
| An integration downloads Lua code while it runs and runs it through the lupa package, where that code can reach Python or run programs | 5 |

- **Pages:** the strongest page counts in full and each further page a quarter.
- **Tokens:** a token handed to another machine is only as safe as that machine. Barkley
  can't tell yet who gets a token or how long it lasts. So it counts one token for a
  user who isn't an administrator, lasting over a year, once per app. An app that only
  checks tokens sent to it isn't counted here.
- **Library vulnerabilities:** each one counts, at the severity the scan gave it (see below).
- **Code a card loads or takes from the address, and Lua an integration downloads:** the
  strongest counts in full and each further one a quarter. Barkley counts downloaded Lua
  only when it can follow the file the code runs back to a web request that wrote it.
  lupa's own source shows that a runner made with its default settings opens all of
  Lua's standard libraries (so Lua can run programs) and gives Lua Python's `eval` and
  builtins. A runner that switches both off, guards attribute access and removes Lua's
  `os` and `io` isn't counted.

Pages, tokens and library vulnerabilities are multiplied by where Home Assistant runs: 1 on a home network, 1.25 on a
shared or work network, 1.5 when it's reachable from the internet. Code a card loads,
and Lua an integration downloads, is added after that, unmultiplied: where Home
Assistant runs doesn't change who publishes that code. The total stops at 10.

| Exposure | The panel says |
|---|---|
| under 2 | Low |
| 2 to under 5 | Medium |
| 5 to 10 | High |

A found threat sets Exposure to 10: the app itself sends your data out. The Exposure
box on an app's page lists the reasons in words, and the pages with their addresses.

Not counted yet: ports the app listens on. The page lists them under Where it connects.

### Why these numbers

One critical sign of malicious behavior is enough for "found", and one high sign reads
"possible". A repeat of the same rule counts a quarter, so one check that matches many
times in a big file doesn't decide a reading on its own. For Exposure, an app with many
login-free pages (an OAuth or webhook integration can have a dozen) isn't High from its
pages alone.

The exact values are a judgment call. They haven't yet been calibrated against a large
set of known good and known bad apps; if that shows a problem the numbers will change in
a release that says so.

### What isn't scored

Everything else: what the app can do, what it touches, where it connects, how it sends
requests, environment variables, where its code comes from, privacy notes, the
developer's security habits, the developer's own words and anything from the AI.

### The capability score

The 0–100 number from before 0.15 is still worked out and stored. You find it in the
technical report (the raw JSON link at the foot of an app's page) and in the command
line's output, called the capability score. It counts what the code openly uses. It
isn't a judgment, and nothing in the panel reads it.

## Minor items

Some items touch no password or login, change nothing, and usually have a plain reason:
listing user accounts (names only), reading other apps' settings (their options, not
their stored data), writing its own files in Home Assistant's `.storage` folder, a
vulnerability in a build tool that never ships in a card, installing its own declared libraries, and
usage reporting that is disclosed or optional.

By default they are hidden. An app's page says how many it left out, with a link to
show them. **Settings → Minor items → Show** always shows them. They never change the
readings.

## If you disagree

There is nothing to accept or mark as reviewed. **Report a false positive** under an
item opens a new public issue on Barkley's GitHub, with the versions, the rule, the file
and the line filled in. You write why it's wrong and submit it yourself.

## Where Home Assistant runs

One setting (Settings → Where Home Assistant runs) with three choices:

| Choice | Exposure reading | What a new sniff finds |
|---|---|---|
| Only my home network (default) | as counted | a known vulnerability in a library is at most medium |
| A shared or work network | up by a quarter | the same |
| Reachable from the internet | up by half | pages that work without a login, pages other websites may call and webhooks count one level higher; a known vulnerability in a library keeps its rating |

Switching between the first two changes the Exposure reading right away. Reachable from
the internet also changes what a sniff finds, and a stored scan keeps the choice it was
made with, so sniff again after changing to or from it. Data leaving your home and other
signs of malicious behavior count the same in all three.

A known vulnerability in one of an app's libraries depends on this, because a flaw an
attacker can't reach is a smaller risk:

- **A home, shared or work network:** at most medium. An item rated higher says so, and
  why it's counted as medium.
- **Reachable from the internet:** its rating (GitHub's, else its CVSS score, at most
  high). If CISA's assessment of the CVE (SSVC, in the CVE record) says it's exploited
  in the wild, or it's in CISA's Known Exploited Vulnerabilities catalog, and it's
  automatable and of total impact, it's critical.

Barkley reads that assessment from the CVE record at `cveawg.mitre.org`. When it can't be
read, nothing is raised.
