# Changelog

Barkley is AI-assisted. The full release notes are on GitHub:
https://github.com/SeriesOfTubez/ha-barkley/releases

## 0.15.0

This release changes what a scan finds, so scans made by 0.14 aren't reused. After the
update the list offers one button to sniff your apps again.

**The sniff report: Threat and Exposure**

- Each app now gets two readings in place of the 0–100 score. Threat counts only signs
  of malicious behavior: none found, possible, or found. Exposure, from 0 to 10 (Low,
  Medium or High), counts what lets someone who isn't an administrator in: pages that
  skip Home Assistant's login, login tokens the app may hand out, and published bugs in
  its libraries. Everything else Barkley finds is listed as context and changes neither
  reading.
- The dog words go with Threat only: Good Boy (none found), Sus (possible), BORK BORK
  BORK (found).
- The 0–100 number stays in the technical report (raw JSON) and the command line, as the
  capability score: what the code openly uses, not a judgment.
- Settings: "Where Home Assistant runs" (home, a shared or work network, or reachable
  from the internet) replaces Exposure, and "Minor items" (Hide or Show) replaces
  Paranoid mode. Powerful no threat, Pages without a login and Hidden usage reporting
  are gone: they only changed the score.
- Command line: `--fail-on possible` or `--fail-on found` replaces `--fail-under`.
- Notifications show the two readings with a coloured light each (🟢 🟡 🔴), and for an
  update the Exposure number before it.
- The list sorts and filters by the readings. "Needs a look" means a found or possible
  threat, High exposure, a check that didn't finish, or an update with a change to check.

**Reviews are gone**

- Accept, Mark reviewed, Accept all, the Reviewed filter, the reviewed score, Malware
  check only and Addresses you trust are removed. With the Threat and Exposure readings
  they no longer changed anything. If you think Barkley got something wrong, use Report
  a false positive under it.
- On its first start, 0.15 deletes what 0.14 stored for them: the findings you
  accepted, the addresses you trusted and the apps set to Malware check only. Your
  stored scans and settings stay.

**Every block says where it comes from**

- Each block on an app's page is tagged Barkley's scan, The developer's words, or AI.
  The developer's words, and the AI's summary of them ("AI inferred"), are never shown
  beside a found or possible threat. Nothing from the developer or the AI changes a
  reading.
- The developer's note under an item is the description (docstring) the developer wrote
  in the code there, quoted with its file and lines.

**More facts on an app's page (none of them scored)**

- How it sends web requests (integrations): open a site under Where it connects to see
  the method (GET, POST and so on) of each request the Python code sends there, and the
  names of what the call puts into the body, the headers and the address. Values are
  never recorded. Requests to an address the code puts together while it runs are listed
  apart. The method alone doesn't tell you what is sent: a GET can carry data too.
  Barkley reads requests that go through the app's own helper functions too.
- How a card sends web requests: fetch, XMLHttpRequest and sendBeacon calls whose site
  is written out, with the method, the headers and query fields, and whether there's a
  body. Map image addresses show as "Loads map images". Sites with a request or map
  images go under Where it connects; the others go under Other addresses in its code.
- Environment variables it uses (integrations): which ones the code reads and sets, by
  name when the code spells the name out, and whether it reads back one it set itself.
- Pages that open without logging in to Home Assistant are listed in the Exposure box
  with the address each one answers on, when the code spells it out.
- A site named only in a list of sign-in return addresses (OAuth) is no longer treated
  as a place the app could send your logins to. It stays listed, with a line saying so.
- A site the app's README mentions, or its funding file lists, says so in the site's
  fold, as the developer's words. It doesn't change the site's group.
- On code hosting (GitHub, GitLab, Bitbucket, Codeberg, SourceForge) a site is "the
  app's own" only when every address the code names there is under the repository
  owner's path.
- Sites, ports and libraries are one line each and fold open. A long list shows five,
  then "N more".
- Under the app's name: the kind of app, the version, a link to the repository, stars,
  and downloads when GitHub counts them.

**What it does: a picture of the app in your home**

- At the top of an app's page. Inside your Home Assistant are seven rooms, the same
  for every app: users and logins, other apps' settings, devices and entities, files,
  programs and the system, your home network, and your browser session. A room is
  blue when the app reaches into it beyond its own job, and dashed when Barkley saw it
  do nothing there.
- What the app does in its own space is said in grey: the kinds of entity it adds, its
  own storage file, its own sidebar page, devices Home Assistant finds for it. A card
  says it runs in your browser session with your Home Assistant login.
- Outside are the sites it sends requests to. A path Barkley found from your data to a
  site that isn't the app's own is red.
- Exposure is orange and points in: a door for each way in (a page that opens without
  logging in, messages from the internet, a link that can run code), and a strip on the
  app for libraries with known security bugs.
- A dotted orange arrow shows code from outside that runs here: from the site a card
  loads code from into your browser session, and from where an integration downloads
  Lua into Programs and the system. When the address comes from a server's answer, the
  arrow starts at a dashed box linked to the sites that answer.
- On a phone the same picture is stacked, one part under the other. Settings →
  Exposure bar decides when the orange strip with the Exposure reading shows: medium
  and high (default), high only, or always.

**Where the login you gave this app goes**

- Barkley follows the logins you enter when you set up an integration (a password,
  token or API key) through its code to the requests that carry them. A box on the
  app's page lists each one: what is sent, whether the app or a library sends it, and
  where it goes. On the picture that line is purple.
- When the code builds a request's address while it runs, Barkley says where the
  address comes from: what you entered at setup, a list of sites in the code, a
  server's answer, a device found on your network, Home Assistant's own address, or
  "couldn't tell". An address you entered shows as a dashed box on the picture: Barkley
  can't tell whether it's on your home network or the internet. Sites the code picks
  from a list in it are shown with the sites it connects to, and on the picture. When
  the address comes from the answer of one of a few sites in the code, those sites are
  named. Barkley also follows methods an app's class gets from its own base class.
- When an integration hands the login you gave it, or an address, to a library it
  requires, Barkley reads inside that library, one level deep. It downloads the
  library's published package (the exact version the app gets, checksum checked, at
  most four per scan and 40 MB each, from PyPI's file host Barkley already used) and
  reads it as text. It is never installed, imported or run. A site the library connects
  to is listed with "through a library". If the download fails, the page says the
  library wasn't read; that's never a finding.
- All of this is context. None of it changes a reading.

**Where its code comes from**

- A new section on an app's page: what the Marketplace installs, the project and whose
  account it is under, who published this release and who published the earlier ones,
  and how the release's commit is signed.
- Every Python package Home Assistant would install for an integration, the ones that
  come along with the app's own included. For a card, the npm packages its
  `package.json` lists.
- Published libraries it ships: each recognised library says "not read" or "read as
  code", with the reason (too new, too few downloads, no answer from npm, a malware
  warning), and how many large files matched nothing.
- Code it gets while it runs: packages it installs or code it loads after it's installed.
  For an integration that runs Lua code through the lupa package, where that Lua comes
  from: downloaded while it runs (and from where), shipped in the release, packed in its
  code, or a file Barkley couldn't follow. Barkley has no checks for Lua code itself.

**AI**

- In the Explain and read code mode, Explain this app makes one more request with the
  README passages and code descriptions the scan stored: the README's opening lines
  first, then the descriptions (docstrings, and the comment block above a function).
  The README gets at most 60% of the space when the code has descriptions. The AI may
  sum up what the developer says the app does, in sentences tagged "AI inferred".
  Barkley shows a sentence only if the lines it cites were sent and hold its words, and
  it gives no verdict. That request isn't sent when a threat was found.
- Settings → AI answers: how much of the developer's text one request may carry: 6,000,
  12,000 (default) or 18,000 characters, with one code description per 1,000 characters.
  The AI may write up to 4 sentences at 6,000 and up to 6 above that. Picking a size
  fills in its time limit (3, 6 or 9 minutes), which you can change.
- Settings → AI time limit: Barkley stops waiting after that many minutes, or, switched
  off, waits as long as your model takes. While it waits, the page has a Stop waiting
  button. A time-out says how long it waited and what you can do; it never changes a
  reading. Home Assistant may still finish an answer Barkley stopped waiting for, but
  Barkley won't use it.
- Barkley now sends AI requests over Home Assistant's websocket. A request sent through
  the Supervisor's API ends after 5 minutes, and a slow model can take longer.
- While your AI answers, the app's card on the list gets a moving outline in the AI's
  colour, the box at the top of the list names the app and how long it has waited, and
  the app's page shows a box with the time so far.

**Update comparison**

- A summary of what the update changes beyond security, added and removed: actions you
  can use in automations, kinds of entity, pages and sidebar pages, commands and
  webhooks it accepts, other integrations' actions it calls, packages, sites it sends
  requests to, sites the login you gave it goes to, and environment variables it reads.
  For example: "Adds 3 actions you can use in automations, adds 1 kind of entity, adds 2
  packages it requires, no longer adds 1 sidebar page." A fold names them. Barkley
  counts kinds of entity (switches, sensors), not entities: how many an app creates
  depends on your devices. An update notification carries the same sentence, with
  counts only. Both versions must be sniffed by 0.15 or later.

- It now also says when an update changes how the release's commit is signed, sends a
  new kind of request to a site, puts new names into a request, reads or sets a new
  environment variable, or brings a new, changed or newly read published library.
  Signing that stops or changes kind is a change to check. The rest are listed under the
  smaller changes.

**Faster scans**

- Published libraries: an integration's large JavaScript file that is byte for byte a
  file of a well-known npm package (a month old, 10,000 downloads a week, no malware
  advisory) isn't read as code. It's listed on the app's page and checked for
  advisories like any dependency. Barkley asks jsDelivr by the file's SHA-256; no
  answer means the file is read. On by default; Settings → Published libraries.
- The check that a login token only goes to Home Assistant itself reuses its work
  within a scan. Same results, less time.
- An update of Barkley no longer sniffs every app again unless it changed what a scan
  finds (its rules, its checks or the scanner tools). Barkley works this out from its
  own files when it starts.
- A cache of code already read: a file Barkley has read before, byte for byte, isn't
  read again (an app's new release, Sniff again). 1 GB by default; Settings → Cache of
  code already read. An app's page says how many files came from it.

**Where Home Assistant runs decides how much a library's known bug counts**

- A home or work network: a known vulnerability in a dependency is at most medium, and
  the item says why. Reachable from the internet: its rating, and critical when CISA
  lists it as exploited in the wild, automatable and of total impact (read from the CVE
  record). Malware and data leaving are never lowered.
- A known vulnerability in a card's or panel's JavaScript is rated by GitHub's rating
  (at most high) instead of always medium; one that can only slow or stop the page
  stays at most medium.

**Fewer false alarms, from scanning the Marketplace**

Barkley scanned 6,753 of the 6,759 apps in the Marketplace's list (November 2026): three
repositories were gone, and three downloads were over Barkley's 256 MB limit. It flagged
92 as a possible or found threat, and when their code was read, none was malicious. Every
change below is a general check applied to every app, not an exception for one:

- A login token sent to Home Assistant itself: through a helper that takes the address
  in any place, a class method, or a script without modules; after a check that the
  address is one of Home Assistant's own paths or its own origin; over Home Assistant's
  websocket; or as a blob address that never leaves the browser.
- Data leaving: a site counts as a destination only when the code uses it like an
  address (not a link in a message, an XML namespace, an app package name or a dotted
  key). Login-token code that only counts, checks or removes tokens, another app's
  settings fields that aren't secrets, the Supervisor's key sent to the Supervisor, and
  one named entry of secrets.yaml are no longer paired with a site.
- Loading saved data with pickle is a habit (medium), not hidden code. Encoded pictures,
  fonts and keys aren't hidden code. Packed text is unpacked, as data, and read like the
  app's own files; the page says so, what kind of code it holds, and when it changes
  another app's files. Barkley has no checks for Lua code, so in packed Lua it only
  looks for web addresses.
- A build tool known to be malware is a possible threat, not a found one: it runs on
  the developer's machine, not in your home, but could change what ships. Settings →
  Build tool known to be malware sets how much it counts (2, 2.5 or 3).
- A library name one typo from a popular one is a note when PyPI's record shows the
  app's own owner published it; medium when only a link says so.
- npm's empty stand-in for a package it removed is a note, with when it was added.
- A library's plugin loader (code that runs what it's handed) is a note; script
  addresses in an app that has one count toward Exposure, like other code it loads.
- A card that sends its login token to the address in its own settings, where the
  card's default is one of Home Assistant's own paths (or there's no default), gets a
  note, not a Threat. A default that points elsewhere stays a Threat.
- A possible theft needs a site the code was read sending a request to (or a request
  whose address Barkley couldn't read), and a real credential: another app's saved
  field counts only when it's named like one (password, token, key, secret and so on).
- Test scripts Home Assistant never loads don't count toward the readings. The app's
  page lists them in "Ignored test scripts that aren't loaded". When the app imports
  code by a name Barkley can't follow, nothing is set aside.
- A card's build tools (file watching, unpacking, test helpers) that its lockfile lists
  as run-time packages aren't counted as code your browser runs. They're listed, not
  counted.

**New in the readings**

- Code a card loads from the internet while it runs counts toward Exposure: 5 when the
  version it gets is decided while it runs, 2 when it's one exact version.
- A card that runs code taken from the page address is Exposure 5, not a Threat: anyone
  who gets a logged-in user to open a link could run code in the dashboard.
- An integration that downloads Lua code while it runs and runs it through lupa is
  Exposure 5, like a card's code from another site. With lupa's out-of-the-box settings
  that code can use Python and run programs, so it can do anything the app can. A
  runner that keeps the code away from both is listed and not counted.

**The list and Settings**

- Filters "Signs of a threat" and "Exposure medium or high", and an Order menu: most
  concern first, Threat, Exposure, or name.
- Apps you sniffed but didn't install stay listed after Barkley's rules change, marked
  "Sniffed with earlier rules", with a button to sniff them again.
- When the Marketplace has removed an app, its page says so.
- An app's page shows the release day and the last push to the project. Settings →
  Quiet projects says when a project has gone quiet (12 months by default, or never).
  It changes no reading.
- An app with only some of its sites unencrypted says "Partly unencrypted", with how
  many.
- Settings → Low memory: scans don't start with less than 1 GB free. You can lower it
  to 0.5 GB or scan anyway, if you accept that Home Assistant may run short.
- Settings → Notify when: every result (default), Exposure medium or high, Exposure
  high, or only signs of malicious behavior. A sniff that didn't finish always notifies.
- On a pre-release track, only a newer version counts as an update.
- History shows each scan's Threat and Exposure.

**Scanner tools are more tightly confined**

- On Home Assistant OS, whose kernel has no Landlock, each scanner tool now runs in
  its own AppArmor profile. It can't read the app's options, the GitHub token file or
  the scan store, and it can write only to Barkley's caches and temporary space. Where
  Landlock is available, Barkley's Landlock sandbox confines the tools as before. With
  neither, Barkley won't start unless you set `BARKLEY_UNSANDBOXED=1`. Diagnostics has
  a Tool sandbox line.

**Removed**

- GuardDog: on a hand-checked sample of 600 Marketplace apps, 1 of its 23 findings was
  right, and none was malware. Barkley no longer downloads every library of an
  integration to run GuardDog on it, so a scan needs far less temporary space. (It
  still downloads the few libraries the app hands the login you gave it to; see above.)

**Fixes from the issue tracker**

- A login-token check is not a reach into the auth store: an app that only checks
  whether a token or signed link sent to it is valid (as Home Assistant's own check
  does) gets a low "Checks login tokens sent to it", and that is never paired with the
  app's outside addresses as possible data leaving.
- Several calls of the same kind in one Python function are one item; an admin-only
  websocket command says so.
- Security checks run through pre-commit (local hooks included), lefthook or husky, and
  Ruff's security rules selected in `pyproject.toml`, `ruff.toml` or `.ruff.toml`, count
  as the developer's security habits. Only checks a workflow runs count toward the A+
  star.
- A full temporary folder says "out of temporary space: N MB free".
- A CPU without the x86-64-v2 instructions (a VM's default CPU type) says so, with the
  fix, on the scan and in Diagnostics.
- Code inside a JavaScript class static block (`static { … }`) is now read. Semgrep
  couldn't parse it, so Barkley rewrites the block in its own copy, with the same
  meaning, before scanning.
- A card's item title read "It can it dashboard card uses …" in 0.14.0. Fixed.
- An app installed at an older version, with a newer one already offered, had only the
  installed version sniffed: the offered update never was. Both are sniffed now, and
  the update's notification no longer replaces the install's.
- Plainer words across the panel and the notifications.

## 0.14.0

**Reviews and a Settings page**

- Findings are grouped by kind: Threats, what the app can do, known bugs in its
  libraries, how it's made. "No signs of malicious behavior" when there's no Threat.
- Mark findings reviewed, or Accept all, with a note. The circle then shows your
  reviewed score; Barkley's own score stays unchanged beside it. Each Threat needs its
  own tick; known malware can never be accepted.
- An accepted finding reopens (and notifies you) when an update changes its code;
  "What changed?" shows the code then and now.
- Malware check only, per app: only Threats and known malware are shown and notified.
- A Settings page: Paranoid mode (minor findings hidden and not counted while off), the
  no-Threat floor at Very Sus, pages without a login, hidden usage reporting, reviews,
  auto-sniff, notifications, AI, parallel scans, Semgrep jobs, memory for scans and the
  GitHub token (with Create token on GitHub). Auto-sniff's box moved from the list to
  this page. The app's options are now the starting values.
- AI mode now starts on Explain and read code. Nothing is sent until you click, and
  a click sends only the app's own public code around a finding.
- Sniff again on every installed app, and Sniff all again for the list. New filters:
  needs a look, reviewed, Malware check only.
- Report a false positive under each finding, and Report an issue, as pre-filled public
  issues you finish and submit yourself (no token).
- Stars and release downloads on an app's page (never scored), an A+ security habits
  star, and plainer wording.

**Checks**

- Fewer false alarms, from the first public feedback: other apps' entries and options,
  `.storage` use, user listing, declared library installs, own sub-integrations, a test
  script's own files, build tools in cards, yarn and pnpm lockfiles, and more.
- New: names built from pieces in cards (`card-hidden-name`), downloaded code that runs
  (`card-eval-remote`; plain run-time code is now medium), and usage reporting
  (telemetry) findings.
- Every file of a card's release is scanned, as the Marketplace installs them all.
- `card-token-exfil` missed some forms in 0.13.0 and earlier; fixed.
- Downloads retry, and a scan that still can't fetch a file says which file and why.

**Running it**

- Standalone: run Barkley as its own container next to Home Assistant Container or Core
  (or on another machine), with "log in with Home Assistant". A short first-time
  setup creates Barkley's own Home Assistant token (or takes one you paste), which it
  rotates, and offers a GitHub token. Full guardrail support needs a Linux kernel with Landlock
  (5.13 or later). On a kernel without it, Barkley won't start unless you set
  `BARKLEY_UNSANDBOXED=1`, which runs the scanner tools without their sandbox. See the
  wiki's Standalone page, "The tool sandbox".
- Each scanner tool runs in a Landlock sandbox if the kernel supports it. Home Assistant
  OS doesn't ship with Landlock enabled in its kernel, so there the app relies on its
  custom AppArmor profile to confine the tools.
- Barkley itself runs on Python 3.14, as Home Assistant does.

**Known issues**

- Scans take longer than in 0.13.0. Barkley now reads every file of a card's release and
  checks JavaScript a second time for code built from pieces, to close a gap in the card
  checks. Scanning 61 real apps took about 50% longer than before, and a large card with
  many files can take several minutes on its own. A cache that skips work already
  done on identical files and packages is being worked on. On a machine with spare
  memory and CPU cores, you can speed things up on the Settings page: Parallel scans
  runs more apps at once, and Semgrep jobs uses more cores within one scan. Keep the
  two multiplied together at or below the number of CPU cores: past that, a big app's
  checks can run out of time and its scan comes out Incomplete.
