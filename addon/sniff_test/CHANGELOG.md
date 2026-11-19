# Changelog

Barkley is AI-assisted. The full release notes are on GitHub:
https://github.com/SeriesOfTubez/ha-barkley/releases

## 0.14.1

**Faster scans of big integrations**

- Published libraries: an integration's large JavaScript file that is byte for byte a
  file of a well-known npm package (a month old, 10,000 downloads a week, no malware
  advisory) isn't read as code. It's listed on the app's page and checked for
  advisories like any dependency. Barkley asks jsDelivr by the file's SHA-256; no
  answer means the file is read. On by default; Settings → Published libraries.
- The check that a login token only goes to Home Assistant itself reuses its work
  within a scan. Same findings, less time.
- A known vulnerability in a card's or panel's JavaScript is now rated by GitHub's
  rating (at most high) instead of always medium; one that can only slow or stop the
  page stays at most medium.

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
