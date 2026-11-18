# Changelog

Barkley is AI-assisted. The full release notes are on GitHub:
https://github.com/SeriesOfTubez/ha-barkley/releases

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
  auto-sniff, notifications, AI, parallel scans, Semgrep jobs and the GitHub token. The
  app's options are now the starting values.
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
  (or on another machine), with "log in with Home Assistant". It can create and rotate
  its own Home Assistant token. Needs Linux with Landlock (5.13 or later).
- Each scanner tool runs in a Landlock sandbox where the kernel has it (Home Assistant OS
  doesn't; there the app's AppArmor profile confines the tools, as before).
- Barkley itself runs on Python 3.14, as Home Assistant does.
